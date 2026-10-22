// A request's Merkle path without the operator's indexer (vault revision 4):
// the vault's state (nextNoteId() first, noteLeaves pages, currentRoot()) read
// at one pinned block hash and rebuilt in the shipped WebAssembly, with the
// vault's logs as the fallback, checked against currentRoot() at that block.
// Exits need no path at all: their statement binds the note's leaf.
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
const {
    NOTE_LEAVES_PAGE, fetchVaultTreeLogs, readTreeState, rebuildRequestPath, treeEventsFromLogs
} = await import('../services/zkapiTreeRebuild.mjs');
// The first operation initializes the shared WebAssembly instance.
await execute('identity', {});

const VAULT = `0x${'5a'.repeat(20)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const hex = value => `0x${BigInt(value).toString(16)}`;
const felt = value => `0x${word(value)}`;
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
const HEAD = { number: 10_000, hash: felt(0xb10c) };

/**
 * A scripted vault history: deposits of notes 0–4 across blocks 1,000–9,000
 * (NoteDeposited with 2 data words) and a retirement of note 1 (no data),
 * plus an escape, its defeat and an expiry claim, which change no leaf.
 * Returns the logs, the vault's leaves at the end, the reference tree's
 * paths and root, and each note's state.
 */
async function history() {
    const reference = new glue.BrowserNoteTree();
    const logs = [];
    const notes = [];
    const leaves = [];
    let logIndex = 0;
    const push = (blockNumber, topics, data) => logs.push({ address: VAULT, blockNumber: hex(blockNumber),
        logIndex: hex(logIndex++), topics, data: `0x${data.map(word).join('')}`, removed: false });
    for (let noteId = 0; noteId < 5; noteId += 1) {
        const deposit = await execute('generateDeposit', {});
        const amount = 1_000_000 + noteId;
        const expiry = 4_000_000_000;
        reference.apply(JSON.stringify({ event: 'note_deposited', note_id: noteId,
            commitment: deposit.registration_commitment, amount: String(amount), expiry_ts: expiry }));
        push(1_000 + noteId * 2_000, [ABI.noteDeposited, `0x${word(noteId)}`, `0x${word(deposit.registration_commitment)}`],
            [amount, expiry]);
        const state = await execute('confirmDeposit', { config, args: { secret: deposit.secret, note_id: noteId, amount, expiry_ts: expiry } });
        leaves.push(await execute('noteLeafFromFields', { noteId, commitment: deposit.registration_commitment, amount, expiryTs: expiry }));
        notes.push({ state, commitment: deposit.registration_commitment, amount, expiry });
        if (noteId === 2) {
            push(5_100, [ABI.escapeInitiatedEvent, `0x${word(1)}`], [0x11, 900, 0x22, 6_000]);
            push(5_200, [ABI.escapeChallengedEvent, `0x${word(1)}`], [0x11]);
            reference.apply(JSON.stringify({ event: 'closed_leaf_retired', note_id: 1 }));
            push(5_300, [ABI.closedLeafRetiredEvent, `0x${word(1)}`], []);
            leaves[1] = felt(0);
        }
    }
    push(9_500, [ABI.expiredClaimedEvent, `0x${word(3)}`], [1_000_003]);
    const root = JSON.parse(reference.root());
    const paths = Object.fromEntries([0, 2, 3, 4].map(noteId => [noteId, JSON.parse(reference.path(noteId))]));
    reference.free();
    return { logs, leaves, root, paths, notes };
}

/**
 * The vault through an RPC at the pinned block HEAD: eth_call answers only
 * for HEAD's hash with requireCanonical (EIP-1898); noteLeaves reverts past
 * nextNoteId; eth_getLogs serves `logs` and refuses ranges wider than
 * `maxRange`. `failState` makes every state call fail; `pageFrom` answers a
 * page with another block's leaves.
 */
function vaultRpc({ logs, leaves, root }, { maxRange = 20_000, chainId = 31337, failState = false, pageFrom = null,
    reportedRoot = root, latest = HEAD } = {}) {
    const calls = [];
    const request = async ({ method, params }) => {
        calls.push({ method, params });
        if (method === 'eth_chainId') return hex(chainId);
        if (method === 'eth_getBlockByNumber') {
            assert.deepEqual(params, ['latest', false]);
            return { number: hex(latest.number), hash: latest.hash };
        }
        if (method === 'eth_call') {
            const [{ to, data }, block] = params;
            assert.equal(to, VAULT);
            assert.deepEqual(block, { blockHash: HEAD.hash, requireCanonical: true }, 'pinned to one block hash');
            if (failState) throw new Error('execution reverted: out of gas (eth_call gas cap)');
            const selector = data.slice(2, 10);
            if (selector === ABI.nextNoteId) return felt(leaves.length);
            if (selector === ABI.currentRoot) return felt(reportedRoot);
            if (selector === ABI.noteLeaves) {
                const start = Number(BigInt(`0x${data.slice(10, 74)}`));
                const count = Number(BigInt(`0x${data.slice(74, 138)}`));
                if (start + count > leaves.length) throw new Error('execution reverted: InvalidNoteRange()');
                const source = pageFrom?.start === start ? pageFrom.leaves : leaves;
                return `0x${word(32)}${word(count)}${source.slice(start, start + count).map(word).join('')}`;
            }
            throw new Error(`unexpected vault call ${selector}`);
        }
        if (method === 'eth_getLogs') {
            const [{ address, topics, fromBlock, toBlock }] = params;
            assert.equal(address, VAULT);
            assert.deepEqual(topics, [[ABI.noteDeposited, ABI.closedLeafRetiredEvent]], 'only leaf-changing events');
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

const rebuild = (rpc, noteId, options = {}) => rebuildRequestPath({ request: rpc.request, vault: VAULT, deployBlock: 900, noteId,
    chainId: 31337, worker, ...options });

test('the state rebuild equals the vault tree: nextNoteId first, noteLeaves pages, then currentRoot, all at one block hash', async () => {
    const vault = await history();
    assert.equal(NOTE_LEAVES_PAGE, 2_048);
    for (const pageSize of [NOTE_LEAVES_PAGE, 2]) {
        const rpc = vaultRpc(vault);
        for (const noteId of [0, 2, 4]) {
            const path = await rebuild(rpc, noteId, { pageSize });
            assert.equal(path.source, 'state');
            assert.deepEqual(path.block, HEAD);
            assert.deepEqual({ active_root: path.active_root, note_id: path.note_id, siblings: path.siblings }, vault.paths[noteId]);
        }
        const calls = rpc.calls.filter(call => call.method === 'eth_call').map(call => call.params[0].data.slice(2, 10));
        const perRebuild = calls.length / 3;
        assert.deepEqual(calls.slice(0, perRebuild), [ABI.nextNoteId, ...Array(Math.ceil(5 / pageSize)).fill(ABI.noteLeaves),
            ABI.currentRoot], `pages of ${pageSize}`);
        assert.ok(!rpc.calls.some(call => call.method === 'eth_getLogs'), 'no log scan when the state reads answer');
    }
    // The snapshot itself: a retired note is a zero leaf.
    const snapshot = await readTreeState({ request: vaultRpc(vault).request, vault: VAULT, block: HEAD, pageSize: 2 });
    assert.deepEqual({ root: BigInt(snapshot.root), next_note_id: snapshot.next_note_id, leaves: snapshot.leaves.map(BigInt) },
        { root: BigInt(vault.root), next_note_id: 5, leaves: vault.leaves.map(BigInt) });
    // A retired note and a note past nextNoteId have no request path.
    await assert.rejects(rebuild(vaultRpc(vault), 1), /tree_event_invalid/);
    await assert.rejects(rebuild(vaultRpc(vault), 9), /tree_event_invalid/);
    // An RPC on another chain is refused before any vault read.
    const other = vaultRpc(vault, { chainId: 1 });
    await assert.rejects(rebuild(other, 0), { code: 'wrong_network' });
    assert.deepEqual(other.calls.map(call => call.method), ['eth_chainId']);
});

test('a page from another block, or leaves that do not reproduce currentRoot, is refused and not retried from logs', async () => {
    const vault = await history();
    const moved = [...vault.leaves];
    moved[3] = felt(0);
    for (const [label, rpc] of [
        ['a page of another block', vaultRpc(vault, { pageFrom: { start: 2, leaves: moved } })],
        ['another root', vaultRpc(vault, { reportedRoot: felt(0x5) })]
    ]) {
        await assert.rejects(rebuild(rpc, 4, { pageSize: 2 }), /tree_root_mismatch/, label);
        assert.ok(!rpc.calls.some(call => call.method === 'eth_getLogs'), `${label}: an inconsistent RPC is not asked again`);
    }
    // The leaf count must be nextNoteId's.
    const short = vaultRpc({ ...vault, leaves: vault.leaves });
    const original = short.request;
    short.request = async payload => payload.method === 'eth_call' && payload.params[0].data.slice(2, 10) === ABI.nextNoteId
        ? felt(4) : original(payload);
    await assert.rejects(rebuild(short, 0), /tree_root_mismatch/);
});

test('when the state reads fail the logs up to the pinned block are the fallback, checked against currentRoot() there', async () => {
    const vault = await history();
    const rpc = vaultRpc(vault, { failState: true, maxRange: 500 });
    // The state calls fail (an eth_call gas cap): the fallback's own root
    // check also needs currentRoot(), so this RPC answers it.
    const original = rpc.request;
    rpc.request = async payload => payload.method === 'eth_call' && payload.params[0].data === `0x${ABI.currentRoot}`
        && rpc.calls.some(call => call.method === 'eth_getLogs') ? felt(vault.root) : original(payload);
    const path = await rebuild(rpc, 2);
    assert.equal(path.source, 'logs');
    assert.deepEqual({ active_root: path.active_root, note_id: path.note_id, siblings: path.siblings }, vault.paths[2]);
    const logReads = rpc.calls.filter(call => call.method === 'eth_getLogs');
    assert.equal(Number(BigInt(logReads.at(-1).params[0].toBlock)), HEAD.number, 'up to the pinned block, not beyond');
    // Logs that do not reproduce the vault's root at that block are refused.
    const tampered = vault.logs.map(log => log.topics[0] === ABI.closedLeafRetiredEvent ? { ...log, removed: true } : log);
    const lying = vaultRpc({ ...vault, logs: tampered }, { failState: true });
    const inner = lying.request;
    lying.request = async payload => payload.method === 'eth_call' && payload.params[0].data === `0x${ABI.currentRoot}`
        && lying.calls.some(call => call.method === 'eth_getLogs') ? felt(vault.root) : inner(payload);
    await assert.rejects(rebuild(lying, 2), { code: 'tree_root_mismatch' });
    // Neither the state nor the logs: the failure names both.
    const down = vaultRpc(vault, { failState: true, maxRange: 50 });
    await assert.rejects(rebuild(down, 2), error => error.code === 'tree_logs_unavailable' && /vault state could not be read/.test(error.message));
    // The events carry no roots any more.
    const events = treeEventsFromLogs(vault.logs, VAULT);
    assert.deepEqual(events.map(event => event.event), ['note_deposited', 'note_deposited', 'note_deposited', 'closed_leaf_retired',
        'note_deposited', 'note_deposited']);
    assert.ok(events.every(event => !('root' in event)));
    // A revision-3 NoteDeposited (a third root word) is another ABI.
    const legacy = { ...vault.logs[0], data: `${vault.logs[0].data}${word(0x77)}` };
    assert.throws(() => treeEventsFromLogs([legacy], VAULT), /exactly 2/);
});

test('log ranges start at 2,000 blocks, halve on a range error down to 100, and grow back after accepted ranges', async () => {
    const vault = await history();
    const rpc = vaultRpc(vault, { maxRange: 500 });
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
    assert.equal(fetched.ranges.at(-1)[1], 10_000);
    const treeLogs = vault.logs.filter(log => [ABI.noteDeposited, ABI.closedLeafRetiredEvent].includes(log.topics[0]));
    assert.equal(fetched.logs.length, treeLogs.length);
    assert.deepEqual(fetched.logs.map(log => log.logIndex), treeLogs.map(log => log.logIndex), 'sorted by block and log index');
    assert.ok(progress.length > 0);
    // An RPC that refuses even 100 blocks fails the log scan.
    await assert.rejects(fetchVaultTreeLogs({ request: vaultRpc(vault, { maxRange: 50 }).request, vault: VAULT,
        fromBlock: 900, toBlock: 10_000 }), { code: 'tree_logs_unavailable' });
});

test('a dense stretch narrows the ranges only while it lasts, and a rebuild ends by its deadline', async () => {
    const vault = await history();
    // The RPC limits ranges to 200 blocks only up to block 2,000.
    const calls = [];
    const dense = async ({ params }) => {
        const from = Number(BigInt(params[0].fromBlock));
        const to = Number(BigInt(params[0].toBlock));
        calls.push(to - from + 1);
        if (from < 2_000 && to - from + 1 > 200) throw new Error('query returned more than 10000 results');
        return vault.logs.filter(log => {
            const block = Number(BigInt(log.blockNumber));
            return block >= from && block <= to;
        });
    };
    const fetched = await fetchVaultTreeLogs({ request: dense, vault: VAULT, fromBlock: 900, toBlock: 40_000 });
    assert.equal(fetched.logs.length, vault.logs.length);
    assert.equal(Math.max(...fetched.ranges.map(([from, to]) => to - from + 1)), 2_000, 'back to full ranges');
    assert.ok(calls.length < 60, `${calls.length} calls; without regrowth about 200`);

    // An RPC that answers each call slowly, or never, ends at the deadline.
    for (const [label, delay] of [['slow', 25], ['silent', null]]) {
        let reads = 0;
        const stalling = async ({ method }) => {
            if (method === 'eth_chainId') return hex(31337);
            if (method === 'eth_getBlockByNumber') return { number: hex(10_000_000), hash: HEAD.hash };
            if (method === 'eth_call') throw new Error('eth_call is capped');
            reads += 1;
            if (delay == null) return new Promise(() => {});
            await new Promise(resolve => setTimeout(resolve, delay));
            return [];
        };
        const started = Date.now();
        await assert.rejects(rebuildRequestPath({ request: stalling, vault: VAULT, deployBlock: 0, noteId: 0, chainId: 31337, worker,
            deadline: Date.now() + 120 }), { code: 'tree_rebuild_timeout' }, label);
        assert.ok(Date.now() - started < 3_000, label);
        assert.ok(reads >= 1 && reads <= 8, `${label}: ${reads} reads`);
    }
    // A deadline already past fails before any read.
    await assert.rejects(fetchVaultTreeLogs({ request: () => assert.fail('no read'), vault: VAULT, fromBlock: 0, toBlock: 10,
        deadline: Date.now() - 1 }), { code: 'tree_rebuild_timeout' });
});

test('a state\'s note leaf is the leaf of its public fields, which recovery matches against noteRecord', async () => {
    const vault = await history();
    for (const [noteId, note] of vault.notes.entries()) {
        const fromState = await execute('noteLeaf', { state: note.state });
        const fromFields = await execute('noteLeafFromFields', { noteId, commitment: note.commitment,
            amount: BigInt(note.amount), expiryTs: `0x${note.expiry.toString(16)}` });
        assert.equal(BigInt(fromState), BigInt(fromFields), `note ${noteId}`);
        if (noteId !== 1) assert.equal(BigInt(fromState), BigInt(vault.leaves[noteId]));
        // Another expiry, amount, note id or commitment is another leaf.
        for (const changed of [{ expiryTs: note.expiry + 86_400 }, { amount: note.amount + 1 }, { noteId: noteId + 1 },
            { commitment: vault.notes[(noteId + 1) % 5].commitment }]) {
            const other = await execute('noteLeafFromFields', { noteId, commitment: note.commitment, amount: note.amount,
                expiryTs: note.expiry, ...changed });
            assert.notEqual(BigInt(other), BigInt(fromState), JSON.stringify(changed));
        }
    }
    await assert.rejects(execute('noteLeafFromFields', { noteId: 0, commitment: vault.notes[0].commitment, amount: 1.5, expiryTs: 1 }),
        /note_fields_invalid/);
    await assert.rejects(execute('noteLeafFromFields', { noteId: 0, commitment: '0x', amount: 1, expiryTs: 1 }),
        /note_fields_invalid/);
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
