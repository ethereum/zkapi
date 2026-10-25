// Deposits and request paths of vault revision 4 (design C), over the real
// runtime, client and store: the minimum deposit, the deposit's leaf checked
// against noteRecord after its receipt (also when it landed at a later note
// id), recovery of a deposit without its receipt by the day-bucket expiry
// search (and a slot conflict when no candidate reproduces the stored leaf),
// and a request's path from the indexer only at the vault's root, otherwise
// rebuilt from the vault's state. The pinned RPC, the wallet provider and the
// proof worker are observed fakes (helpers/request-archive-harness.mjs).
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, VAULT, createHarness, fakeNoteLeaf, memoryIndexedDb, noteState
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
const storage = new Map();
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: shared } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { ABI } = globalThis.zkapiWallet;

const DAY = 86_400;
const NOTE_TTL = 2_592_000;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const bucket = seconds => Math.ceil((seconds + NOTE_TTL) / DAY) * DAY;
const HASH = `0x${'ab'.repeat(32)}`;

/** The shared runtime under the harness, with a pending deposit and the worker's confirmation. */
async function harness(pendingDeposit = null) {
    indexedDB.clear();
    const h = createHarness(function SharedRuntime() { return shared; });
    const call = shared.worker.call;
    shared.worker.call = async (operation, payload) => operation === 'confirmDeposit'
        ? noteState({ note_id: payload.args.note_id, secret_s: payload.args.secret, deposit_amount: payload.args.amount,
            current_balance: payload.args.amount, expiry_ts: payload.args.expiry_ts })
        : call(operation, payload);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null,
        ...(pendingDeposit ? { pendingDeposit } : {}) });
    await shared.reload();
    return h;
}

/** A wallet provider over a scripted vault: noteRecord per note id, receipts, finality. */
function vaultProvider(h, { records = {}, receipts = {}, finalized = '0x64', head = '0x80' } = {}) {
    const calls = [];
    globalThis.ethereum = {
        async request({ method, params = [] }) {
            calls.push({ method, params });
            if (method === 'eth_chainId') return `0x${Number(h.funding.chain_id).toString(16)}`;
            if (method === 'eth_getTransactionReceipt') return structuredClone(receipts[params[0]] ?? null);
            if (method === 'eth_getBlockByNumber') return { number: params[0] === 'finalized' ? finalized : params[0], hash: `0x${'cc'.repeat(32)}` };
            if (method === 'eth_blockNumber') return head;
            if (method === 'eth_getTransactionByHash') return null;
            if (method === 'eth_call') {
                assert.equal(params[0].to, VAULT);
                assert.ok(params[0].data.startsWith(`0x${ABI.noteRecord}`), 'only noteRecord is read');
                const noteId = Number(BigInt(`0x${params[0].data.slice(10)}`));
                const record = records[noteId] ?? { leaf: 0n, status: 0 };
                return `0x${word(record.leaf)}${word(record.status)}`;
            }
            throw new Error(`unexpected wallet RPC ${method}`);
        }
    };
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = shared.config;
    client.refresh = async () => {};
    client.refreshConfirmedBrowserDeposit = async () => false;
    shared.refreshExitCost = async () => null;
    return { client, calls };
}

const plan = (changes = {}) => ({ operationId: 'deposit', phase: 'submitted', amount: 5_000_000, secret: '0x51',
    commitment: '0x52', next_note_id: 7, createdAt: Date.now(), ...changes });

test('a deposit below the pinned minimum, or a vault whose minDeposit differs, is refused before a secret exists', async () => {
    const h = await harness();
    h.chain.minDeposit = 1_000_000n;
    shared.browserConfig.trusted_deployment.min_deposit_units = 1_000_000;
    let generated = 0;
    const call = shared.worker.call;
    shared.worker.call = async (operation, payload) => {
        if (operation === 'generateDeposit') {
            generated += 1;
            return { secret: '0x51', registration_commitment: '0x52' };
        }
        return call(operation, payload);
    };
    await assert.rejects(shared.prepareDeposit(999_999), error => error.code === 'deposit_too_small'
        && error.data.min_deposit_units === 1_000_000 && error.status === 400);
    await assert.rejects(shared.prepareDepositQuote(999_999), { code: 'deposit_too_small' });
    assert.equal(generated, 0, 'no note secret for a refused amount');
    // The vault's minDeposit() must be the pinned one.
    h.chain.minDeposit = 2_000_000n;
    await assert.rejects(shared.prepareDeposit(1_500_000), error => error.code === 'deployment_mismatch'
        && error.data.mismatches[0].field === 'minDeposit');
    // A profile without the pin takes no deposit.
    delete shared.browserConfig.trusted_deployment.min_deposit_units;
    await assert.rejects(shared.prepareDeposit(1_500_000), { code: 'min_deposit_unpinned' });
    shared.browserConfig.trusted_deployment.min_deposit_units = 1_000_000;
    h.chain.minDeposit = 1_000_000n;
    h.chain.nextNoteId = 41n;
    const prepared = await shared.prepareDeposit(1_000_000);
    assert.equal(generated, 1);
    assert.equal(prepared.next_note_id, 41, 'the expected id is the vault\'s nextNoteId()');
    assert.equal(prepared.active_root, undefined);
    assert.equal(prepared.zero_path, undefined);
});

test('after the receipt the vault\'s stored leaf must be the leaf of the NoteDeposited fields; a later note id confirms', async () => {
    for (const [label, noteId, stored, accepted] of [
        ['the expected id', 7, 'match', true],
        ['a later id, behind a front-running deposit', 9, 'match', true],
        ['another leaf', 7, 'other', false]
    ]) {
        const h = await harness(plan());
        const expiry = 2_000_086_400;
        const leaf = BigInt(fakeNoteLeaf(noteId, '0x52', 5_000_000, expiry));
        const { client, calls } = vaultProvider(h, { records: { [noteId]: { leaf: stored === 'match' ? leaf : leaf + 1n, status: 1 } } });
        const receipt = { status: '0x1', transactionHash: HASH, blockNumber: '0x70', logs: [{ address: VAULT,
            topics: [ABI.noteDeposited, `0x${word(noteId)}`, `0x${word(0x52)}`], data: `0x${word(5_000_000)}${word(expiry)}` }] };
        const confirm = client.confirmBrowserDepositReceipt(await shared.pendingDeposit(), receipt, VAULT, () => {});
        if (!accepted) {
            await assert.rejects(confirm, { code: 'deposit_leaf_mismatch' }, label);
            assert.equal((await store.readBrowserWallet()).pendingDeposit.operationId, 'deposit', `${label}: kept for recovery`);
            continue;
        }
        const result = await confirm;
        assert.equal(result.noteId, noteId, label);
        const record = calls.find(call => call.method === 'eth_call');
        assert.equal(record.params[1], '0x70', `${label}: read at the receipt's block`);
        const saved = (await store.readBrowserWallet()).state;
        assert.equal(saved.note_id, noteId, label);
        assert.equal(saved.expiry_ts, expiry, `${label}: e from the event`);
        assert.equal(saved.registration_commitment, '0x52');
    }
    // A NoteDeposited of another commitment, an earlier id or a revision-3
    // shape (a third root word) is not this deposit.
    for (const log of [
        { topics: [ABI.noteDeposited, `0x${word(7)}`, `0x${word(0x53)}`], data: `0x${word(5_000_000)}${word(1)}` },
        { topics: [ABI.noteDeposited, `0x${word(6)}`, `0x${word(0x52)}`], data: `0x${word(5_000_000)}${word(1)}` },
        { topics: [ABI.noteDeposited, `0x${word(7)}`, `0x${word(0x52)}`], data: `0x${word(5_000_000)}${word(1)}${word(0x77)}` }
    ]) {
        const h = await harness(plan());
        const { client } = vaultProvider(h);
        await assert.rejects(client.confirmBrowserDepositReceipt(await shared.pendingDeposit(),
            { status: '0x1', transactionHash: HASH, logs: [{ address: VAULT, ...log }] }, VAULT, () => {}),
        /did not match|was not found/);
    }
});

test('the expiry candidates are the day buckets from the plan\'s creation (less 5 minutes) to now', async () => {
    await harness();
    // Created just after a bucket boundary: the 5-minute margin reaches the previous bucket.
    const created = 1_900_000_000 - (1_900_000_000 % DAY) + 60;
    const at = (deltaSeconds, createdAt = created) => shared.depositExpiryCandidates({ createdAt: createdAt * 1_000 },
        createdAt + deltaSeconds);
    assert.deepEqual(at(0), [bucket(created - 300), bucket(created)]);
    assert.equal(bucket(created - 300) + DAY, bucket(created));
    // Mid-bucket and recovered within the day: one candidate.
    const mid = created + DAY / 2;
    assert.deepEqual(at(3_600, mid), [bucket(mid)]);
    // Recovered two and a half days later: one more per day boundary crossed (three).
    const late = at(2.5 * DAY, mid);
    assert.deepEqual(late, [bucket(mid), bucket(mid) + DAY, bucket(mid) + 2 * DAY, bucket(mid) + 3 * DAY]);
    // Never more than ⌈Δt / day⌉ + 2.
    for (const delta of [0, 1, DAY - 1, DAY, 7 * DAY + 5]) {
        assert.ok(at(delta).length <= Math.ceil(delta / DAY) + 2, `Δt ${delta}`);
    }
    // No creation time or no note_ttl: no candidate (recovery then reports a conflict, never guesses).
    assert.deepEqual(shared.depositExpiryCandidates({}, created), []);
});

test('a deposit without its receipt is recovered across a day boundary by the leaf of its expiry', async () => {
    const created = Math.floor(Date.now() / 1_000) - 2 * DAY;
    // The deposit mined a day after the plan was made, into the next bucket.
    const expiry = bucket(created + DAY);
    const h = await harness(plan({ createdAt: created * 1_000, transactionHash: undefined }));
    const leaf = BigInt(fakeNoteLeaf(7, '0x52', 5_000_000, expiry));
    const { client } = vaultProvider(h, { records: { 7: { leaf, status: 1 } } });
    const result = await client.recoverBrowserDeposit(() => {});
    assert.equal(result.status, 'confirmed');
    assert.equal(result.noteId, 7);
    const saved = (await store.readBrowserWallet()).state;
    assert.equal(saved.expiry_ts, expiry, 'the matching candidate is the expiry');
    assert.equal(saved.registration_commitment, '0x52');
    const tried = h.workerOperations('noteLeafFromFields').map(call => Number(call.payload.expiryTs));
    assert.ok(tried.length >= 2 && tried.includes(expiry), `candidates ${tried}`);
    assert.ok(tried.every(candidate => candidate % DAY === 0));
});

test('a slot holding a leaf no candidate reproduces is a slot conflict, settled at finality', async () => {
    const created = Math.floor(Date.now() / 1_000) - 3_600;
    for (const [label, status] of [['another deposit', 1], ['another, already closed', 3]]) {
        const h = await harness(plan({ createdAt: created * 1_000, transactionHash: undefined, phase: 'ambiguous' }));
        const other = BigInt(fakeNoteLeaf(7, '0x99', 5_000_000, bucket(created)));
        const { client } = vaultProvider(h, { records: { 7: { leaf: other, status } } });
        const result = await client.recoverBrowserDeposit(() => {});
        assert.equal(result.status, 'slot_consumed', label);
        const pending = (await store.readBrowserWallet()).pendingDeposit;
        assert.equal(pending.phase, 'prepared', `${label}: ready to retry`);
        assert.equal(pending.previousSlot, 7);
        assert.equal(pending.secret, '0x51', `${label}: the same note secret`);
    }
    // A slot that is still empty is not a conflict.
    const empty = await harness(plan({ createdAt: created * 1_000, transactionHash: undefined, phase: 'prepared' }));
    const { client } = vaultProvider(empty);
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'prepared');
});

test('a request takes the indexer\'s path only at the vault\'s current root; else the path is rebuilt from the vault', async () => {
    const h = createHarness(BrowserWalletRuntime);
    // The real path selection over the harness's indexer and rebuild fakes.
    h.runtime.config.funding.indexer_url = 'https://indexer.example';
    const at = await h.runtime.requestPath(7);
    assert.equal(at.source, 'indexer');
    assert.equal(h.runtime.lastRequestPathSource, 'indexer');
    assert.equal(h.chain.rebuilds ?? 0, 0);
    // An indexer behind the vault is asked again, then the vault's state decides.
    h.chain.indexerRoot = '0x76';
    const started = Date.now();
    const lagging = await h.runtime.requestPath(7);
    assert.equal(lagging.source, 'state');
    assert.equal(lagging.active_root, h.chain.root);
    assert.equal(h.chain.rebuilds, 1);
    assert.ok(Date.now() - started >= 900, 'it waited for the indexer twice');
    assert.equal(h.chain.reads.filter(read => read === `0x${ABI.currentRoot}`).length, 1 + 3, 'the vault root read per attempt');
    // An indexer that catches up within the attempts is used.
    let answers = 0;
    h.chain.indexerRoot = null;
    const indexerPath = h.runtime.indexerPath;
    h.runtime.indexerPath = async noteId => {
        answers += 1;
        const path = await indexerPath(noteId);
        return answers === 1 ? { ...path, active_root: '0x76' } : path;
    };
    assert.equal((await h.runtime.requestPath(7)).source, 'indexer');
    // An indexer that is down: no wait, the state rebuild.
    h.runtime.indexerPath = indexerPath;
    h.chain.indexerDown = true;
    const down = Date.now();
    assert.equal((await h.runtime.requestPath(7)).source, 'state');
    assert.ok(Date.now() - down < 400);
    assert.equal(h.chain.rebuilds, 2);
    // The request proof takes the rebuilt path's root.
    h.chain.indexerDown = false;
    h.chain.indexerRoot = '0x76';
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: noteState() });
    await h.runtime.reload();
    h.server.leasePost = body => h.activeLease(body);
    await h.runtime.issueLease('chat');
    const proof = h.workerOperations('prepareRequest').at(-1);
    assert.equal(proof.payload.args.active_root, h.chain.root);
    assert.equal(proof.payload.args.merkle_siblings.length, 32);
});
