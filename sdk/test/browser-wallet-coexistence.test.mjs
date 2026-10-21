// Two builds share one origin's IndexedDB (design §10.5): the legacy
// zkapi-v2-note-bound-v1 build (release/v2-note-bound, cut at ac9be63) at its
// publicPath and this build at /zkapi/v2c/, both opening
// `zkapi-browser-wallet-v1` version 3 under the same lock. Each must read a
// store the other wrote without throwing, and never rewrite the other
// deployment's records.
//
// The legacy store, request archive and recovery modules are vendored
// byte for byte (fixtures/legacy-store-ac9be63) so the check needs no git
// history. The store this build writes is also committed as
// fixtures/v2c-store-snapshot.json, so the release branch can run its own
// build over it (ZKAPI_UPDATE_FIXTURES=1 rewrites it).
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { memoryIndexedDb } from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const LEGACY_FIXTURE = new URL('./fixtures/legacy-store-ac9be63/', import.meta.url);
const LEGACY_SHA256 = Object.freeze({
    'browserWalletStore.js': '5cf4d8bc764b012d62cc79df6ef7506b4333406e7c385c14303dc90452559887',
    'zkapiRequestArchive.mjs': 'f60eb94346aca071d2d3bbe9a2ca841f27908eaf2cceb99790881d797f7620f1',
    'zkapiWithdrawalRecovery.mjs': '4d54c9f44d9674631edf8e84a7db7e266d23492f6302820322ef8fbd21151d05'
});
const SNAPSHOT = new URL('./fixtures/v2c-store-snapshot.json', import.meta.url);

const current = await import('../services/browserWalletStore.js');
const archive = await import('../services/zkapiRequestArchive.mjs');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const legacy = await import(new URL('browserWalletStore.js', LEGACY_FIXTURE).href);
const legacyArchive = await import(new URL('zkapiRequestArchive.mjs', LEGACY_FIXTURE).href);

const V2C = 'zkapi-native-eth-sepolia-concession-v1';
const LEGACY = 'zkapi-native-eth-sepolia-note-bound-v1';
const V2C_VAULT = `0x${'c2'.repeat(20)}`;
const LEGACY_VAULT = `0x${'1e'.repeat(20)}`;
const DESTINATION = `0x${'34'.repeat(20)}`;
const FIXED_NOW = 1_800_000_000_000;

const v2cState = (changes = {}) => ({
    protocol_version: 2, chain_id: 11155111, contract_address: V2C_VAULT, note_id: 4, secret_s: '0x5ec',
    deposit_amount: 5_000_000, expiry_ts: 2_000_000_000, current_balance: 4_975_000, balance_blinding: '0xb1',
    current_commitment_x: '0xc1', current_commitment_y: '0xc2', current_anchor: '0xa2', is_genesis: false,
    state_signature: { r_x: '0x1', r_y: '0x2', s: '0x3' }, prev_anchor: '0x1', bound_at_state: 1_000_000,
    deposit_path: { active_root: '0x51', siblings: Array.from({ length: 32 }, (_, index) => `0x${index}`) },
    ...changes
});
const legacyState = (changes = {}) => ({
    protocol_version: 2, chain_id: 11155111, contract_address: LEGACY_VAULT, note_id: 9, secret_s: '0x1e5',
    deposit_amount: 3_000_000, expiry_ts: 1_990_000_000, current_balance: 3_000_000, balance_blinding: '0xb2',
    current_commitment_x: '0xd1', current_commitment_y: '0xd2', current_anchor: '0x1', is_genesis: true,
    state_signature: null, ...changes
});
const journalAt = (state, id, builder = archive) => ({
    exists: true, client_request_id: id, nullifier: `0x${(BigInt(state.current_anchor) + 0x5000n).toString(16)}`,
    payload_hash: '0xabc', user_rerandomization: '0xfeed', created_at_ms: FIXED_NOW - 60_000,
    prepared_request: { client_request_id: id, payload: '{}', payload_hash: '0xabc',
        public_inputs: { request_time: (FIXED_NOW - 60_000) / 1_000, solvency_bound: 1_000_000 },
        proof: { backend: 'groth16_bn254', proof: `proof-${id}` } }
});

/** Every stored value, keyed by store and key, as one comparable object. */
function dump() {
    const out = {};
    for (const [name, values] of indexedDB.stores) {
        out[name] = Object.fromEntries([...values.entries()].map(([key, value]) => [String(key), structuredClone(value)]));
    }
    return out;
}

/** The entries of `deploymentId` (and, for the runtime slot, when it is that deployment's). */
function entriesOf(snapshot, deploymentId) {
    const out = {};
    for (const [name, values] of Object.entries(snapshot)) {
        out[name] = Object.fromEntries(Object.entries(values).filter(([, value]) => value?.deploymentId === deploymentId));
    }
    return out;
}

async function withFixedClock(operation) {
    const realNow = Date.now;
    Date.now = () => FIXED_NOW;
    try {
        return await operation();
    } finally {
        Date.now = realNow;
    }
}

/** The store as this build leaves it mid-exit, beside a set-aside legacy close. */
async function writeV2cStore() {
    const state = v2cState();
    const late = archive.buildRequestJournalRecord({ deploymentId: V2C, state, journal: journalAt(state, 'late'),
        disposition: 'late_successor', now: FIXED_NOW });
    const invalid = archive.buildRequestJournalRecord({ deploymentId: V2C, state, journal: journalAt(state, 'invalid'),
        disposition: 'invalid_successor', now: FIXED_NOW });
    const deferred = archive.buildRequestJournalRecord({ deploymentId: V2C, state, journal: journalAt(state, 'deferred'),
        observations: [archive.requestObservation('exit_deferred', 'exit', FIXED_NOW - 1_000),
            archive.requestObservation('exited_unsigned', 'exit', FIXED_NOW - 500)], now: FIXED_NOW });
    await current.writeBrowserWallet({
        deploymentId: V2C, billingAsset: 'native_eth', state, stateSeq: 3, exitKitExportedSeq: 2,
        exitLock: { noteId: 4, anchor: '0xa2', mode: 'escape', since: 1_799_999_000,
            released: [{ kind: 2, valid_until: 1_800_003_000, conceded: '0', at: 1_799_999_000 },
                { kind: 0, valid_until: 1_800_010_000, conceded: '1000000', at: 1_799_999_100 }] },
        preparedWithdrawal: { mode: 'escape', phase: 'prepared', noteId: 4, destination: DESTINATION, operationId: 'exit',
            withdrawalNullifier: '0x50a2', decision: { rule: 'E3.T', conceded: '1000000' }, stateBalance: '4975000',
            concededAtInit: '1000000', boundAtState: '1000000', validUntil: 1_800_010_000, pathSource: 'deposit',
            public_inputs: { kind: 0, note_id: 4, conceded: 1_000_000, final_balance: 3_975_000, valid_until: 1_800_010_000 },
            proof: { backend: 'groth16_bn254', proof: 'escape' } }
    });
    await current.putBrowserRequestArchive([{ ...late, lateResponse: { client_request_id: 'late', charge_applied: 25_000 },
        lateAt: FIXED_NOW }, { ...invalid, invalidCheck: 'S4', invalidAt: FIXED_NOW }, deferred,
    archive.buildRequestEvidenceRecord({ deploymentId: V2C, noteId: 5, anchor: '0xb1', nullifier: '0x50b1', now: FIXED_NOW })]);
    await current.putBrowserWithdrawal({
        recordId: `${V2C}:11155111:${V2C_VAULT}:3`, deploymentId: V2C, chainId: 11155111, contractAddress: V2C_VAULT,
        noteId: 3, mode: 'escape', phase: 'pending', chainStatus: 'pending_withdrawal', destination: DESTINATION,
        finalBalance: 800_000, stateBalance: '1000000', concededAtInit: '0', boundAtState: '300000', concededCurrent: '200000',
        validUntil: 1_800_010_000, challengeDeadline: 1_800_100_000, startBlockNumber: 10, withdrawalNullifier: '0x50a3',
        state: v2cState({ note_id: 3, current_anchor: '0xa3' }),
        exitLock: { noteId: 3, anchor: '0xa3', mode: 'escape', since: 1, released: [{ kind: 0, valid_until: 9, conceded: '0', at: 1 }] }
    });
    await current.putBrowserWithdrawal({
        recordId: `${V2C}:11155111:${V2C_VAULT}:2`, deploymentId: V2C, chainId: 11155111, contractAddress: V2C_VAULT,
        noteId: 2, mode: 'escape', phase: 'closed', chainStatus: 'closed', destination: DESTINATION, finalBalance: 600_000,
        payoutAlert: 'concession_exceeded_bound', concededFinal: '400000', payoutVerified: true
    });
}

async function writeLegacyRecords() {
    const state = legacyState();
    await legacy.putBrowserWithdrawal({
        recordId: `${LEGACY}:11155111:${LEGACY_VAULT}:9`, deploymentId: LEGACY, chainId: 11155111, contractAddress: LEGACY_VAULT,
        noteId: 9, mode: 'mutual', phase: 'parked', clearanceReserved: true, destination: DESTINATION, finalBalance: 3_000_000,
        state, withdrawalNullifier: '0x5001',
        preparedWithdrawal: { phase: 'reserving', mode: 'mutual', noteId: 9, clearanceReserved: true, withdrawalNullifier: '0x5001' }
    });
    await legacy.putBrowserRequestArchive([legacyArchive.buildRequestJournalRecord({ deploymentId: LEGACY, state,
        journal: journalAt(state, 'legacy-request'), disposition: 'discarded_stale_root',
        observations: [legacyArchive.requestObservation('unknown', 'stale_root', FIXED_NOW - 10_000)], now: FIXED_NOW })]);
}

test('the vendored legacy store is the ac9be63 copy', async () => {
    for (const [file, sha256] of Object.entries(LEGACY_SHA256)) {
        const bytes = await readFile(new URL(file, LEGACY_FIXTURE));
        assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `${file} is the frozen ac9be63 copy`);
    }
});

test('the legacy build reads a store this build wrote mid-exit without throwing or rewriting its records', async () => {
    indexedDB.clear();
    await withFixedClock(async () => {
        await writeV2cStore();
        await writeLegacyRecords();
        // This build's own load, which projects the public deposit rows that
        // either build derives from any deployment's note states.
        await current.readBrowserWalletSnapshot(V2C);
    });
    const written = dump();
    const before = entriesOf(written, V2C);
    // The committed snapshot is what the release branch reads with its own build.
    if (process.env.ZKAPI_UPDATE_FIXTURES === '1') {
        await writeFile(SNAPSHOT, `${JSON.stringify(written, null, 2)}\n`);
    }
    assert.deepEqual(JSON.parse(await readFile(SNAPSHOT, 'utf8')), JSON.parse(JSON.stringify(written)),
        'fixtures/v2c-store-snapshot.json is the store this build writes (ZKAPI_UPDATE_FIXTURES=1 rewrites it)');
    assert.ok(indexedDB.versions.every(version => version === 3), 'the shared database version is never bumped');

    // Everything the legacy runtime does at load, with a host loader and with
    // its own records: no throw.
    const own = await legacy.readBrowserWalletSnapshot(LEGACY);
    assert.deepEqual(own.withdrawals.map(record => record.noteId), [9]);
    assert.deepEqual(own.requestArchive.map(record => record.clientRequestId), ['legacy-request']);
    assert.deepEqual(own.otherDeploymentWithdrawals.map(record => [record.deploymentId, record.noteId]), [[V2C, 3]],
        'the legacy build sees this build\'s open escape as another deployment\'s');
    await legacy.readBrowserWalletSnapshot();
    const holdings = await legacy.readBrowserWalletHoldings();
    assert.deepEqual(holdings.map(entry => [entry.deploymentId, entry.runtime]), [[V2C, true], [LEGACY, false]]);
    // The legacy runtime refuses to load over this build's runtime slot.
    assert.equal(legacy.browserRuntimeHoldsState((await legacy.readBrowserWallet())), true);
    await legacy.listBrowserRequestArchive();
    await legacy.listBrowserWithdrawals();
    await legacy.readBrowserWalletPayoutCredits();
    // Its own writes: an observation, and the sanitized close of its note.
    await legacy.putBrowserRequestArchive([{ archiveId: own.requestArchive[0].archiveId, type: 'request_journal',
        serverObservations: [legacyArchive.requestObservation('unknown', 'recovery', FIXED_NOW)] }]);
    await legacy.updateBrowserWithdrawal(`${LEGACY}:11155111:${LEGACY_VAULT}:9`, { phase: 'closed', chainStatus: 'closed' },
        { sanitize: true });

    const after = entriesOf(dump(), V2C);
    assert.deepEqual(after, before, 'no record of this build\'s deployment changed');
    const legacyAfter = entriesOf(dump(), LEGACY);
    assert.equal(legacyAfter.withdrawals[`${LEGACY}:11155111:${LEGACY_VAULT}:9`].phase, 'closed', 'its own records still move');
});

test('this build reads a store the legacy build wrote without throwing or rewriting its records', async () => {
    indexedDB.clear();
    const state = legacyState({ note_id: 11 });
    const journal = journalAt(state, 'legacy-live');
    await withFixedClock(async () => {
        // A legacy runtime with an open note and a live request journal.
        await legacy.commitBrowserWallet({ deploymentId: LEGACY, billingAsset: 'native_eth', state, journal },
            { requestArchive: [legacyArchive.buildRequestJournalRecord({ deploymentId: LEGACY, state, journal, now: FIXED_NOW })] });
        await writeLegacyRecords();
        await legacy.putBrowserWithdrawal({
            recordId: `${LEGACY}:11155111:${LEGACY_VAULT}:12`, deploymentId: LEGACY, chainId: 11155111,
            contractAddress: LEGACY_VAULT, noteId: 12, mode: 'escape', phase: 'pending', chainStatus: 'pending_withdrawal',
            destination: DESTINATION, finalBalance: 1_000_000, challengeDeadline: 1_800_100_000, startBlockNumber: 5,
            state: legacyState({ note_id: 12 }), withdrawalNullifier: '0x5012'
        });
        await legacy.readBrowserWalletSnapshot(LEGACY);
    });
    const before = entriesOf(dump(), LEGACY);

    // A host's loader: the legacy runtime holds an open note.
    const holdings = await current.readBrowserWalletHoldings();
    assert.deepEqual(holdings.map(entry => [entry.deploymentId, entry.runtime,
        entry.withdrawals.map(record => record.noteId).sort((a, b) => a - b)]), [[LEGACY, true, [9, 12]]]);
    // This build's runtime refuses another deployment's runtime slot.
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: V2C };
    await assert.rejects(runtime.reload(), /This browser contains a wallet for zkapi-native-eth-sepolia-note-bound-v1/);
    const snapshot = await current.readBrowserWalletSnapshot(V2C);
    assert.deepEqual(snapshot.otherDeploymentWithdrawals.map(record => record.noteId).sort((a, b) => a - b), [9, 12]);
    assert.deepEqual(snapshot.requestArchive, [], 'another deployment\'s requests are never this build\'s');
    await current.readBrowserWalletSnapshot();
    await current.listBrowserRequestArchive();
    await current.readBrowserWalletPayoutCredits();
    // This build's own writes beside them.
    const ownState = v2cState();
    await current.putBrowserRequestArchive([archive.buildRequestJournalRecord({ deploymentId: V2C, state: ownState,
        journal: journalAt(ownState, 'v2c'), disposition: 'late_successor' })]);
    await current.putBrowserWithdrawal({ recordId: `${V2C}:11155111:${V2C_VAULT}:1`, deploymentId: V2C, chainId: 11155111,
        contractAddress: V2C_VAULT, noteId: 1, mode: 'escape', phase: 'closed', chainStatus: 'closed', destination: DESTINATION,
        finalBalance: 1 });

    assert.deepEqual(entriesOf(dump(), LEGACY), before, 'no record of the legacy deployment changed');
});
