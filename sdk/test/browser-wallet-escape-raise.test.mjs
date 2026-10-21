// After a raise (EscapeConcessionRaised) the vault pays B − c_final. Every
// payout matcher (background sync, the finalize action and the credit) must
// accept that amount and reach 'closed' (design §6.4 E5); deposits verify the
// deployment through the wallet provider and the pinned RPC and respect the
// canary caps (§6.5).
import assert from 'node:assert/strict';
import test from 'node:test';
import { keccak256Hex, memoryIndexedDb, selectorOf } from './helpers/request-archive-harness.mjs';
import { nativeFunding } from './helpers/native-fixtures.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, removeItem() {}, setItem() {} };
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { default: runtime, BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { codehash } = await import('../services/zkapiKeccak.mjs');
const { CONCESSION_CIRCUIT_ID_HASH } = await import('../services/zkapiDeploymentCheck.mjs');
const { ABI } = globalThis.zkapiWallet;

const DEPLOYMENT_ID = 'raise-test';
const CHAIN_ID = 11155111;
const VAULT = `0x${'22'.repeat(20)}`;
const DESTINATION = '0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f';
const FROM = `0x${'77'.repeat(20)}`;
const NOTE_ID = 7;
const B = 1_000_000;
const BOUND = 300_000;
const NULLIFIER = '0x99';
const START_BLOCK = 4_900;
const CLOSE_BLOCK = 5_000;
const FINALIZE_HASH = `0x${'f1'.repeat(32)}`;
const CLAIM_HASH = `0x${'c1'.repeat(32)}`;
const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const TOPIC = Object.freeze({
    raised: keccak256Hex('EscapeConcessionRaised(uint32,uint256,uint128,uint128)'),
    deferred: keccak256Hex('EscapePayoutDeferred(uint32,address,uint128)'),
    claimed: keccak256Hex('EscapePayoutClaimed(address,uint128)'),
    finalized: keccak256Hex('EscapeWithdrawalFinalized(uint32,uint256,uint128,address)')
});
const SELECTOR = Object.freeze({
    notes: selectorOf('notes(uint32)'),
    pending: selectorOf('pendingWithdrawals(uint32)'),
    concessions: selectorOf('pendingConcessions(uint32)'),
    credits: selectorOf('escapePayoutCredits(address)')
});
const recordId = `${DEPLOYMENT_ID}:${CHAIN_ID}:${VAULT}:${NOTE_ID}`;

function escapeRecord(overrides = {}) {
    return {
        recordId, deploymentId: DEPLOYMENT_ID, chainId: CHAIN_ID, contractAddress: VAULT, mode: 'escape',
        phase: 'pending', chainStatus: 'pending_withdrawal', noteId: NOTE_ID, destination: DESTINATION,
        // The escape started at B with nothing conceded; its state's bound is BOUND.
        finalBalance: B, stateBalance: String(B), concededAtInit: '0', boundAtState: String(BOUND),
        withdrawalNullifier: NULLIFIER, challengeDeadline: Math.floor(Date.now() / 1_000) - 1,
        startBlockNumber: START_BLOCK, lastObservedBlock: START_BLOCK, ...overrides
    };
}

function finalizeReceipt({ paid, credited = false }) {
    return {
        transactionHash: FINALIZE_HASH, blockNumber: hex(CLOSE_BLOCK), status: '0x1',
        logs: [
            ...(credited ? [{ address: VAULT, topics: [TOPIC.deferred, `0x${word(NOTE_ID)}`, `0x${word(DESTINATION)}`],
                data: `0x${word(paid)}`, removed: false }] : []),
            { address: VAULT, topics: [TOPIC.finalized, `0x${word(NOTE_ID)}`],
                data: `0x${word(NULLIFIER)}${word(paid)}${word(DESTINATION)}`, removed: false }
        ]
    };
}

const raisedLog = (conceded, blockNumber = START_BLOCK + 10, nullifier = NULLIFIER) => ({
    address: VAULT, blockNumber: hex(blockNumber), logIndex: '0x0', removed: false,
    topics: [TOPIC.raised, `0x${word(NOTE_ID)}`], data: `0x${word(nullifier)}${word(conceded)}${word(B - conceded)}`
});

function scriptedChain() {
    const chain = {
        head: CLOSE_BLOCK + 10, finalized: CLOSE_BLOCK - 10, noteStatus: 3, raises: [], logsFail: false,
        pending: { finalBalance: B, conceded: 0 }, credits: new Map(), receipts: new Map(), calls: [], sent: []
    };
    chain.provider = {
        async request({ method, params = [] }) {
            chain.calls.push({ method, params: structuredClone(params) });
            if (method === 'eth_chainId') return hex(CHAIN_ID);
            if (method === 'eth_blockNumber') return hex(chain.head);
            if (method === 'eth_getBlockByNumber') return { number: hex(chain.finalized) };
            if (method === 'eth_getTransactionReceipt') return structuredClone(chain.receipts.get(params[0]) ?? null);
            if (method === 'eth_getTransactionByHash') return null;
            if (method === 'eth_getLogs') {
                if (chain.logsFail) throw new Error('log range too large');
                const [{ address, topics, fromBlock, toBlock }] = params;
                assert.equal(address, VAULT);
                assert.deepEqual(topics, [ABI.escapeConcessionRaisedEvent, `0x${word(NOTE_ID)}`]);
                return chain.raises.filter(log => BigInt(log.blockNumber) >= BigInt(fromBlock)
                    && BigInt(log.blockNumber) <= BigInt(toBlock));
            }
            if (method === 'eth_call') {
                const [{ data }] = params;
                if (data.startsWith(SELECTOR.notes)) return `0x${[0, 0, 0, chain.noteStatus].map(word).join('')}`;
                if (data.startsWith(SELECTOR.pending)) {
                    return `0x${[1, 0x11, NULLIFIER, chain.pending.finalBalance, DESTINATION, CLOSE_BLOCK].map(word).join('')}`;
                }
                if (data.startsWith(SELECTOR.concessions)) {
                    return `0x${[0x5099, chain.pending.finalBalance + chain.pending.conceded, chain.pending.conceded].map(word).join('')}`;
                }
                if (data.startsWith(SELECTOR.credits)) return `0x${word(chain.credits.get(`0x${data.slice(-40)}`) ?? 0)}`;
                throw new Error(`unexpected eth_call ${data.slice(0, 10)}`);
            }
            if (method === 'eth_estimateGas') return '0x9c40';
            if (method === 'eth_sendTransaction') {
                chain.sent.push(structuredClone(params[0]));
                const destination = `0x${params[0].data.slice(-40)}`;
                const amount = chain.credits.get(destination) ?? 0;
                chain.credits.set(destination, 0);
                chain.receipts.set(CLAIM_HASH, { transactionHash: CLAIM_HASH, blockNumber: hex(chain.head + 1), status: '0x1',
                    logs: [{ address: VAULT, topics: [TOPIC.claimed, `0x${word(destination)}`], data: `0x${word(amount)}`, removed: false }] });
                return CLAIM_HASH;
            }
            throw new Error(`unexpected RPC ${method}`);
        }
    };
    return chain;
}

async function scenario(record = escapeRecord()) {
    indexedDB.clear();
    runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    runtime.config = { funding: nativeFunding({ chain_id: CHAIN_ID, contract_address: VAULT }) };
    runtime.browserConfig = { trusted_deployment: {} };
    runtime.init = async () => runtime.snapshot();
    await store.putBrowserWithdrawal(record);
    await runtime.reload();
    const chain = scriptedChain();
    globalThis.ethereum = chain.provider;
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    client.connectWallet = async () => FROM;
    client.submittedTransactionMetadata = async () => null;
    client.refresh = async () => {
        await runtime.reload();
        client.withdrawals = runtime.snapshot().withdrawals;
        return client.snapshot();
    };
    await client.refresh();
    const saved = async () => (await store.listBrowserWithdrawals(DEPLOYMENT_ID)).find(entry => entry.noteId === NOTE_ID);
    return { chain, client, saved };
}

test('a pending escape shows a raise: its payout and concession follow pendingWithdrawals and pendingConcessions', async () => {
    const { chain, client, saved } = await scenario();
    chain.noteStatus = 2;
    chain.pending = { finalBalance: B - 200_000, conceded: 200_000 };
    await client.syncEscapeWithdrawals(() => {});
    let record = await saved();
    assert.equal(record.finalBalance, B - 200_000);
    assert.equal(record.concededCurrent, '200000');
    // A further raise is announced.
    chain.pending = { finalBalance: B - 250_000, conceded: 250_000 };
    const statuses = [];
    await client.syncEscapeWithdrawals(message => statuses.push(message));
    record = await saved();
    assert.equal(record.concededCurrent, '250000');
    assert.ok(statuses.some(message => /raised this escape’s concession/.test(message)));
    const reads = chain.calls.filter(call => call.method === 'eth_call');
    const pendingRead = reads.findLast(call => call.params[0].data.startsWith(SELECTOR.pending));
    const concessionRead = reads.findLast(call => call.params[0].data.startsWith(SELECTOR.concessions));
    assert.equal(pendingRead.params[1], concessionRead.params[1], 'both read at the same block');
});

test('E5: after a raise the escape\'s start receipt still matches its start, on every later sync', async () => {
    const START_HASH = `0x${'5a'.repeat(32)}`;
    const deadline = Math.floor(Date.now() / 1_000) + 86_400;
    const { chain, client, saved } = await scenario(escapeRecord({
        challengeDeadline: deadline, transactionHash: START_HASH, startRecoveryPending: true
    }));
    // The start receipt: initiated at B with nothing conceded.
    chain.receipts.set(START_HASH, { transactionHash: START_HASH, blockNumber: hex(START_BLOCK), status: '0x1', logs: [
        { address: VAULT, topics: [ABI.escapeInitiatedEvent, `0x${word(NOTE_ID)}`],
            data: `0x${[NULLIFIER, B, DESTINATION, deadline, 0x77].map(word).join('')}`, removed: false },
        { address: VAULT, topics: [ABI.escapeConcessionRecordedEvent, `0x${word(NOTE_ID)}`],
            data: `0x${[0x5099, B, 0].map(word).join('')}`, removed: false }
    ] });
    chain.noteStatus = 2;
    chain.pending = { finalBalance: B - 200_000, conceded: 200_000 };
    await client.syncEscapeWithdrawals(() => {});
    let record = await saved();
    assert.equal(record.finalBalance, B - 200_000, 'the record follows the raise');
    assert.equal(record.startRecoveryPending, false);
    assert.equal(record.startSubmissionOutcome, 'resolved');
    await client.syncEscapeWithdrawals(() => {});
    // A defeat after the raise is a challenge of a started escape, not a
    // start the client must still look for.
    chain.noteStatus = 1;
    const [result] = await client.syncEscapeWithdrawals(() => {});
    record = await saved();
    assert.notEqual(result.status, 'submitted_unconfirmed');
    assert.equal(record.phase, 'challenged_unconfirmed');
    assert.equal(record.startSubmissionOutcome, 'resolved');
});

test('raise then finalize: the finalize action accepts B − c_final and the record reaches closed', async () => {
    const { chain, client, saved } = await scenario();
    // The raise landed after the last sync: the record still says B.
    chain.raises = [raisedLog(120_000), raisedLog(200_000, START_BLOCK + 20)];
    client.sendContractTransaction = async (_from, _to, data, onSubmitted) => {
        assert.equal(data, globalThis.zkapiWallet.encodeFinalizeEscape(NOTE_ID));
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 200_000 });
    };
    const result = await client.finalizeEscape(recordId, () => {});
    assert.equal(result.status, 'closed');
    let record = await saved();
    assert.equal(record.phase, 'closed_unconfirmed');
    assert.equal(record.finalBalance, B - 200_000);
    assert.equal(record.concededFinal, '200000');
    assert.equal(record.payoutVerified, true);
    const logRead = chain.calls.find(call => call.method === 'eth_getLogs');
    assert.deepEqual([logRead.params[0].fromBlock, logRead.params[0].toBlock], [hex(START_BLOCK), hex(CLOSE_BLOCK)]);
    // Finality: the background sync matches the same receipt and closes it.
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ paid: B - 200_000 }));
    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    record = await saved();
    assert.equal(record.phase, 'closed');
    assert.equal(record.payoutVerified, true);

    // The pre-raise amount (or any other) never matches.
    for (const paid of [B, B - 120_000, B - 200_001]) {
        const other = await scenario();
        other.chain.raises = [raisedLog(120_000), raisedLog(200_000, START_BLOCK + 20)];
        other.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
            await onSubmitted(FINALIZE_HASH);
            return finalizeReceipt({ paid });
        };
        await assert.rejects(other.client.finalizeEscape(recordId, () => {}), /did not match the pending withdrawal/, String(paid));
    }
    // A raise of another escape of this note (another nullifier) is not this one's.
    const foreign = await scenario();
    foreign.chain.raises = [raisedLog(200_000, START_BLOCK + 20, '0x55')];
    foreign.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 200_000 });
    };
    await assert.rejects(foreign.client.finalizeEscape(recordId, () => {}), /did not match/);
});

test('raise then deferred credit then claim: the background sync and the claim reach closed', async () => {
    const { chain, client, saved } = await scenario(escapeRecord({
        phase: 'finalizing', finalizeTransactionHash: FINALIZE_HASH, finalizeTransactionHashes: [FINALIZE_HASH]
    }));
    chain.raises = [raisedLog(150_000)];
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ paid: B - 150_000, credited: true }));
    chain.credits.set(DESTINATION, B - 150_000);
    const [result] = await client.syncEscapeWithdrawals(() => {});
    assert.equal(result.status, 'closed');
    assert.equal(result.payout_credited, true);
    let record = await saved();
    assert.equal(record.phase, 'closed_unconfirmed');
    assert.equal(record.payoutCredited, true);
    assert.equal(record.creditedAmount, B - 150_000);
    assert.equal(record.finalBalance, B - 150_000);
    assert.equal(record.concededFinal, '150000');

    const claim = await client.claimEscapePayout(recordId, () => {});
    assert.equal(claim.status, 'claimed');
    assert.equal(claim.amount, BigInt(B - 150_000));
    record = await saved();
    assert.equal(record.payoutClaimed, true);
    assert.equal(record.payoutVerified, true);

    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    record = await saved();
    assert.equal(record.phase, 'closed');
    assert.equal(record.payoutVerified, true);
});

test('a payout below B − b closes with concession_exceeded_bound; unreadable raise logs are accepted within bounds', async () => {
    const { chain, client, saved } = await scenario();
    chain.raises = [raisedLog(400_000)];
    const statuses = [];
    client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 400_000 });
    };
    await client.finalizeEscape(recordId, message => statuses.push(message));
    const record = await saved();
    assert.equal(record.phase, 'closed_unconfirmed');
    assert.equal(record.payoutAlert, 'concession_exceeded_bound');
    assert.ok(statuses.some(message => /concession_exceeded_bound/.test(message)));

    // The logs cannot be read: any amount up to B − c_init is accepted, never more.
    const bounded = await scenario(escapeRecord({ concededAtInit: '50000', finalBalance: B - 50_000 }));
    bounded.chain.logsFail = true;
    bounded.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 120_000 });
    };
    await bounded.client.finalizeEscape(recordId, () => {});
    assert.equal((await bounded.saved()).concededFinal, '120000');
    const above = await scenario(escapeRecord({ concededAtInit: '50000', finalBalance: B - 50_000 }));
    above.chain.logsFail = true;
    above.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 49_999 });
    };
    await assert.rejects(above.client.finalizeEscape(recordId, () => {}), /did not match/);

    // A record saved before vault revision 3 (no B or c_init) matches exactly.
    const legacy = await scenario(escapeRecord({ stateBalance: undefined, concededAtInit: undefined, boundAtState: undefined }));
    legacy.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ paid: B - 1 });
    };
    await assert.rejects(legacy.client.finalizeEscape(recordId, () => {}), /did not match/);
});

test('an escape\'s record carries B, its initial concession, the bound and valid_until from its plan', async () => {
    indexedDB.clear();
    runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    runtime.config = { funding: nativeFunding({ chain_id: CHAIN_ID, contract_address: VAULT }) };
    const state = { note_id: NOTE_ID, current_balance: B, current_anchor: '0x1234', expiry_ts: 2_000_000_000 };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT_ID, billingAsset: 'native_eth', state,
        exitLock: { noteId: NOTE_ID, anchor: '0x1234', mode: 'escape', since: 1, released: [{ kind: 0, valid_until: 9, conceded: '0', at: 1 }] },
        preparedWithdrawal: { mode: 'escape', noteId: NOTE_ID, destination: DESTINATION, stateBalance: String(B),
            concededAtInit: '25000', boundAtState: String(BOUND), validUntil: 1_900_000_000, withdrawalNullifier: NULLIFIER,
            transactionHash: FINALIZE_HASH } });
    await runtime.reload();
    const record = await runtime.detachEscapeWithdrawal({ noteId: NOTE_ID, destination: DESTINATION, finalBalance: B - 25_000,
        challengeDeadline: 2_000_000_000, transactionHash: FINALIZE_HASH, startBlockNumber: START_BLOCK });
    assert.deepEqual([record.stateBalance, record.concededAtInit, record.boundAtState, record.validUntil],
        [String(B), '25000', String(BOUND), 1_900_000_000]);
    assert.equal(record.exitLock.mode, 'escape', 'the exit lock moves with the note');
    assert.equal((await store.readBrowserWallet()).exitLock, null);
});

// ---- deposits: deployment pins and canary caps (§6.5, §10.7 C) ----

const ADAPTER = `0x${'33'.repeat(20)}`;
const POSEIDON = `0x${'44'.repeat(20)}`;
const CODE = { [VAULT]: '0x6080604052', [ADAPTER]: '0x60806040', [POSEIDON]: '0x6001600201' };
const pinnedProfile = (overrides = {}) => ({
    deployment_status: 'deployed', contract_address: VAULT, proof_adapter_address: ADAPTER, poseidon_library_address: POSEIDON,
    vault_runtime_codehash: codehash(CODE[VAULT]), adapter_runtime_codehash: codehash(CODE[ADAPTER]),
    poseidon_runtime_codehash: codehash(CODE[POSEIDON]),
    request_vk_keccak256: `0x${'4d'.repeat(32)}`, withdrawal_vk_keccak256: `0x${'29'.repeat(32)}`,
    challenge_period: 172_800, note_ttl: 2_592_000, max_pause_duration: 3_888_000,
    state_signing_key: { x: '0x111', y: '0x112' }, clearance_signing_key: { x: '0x113', y: '0x114' },
    ...overrides
});

function deploymentChain({ code = CODE, getters = {}, balance = 0n } = {}) {
    const values = {
        [`${VAULT}:${ABI.proofAdapter}`]: BigInt(ADAPTER), [`${VAULT}:${ABI.stateSigningKeyX}`]: 0x111n,
        [`${VAULT}:${ABI.stateSigningKeyY}`]: 0x112n, [`${VAULT}:${ABI.clearanceSigningKeyX}`]: 0x113n,
        [`${VAULT}:${ABI.clearanceSigningKeyY}`]: 0x114n, [`${VAULT}:${ABI.challengePeriod}`]: 172_800n,
        [`${VAULT}:${ABI.noteTtl}`]: 2_592_000n, [`${VAULT}:${ABI.maxPauseDuration}`]: 3_888_000n,
        [`${VAULT}:${ABI.CONCESSION_ESCAPE_VERSION}`]: 1n, [`${VAULT}:${ABI.ROOT_HISTORY_WINDOW}`]: 86_400n,
        [`${ADAPTER}:${ABI.CIRCUIT_ID_HASH}`]: BigInt(CONCESSION_CIRCUIT_ID_HASH),
        [`${ADAPTER}:${ABI.REQUEST_VK_HASH}`]: BigInt(`0x${'4d'.repeat(32)}`),
        [`${ADAPTER}:${ABI.WITHDRAWAL_VK_HASH}`]: BigInt(`0x${'29'.repeat(32)}`),
        ...getters
    };
    const calls = [];
    return {
        calls,
        request: async ({ method, params }) => {
            calls.push(method);
            if (method === 'eth_chainId') return hex(CHAIN_ID);
            if (method === 'eth_getCode') return code[params[0]] ?? '0x';
            if (method === 'eth_getBalance') { assert.equal(params[0], VAULT); return hex(balance); }
            assert.equal(method, 'eth_call');
            const key = `${params[0].to}:${params[0].data.slice(2)}`;
            if (!(key in values)) throw Object.assign(new Error('execution reverted'), { code: 3 });
            return `0x${word(values[key])}`;
        }
    };
}

function depositRuntime(trusted, pinned) {
    const deposit = new BrowserWalletRuntime();
    deposit.config = { funding: nativeFunding({ chain_id: CHAIN_ID, contract_address: VAULT }) };
    deposit.browserConfig = { trusted_deployment: trusted };
    deposit.pinnedRpc = () => pinned.request;
    return deposit;
}

test('a deposit is refused unless the wallet provider and the pinned RPC both show the pinned deployment', async () => {
    const trusted = pinnedProfile();
    const wallet = deploymentChain();
    const pinned = deploymentChain();
    const ok = await depositRuntime(trusted, pinned).verifyDeploymentForDeposit({ walletRequest: wallet.request, depositWei: 1n });
    assert.equal(ok.ok, true);
    assert.ok(wallet.calls.includes('eth_getCode') && pinned.calls.includes('eth_getCode'), 'both sources are read');

    // A backdoored adapter seen through the wallet provider, or another
    // vault code seen through the pinned RPC: no deposit.
    for (const [walletChange, pinnedChange, field] of [
        [{ getters: { [`${ADAPTER}:${ABI.WITHDRAWAL_VK_HASH}`]: 1n } }, {}, 'WITHDRAWAL_VK_HASH'],
        [{}, { code: { ...CODE, [VAULT]: '0x00' } }, 'vault_runtime_codehash']
    ]) {
        await assert.rejects(depositRuntime(trusted, deploymentChain(pinnedChange)).verifyDeploymentForDeposit({
            walletRequest: deploymentChain(walletChange).request, depositWei: 1n }), error => {
            assert.equal(error.code, 'deployment_mismatch');
            assert.ok(error.data.mismatches.some(entry => entry.field === field));
            return true;
        });
    }
    // A placeholder profile or a profile without pins can take no deposit.
    await assert.rejects(depositRuntime(pinnedProfile({ adapter_runtime_codehash: null }), pinned)
        .verifyDeploymentForDeposit({ walletRequest: wallet.request, depositWei: 1n }), { code: 'deployment_unverifiable' });
});

test('canary caps: a per-note cap and an aggregate cap against the vault balance read through the wallet provider', async () => {
    const until = Math.floor(Date.now() / 1_000) + 3_600;
    const trusted = pinnedProfile({ canary: { per_note_max_wei: '250000000000000000', aggregate_max_wei: '25000000000000000000', until } });
    const pinned = deploymentChain();
    const deposit = depositRuntime(trusted, pinned);
    await assert.rejects(deposit.verifyDeploymentForDeposit({ walletRequest: deploymentChain().request,
        depositWei: 250_000_000_000_000_001n }), error => error.code === 'canary_cap_exceeded' && error.data.cap === 'per_note');
    const wallet = deploymentChain({ balance: 24_900_000_000_000_000_000n });
    await assert.rejects(deposit.verifyDeploymentForDeposit({ walletRequest: wallet.request,
        depositWei: 200_000_000_000_000_000n }), error => error.code === 'canary_cap_exceeded' && error.data.cap === 'aggregate');
    assert.ok(wallet.calls.includes('eth_getBalance'), 'the vault balance comes from the wallet provider');
    assert.equal((await deposit.verifyDeploymentForDeposit({ walletRequest: deploymentChain({ balance: 1n }).request,
        depositWei: 100_000_000_000_000_000n })).ok, true);
    // After the canary period the caps no longer apply.
    const after = depositRuntime(pinnedProfile({ canary: { ...trusted.canary, until: 1 } }), pinned);
    assert.equal((await after.verifyDeploymentForDeposit({ walletRequest: deploymentChain().request,
        depositWei: 10n ** 21n })).ok, true);
});
