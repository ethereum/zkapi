import assert from 'node:assert/strict';
import test from 'node:test';
import { keccak256Hex, memoryIndexedDb, selectorOf } from './helpers/request-archive-harness.mjs';
import { nativeFunding } from './helpers/native-fixtures.mjs';

// A hardened vault closes an escape even when its push to the destination
// fails, and only credits the payout (EscapePayoutDeferred). These tests run
// the real wallet store, runtime and client against a scripted chain whose
// receipts follow the layout pinned by the vault's
// test_finalizeReceiptTellsPaidFromCreditedPayout.
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, removeItem() {}, setItem() {} };
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { deriveExpiryRecords } = await import('../services/zkapiExpiryHistory.mjs');

const DEPLOYMENT_ID = 'payout-credit-test';
const CHAIN_ID = 11155111;
const VAULT = `0x${'22'.repeat(20)}`;
const DESTINATION = '0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f';
const OTHER_DESTINATION = `0x${'44'.repeat(20)}`;
const FROM = `0x${'77'.repeat(20)}`;
const NOTE_ID = 7;
const FINAL_BALANCE = 700_000;
const CLOSE_BLOCK = 5_000;
const FINALIZE_HASH = `0x${'f1'.repeat(32)}`;
const CLAIM_HASH = `0x${'c1'.repeat(32)}`;
const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
// Derived from the event and function signatures, not from the SDK's table.
const TOPIC = Object.freeze({
    deferred: keccak256Hex('EscapePayoutDeferred(uint32,address,uint128)'),
    claimed: keccak256Hex('EscapePayoutClaimed(address,uint128)'),
    finalized: keccak256Hex('EscapeWithdrawalFinalized(uint32,uint256,uint128,address)')
});
const SELECTOR = Object.freeze({
    notes: selectorOf('notes(uint32)'),
    pending: selectorOf('pendingWithdrawals(uint32)'),
    credits: selectorOf('escapePayoutCredits(address)'),
    claim: selectorOf('claimEscapePayout(address)'),
    nativeTransferFailed: selectorOf('NativeTransferFailed()'),
    zeroAmount: selectorOf('ZeroAmount()')
});
const CREDITED_MESSAGE = /escape closed, but the destination did not accept the payout\. The vault holds it/;

const recordIdOf = noteId => `${DEPLOYMENT_ID}:${CHAIN_ID}:${VAULT}:${noteId}`;

function finalizeReceipt({ credited, noteId = NOTE_ID, destination = DESTINATION, hash = FINALIZE_HASH,
    blockNumber = CLOSE_BLOCK } = {}) {
    return {
        transactionHash: hash,
        blockNumber: hex(blockNumber),
        status: '0x1',
        logs: [
            ...(credited ? [{
                address: VAULT,
                topics: [TOPIC.deferred, `0x${word(noteId)}`, `0x${word(destination)}`],
                data: `0x${word(FINAL_BALANCE)}`,
                removed: false
            }] : []),
            {
                address: VAULT,
                topics: [TOPIC.finalized, `0x${word(noteId)}`],
                data: `0x${word(99)}${word(FINAL_BALANCE)}${word(destination)}`,
                removed: false
            }
        ]
    };
}

function claimReceipt({ destination = DESTINATION, amount = FINAL_BALANCE, blockNumber = CLOSE_BLOCK + 20,
    hash = CLAIM_HASH, status = '0x1' } = {}) {
    return {
        transactionHash: hash,
        blockNumber: hex(blockNumber),
        status,
        logs: status === '0x1' ? [{
            address: VAULT,
            topics: [TOPIC.claimed, `0x${word(destination)}`],
            data: `0x${word(amount)}`,
            removed: false
        }] : []
    };
}

function escapeRecord(overrides = {}) {
    const noteId = overrides.noteId ?? NOTE_ID;
    return {
        recordId: recordIdOf(noteId),
        deploymentId: DEPLOYMENT_ID,
        chainId: CHAIN_ID,
        contractAddress: VAULT,
        mode: 'escape',
        phase: 'pending',
        chainStatus: 'pending_withdrawal',
        noteId,
        destination: DESTINATION,
        finalBalance: FINAL_BALANCE,
        challengeDeadline: Math.floor(Date.now() / 1_000) - 1,
        startBlockNumber: CLOSE_BLOCK - 100,
        lastObservedBlock: CLOSE_BLOCK - 50,
        ...overrides
    };
}

// The scripted chain: note statuses per note id, escape payout credits per
// destination, receipts and transactions by hash.
function scriptedChain() {
    const chain = {
        head: CLOSE_BLOCK + 10,
        finalized: CLOSE_BLOCK - 10,
        noteStatus: new Map([[NOTE_ID, 3]]),
        credits: new Map(),
        receipts: new Map(),
        transactions: new Map(),
        claimRevert: null,
        nextClaimHash: CLAIM_HASH,
        calls: [],
        sent: []
    };
    chain.provider = {
        async request({ method, params = [] }) {
            chain.calls.push({ method, params: structuredClone(params) });
            if (method === 'eth_chainId') return hex(CHAIN_ID);
            if (method === 'eth_blockNumber') return hex(chain.head);
            if (method === 'eth_getBlockByNumber') {
                assert.deepEqual(params, ['finalized', false]);
                return { number: hex(chain.finalized) };
            }
            if (method === 'eth_getTransactionReceipt') {
                return structuredClone(chain.receipts.get(params[0]) ?? null);
            }
            if (method === 'eth_getTransactionByHash') return structuredClone(chain.transactions.get(params[0]) ?? null);
            if (method === 'eth_call') {
                const [{ to, data }] = params;
                assert.equal(to, VAULT);
                if (data.startsWith(SELECTOR.notes)) {
                    const noteId = Number(BigInt(`0x${data.slice(10)}`));
                    return `0x${[0, 0, 0, chain.noteStatus.get(noteId) ?? 3].map(word).join('')}`;
                }
                if (data.startsWith(SELECTOR.pending)) {
                    return `0x${[1, 0x11, 0x99, FINAL_BALANCE, DESTINATION, CLOSE_BLOCK].map(word).join('')}`;
                }
                if (data.startsWith(SELECTOR.credits)) {
                    assert.equal(data.length, 10 + 64);
                    const destination = `0x${data.slice(-40)}`;
                    return `0x${word(chain.credits.get(destination) ?? 0)}`;
                }
                throw new Error(`unexpected eth_call ${data.slice(0, 10)}`);
            }
            if (method === 'eth_estimateGas') {
                if (chain.claimRevert) {
                    throw { code: 3, message: 'execution reverted', data: chain.claimRevert };
                }
                return '0x9c40';
            }
            if (method === 'eth_sendTransaction') {
                chain.sent.push(structuredClone(params[0]));
                // The claim pays every credit of the destination at once, in
                // the block after the current head.
                const destination = `0x${params[0].data.slice(-40)}`;
                const amount = chain.credits.get(destination) ?? 0;
                chain.credits.set(destination, 0);
                const hash = chain.nextClaimHash;
                chain.receipts.set(hash, chain.claimReceipt
                    ?? claimReceipt({ destination, amount, hash, blockNumber: chain.head + 1 }));
                return hash;
            }
            throw new Error(`unexpected RPC ${method}`);
        }
    };
    return chain;
}

async function scenario({ records = [escapeRecord()], hardened = true } = {}) {
    indexedDB.clear();
    runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    runtime.config = { funding: nativeFunding({ chain_id: CHAIN_ID, contract_address: VAULT }) };
    runtime.browserConfig = { trusted_deployment: hardened ? { vault_revision: 2 } : {} };
    runtime.init = async () => runtime.snapshot();
    for (const record of records) await store.putBrowserWithdrawal(record);
    await runtime.reload();
    const chain = scriptedChain();
    globalThis.ethereum = chain.provider;
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    client.connectWallet = async () => FROM;
    client.refresh = async () => {
        await runtime.reload();
        client.withdrawals = runtime.snapshot().withdrawals;
        return client.snapshot();
    };
    await client.refresh();
    const record = async (noteId = NOTE_ID) => (await store.listBrowserWithdrawals(DEPLOYMENT_ID))
        .find(entry => entry.noteId === noteId);
    return { chain, client, record };
}

test('signature-derived selectors and topics match the SDK table', () => {
    const { ABI } = globalThis.zkapiWallet;
    assert.equal(TOPIC.deferred, ABI.escapePayoutDeferredEvent);
    assert.equal(TOPIC.claimed, ABI.escapePayoutClaimedEvent);
    assert.equal(TOPIC.finalized, ABI.escapeFinalizedEvent);
    assert.equal(SELECTOR.credits, `0x${ABI.escapePayoutCredits}`);
    assert.equal(SELECTOR.claim, `0x${ABI.claimEscapePayout}`);
    assert.equal(SELECTOR.notes, `0x${ABI.notes}`);
    assert.equal(SELECTOR.nativeTransferFailed, '0xf4b3b1bc');
    assert.equal(SELECTOR.zeroAmount, '0x1f2a2005');
});

test('background finalize sync records a credited payout and never verifies it, through finality', async () => {
    const { chain, client, record } = await scenario({ records: [escapeRecord({
        phase: 'finalizing', finalizeTransactionHash: FINALIZE_HASH, finalizeTransactionHashes: [FINALIZE_HASH]
    })] });
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: true }));
    const statuses = [];
    const [result] = await client.syncEscapeWithdrawals(message => statuses.push(message));
    assert.equal(result.status, 'closed');
    assert.equal(result.payout_credited, true);
    let saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutVerified, false, 'a credited payout is not a verified payout');
    assert.equal(saved.creditedAmount, FINAL_BALANCE);
    assert.equal(saved.payoutCreditEvidence, 'receipt');
    assert.match(statuses.at(-1), CREDITED_MESSAGE);
    assert.ok(!statuses.some(message => /returned|up to date/i.test(message)));
    assert.deepEqual(client.creditedEscapePayouts.map(entry => entry.recordId), [recordIdOf(NOTE_ID)]);

    // Finality sanitizes the record but keeps the credit for the claim action.
    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    saved = await record();
    assert.equal(saved.phase, 'closed');
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.creditedAmount, FINAL_BALANCE);
    assert.equal(saved.finalizeTransactionHash, undefined);
    assert.equal(runtime.snapshot().withdrawals[0].payoutCredited, true, 'the host snapshot shows the credit');
    assert.ok(!chain.calls.some(call => call.method === 'eth_sendTransaction'));
});

test('a paid finalization stays verified and is not mistaken for a credit', async () => {
    const { chain, client, record } = await scenario({ records: [escapeRecord({
        phase: 'finalizing', finalizeTransactionHash: FINALIZE_HASH, finalizeTransactionHashes: [FINALIZE_HASH]
    })] });
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: false }));
    // Another credit for the same destination must not taint a paid receipt.
    chain.credits.set(DESTINATION, 123);
    const statuses = [];
    await client.syncEscapeWithdrawals(message => statuses.push(message));
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.payoutCredited, undefined);
    assert.equal(statuses.at(-1), 'Withdrawal status is up to date.');
    assert.ok(!chain.calls.some(call => call.method === 'eth_call' && call.params[0].data.startsWith(SELECTOR.credits)));
});

test('an escape finalized elsewhere is reported credited while the hardened vault holds a credit for it', async () => {
    const { chain, client, record } = await scenario();
    chain.credits.set(DESTINATION, FINAL_BALANCE);
    const statuses = [];
    await client.syncEscapeWithdrawals(message => statuses.push(message));
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.payoutCreditEvidence, 'vault_credit');
    assert.equal(saved.creditedAmount, null);
    assert.match(statuses.at(-1), CREDITED_MESSAGE);
    const creditRead = chain.calls.find(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits));
    assert.equal(creditRead.params[0].data, `${SELECTOR.credits}${word(DESTINATION)}`);
    assert.equal(creditRead.params[1], hex(chain.head), 'read at the block that showed the note closed');

    // Without a credit nothing is claimed either way.
    const other = await scenario();
    other.chain.credits.set(DESTINATION, 0);
    await other.client.syncEscapeWithdrawals(() => {});
    const closed = await other.record();
    assert.equal(closed.phase, 'closed_unconfirmed');
    assert.equal(closed.payoutCredited, undefined);
    assert.equal(closed.payoutVerified, false);
    assert.ok(other.chain.calls.some(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits)));

    // A push an earlier pass proved from its receipt is not re-attributed to
    // a credit the destination holds for another escape.
    const proven = await scenario({ records: [escapeRecord({ phase: 'closed_unconfirmed', chainStatus: 'closed',
        payoutVerified: true, closeBlockNumber: CLOSE_BLOCK })] });
    proven.chain.credits.set(DESTINATION, FINAL_BALANCE);
    await proven.client.syncEscapeWithdrawals(() => {});
    assert.equal((await proven.record()).payoutCredited, undefined);
    assert.ok(!proven.chain.calls.some(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits)));
});

test('a credit read from the vault yields to this escape\'s own receipt proving the push', async () => {
    // Pass 1 cannot read this browser's finalization receipt yet, and the
    // destination holds another escape's credit.
    const { chain, client, record } = await scenario({ records: [escapeRecord({
        phase: 'finalizing', finalizeTransactionHash: FINALIZE_HASH, finalizeTransactionHashes: [FINALIZE_HASH]
    })] });
    chain.credits.set(DESTINATION, 123);
    await client.syncEscapeWithdrawals(() => {});
    let saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutCredited, true, 'without the receipt the credit is the conservative reading');
    assert.equal(saved.payoutCreditEvidence, 'vault_credit');

    // Pass 2 reads the receipt, which carries no EscapePayoutDeferred log.
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: false }));
    const statuses = [];
    const [result] = await client.syncEscapeWithdrawals(message => statuses.push(message));
    assert.equal(result.payout_credited, undefined);
    assert.equal(statuses.at(-1), 'Withdrawal status is up to date.');
    saved = await record();
    assert.equal(saved.payoutCredited, false);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.payoutCreditEvidence, null);
    assert.equal(saved.creditedAmount, null);
    assert.deepEqual(client.creditedEscapePayouts, []);

    // Finality keeps the proven push.
    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    saved = await record();
    assert.equal(saved.phase, 'closed');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.payoutCredited, false);

    // A credit proven by a receipt does not yield.
    const proven = await scenario({ records: [escapeRecord({ phase: 'closed_unconfirmed', chainStatus: 'closed',
        payoutCredited: true, payoutVerified: false, creditedAmount: FINAL_BALANCE, payoutCreditEvidence: 'receipt',
        closeBlockNumber: CLOSE_BLOCK, finalizeTransactionHash: FINALIZE_HASH,
        finalizeTransactionHashes: [FINALIZE_HASH] })] });
    proven.chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: false }));
    await proven.client.syncEscapeWithdrawals(() => {});
    assert.equal((await proven.record()).payoutCredited, true);
    assert.equal((await proven.record()).payoutVerified, false);
});

test('a proven push stays proven through passes that cannot read its receipt', async () => {
    const { chain, client, record } = await scenario({ records: [escapeRecord({
        phase: 'closed_unconfirmed', chainStatus: 'closed', payoutVerified: true, closeBlockNumber: CLOSE_BLOCK,
        lastObservedBlock: CLOSE_BLOCK, finalizeTransactionHash: FINALIZE_HASH,
        finalizeTransactionHashes: [FINALIZE_HASH] })] });
    chain.credits.set(DESTINATION, 123);
    for (const pass of [1, 2]) {
        await client.syncEscapeWithdrawals(() => {});
        const saved = await record();
        assert.equal(saved.payoutVerified, true, `pass ${pass}`);
        assert.equal(saved.payoutCredited, undefined, `pass ${pass}`);
    }
    assert.ok(!chain.calls.some(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits)), 'a proven push is not re-read as a credit');
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: false }));
    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    const final = await record();
    assert.equal(final.phase, 'closed');
    assert.equal(final.payoutVerified, true);
    assert.equal(final.payoutCredited, undefined);
});

test('a close reorganized away drops its payout reading', async () => {
    const { chain, client, record } = await scenario({ records: [escapeRecord({
        phase: 'closed_unconfirmed', chainStatus: 'closed', payoutVerified: true, closeBlockNumber: CLOSE_BLOCK,
        lastObservedBlock: CLOSE_BLOCK })] });
    chain.noteStatus.set(NOTE_ID, 2);
    await client.syncEscapeWithdrawals(() => {});
    let saved = await record();
    assert.equal(saved.chainStatus, 'pending_withdrawal');
    assert.equal(saved.phase, 'pending');
    assert.equal(saved.payoutVerified, false);

    // Closed again by a finalization this browser has no receipt for, while
    // the vault holds a credit for the destination.
    chain.noteStatus.set(NOTE_ID, 3);
    chain.credits.set(DESTINATION, FINAL_BALANCE);
    await client.syncEscapeWithdrawals(() => {});
    saved = await record();
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.payoutCreditEvidence, 'vault_credit');
});

test('finalizing an escape whose destination rejects the payout reports a credit, not a return', async () => {
    const { chain, client, record } = await scenario();
    chain.noteStatus.set(NOTE_ID, 3);
    chain.receipts.set(FINALIZE_HASH, finalizeReceipt({ credited: true }));
    client.sendContractTransaction = async (from, to, data, onSubmitted) => {
        assert.equal(from, FROM);
        assert.equal(to, VAULT);
        assert.equal(data, globalThis.zkapiWallet.encodeFinalizeEscape(NOTE_ID));
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ credited: true });
    };
    client.submittedTransactionMetadata = async () => null;
    const statuses = [];
    const result = await client.finalizeEscape(recordIdOf(NOTE_ID), message => statuses.push(message));
    assert.equal(result.status, 'closed');
    assert.equal(result.payoutCredited, true);
    assert.equal(result.event.payoutCredited, true);
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.creditedAmount, FINAL_BALANCE);
    assert.match(statuses.at(-1), CREDITED_MESSAGE);
    assert.ok(!statuses.some(message => /returned/i.test(message)));

    // The same flow with a paid receipt still reports the return.
    const paid = await scenario();
    paid.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        return finalizeReceipt({ credited: false });
    };
    paid.client.submittedTransactionMetadata = async () => null;
    const paidStatuses = [];
    const paidResult = await paid.client.finalizeEscape(recordIdOf(NOTE_ID), message => paidStatuses.push(message));
    assert.equal(paidResult.payoutCredited, undefined);
    assert.equal((await paid.record()).payoutVerified, true);
    assert.equal((await paid.record()).payoutCredited, undefined);
    assert.match(paidStatuses.at(-1), /Escape withdrawal returned/);

    // A background pass that saw the close before the receipt arrived read
    // another escape's credit; the paid receipt replaces that reading.
    const raced = await scenario();
    raced.client.sendContractTransaction = async (_from, _to, _data, onSubmitted) => {
        await onSubmitted(FINALIZE_HASH);
        raced.chain.credits.set(DESTINATION, 123);
        await raced.client.syncEscapeWithdrawals(() => {});
        assert.equal((await raced.record()).payoutCreditEvidence, 'vault_credit');
        return finalizeReceipt({ credited: false });
    };
    raced.client.submittedTransactionMetadata = async () => null;
    await raced.client.finalizeEscape(recordIdOf(NOTE_ID), () => {});
    const racedRecord = await raced.record();
    assert.equal(racedRecord.payoutVerified, true);
    assert.equal(racedRecord.payoutCredited, false);
    assert.deepEqual(raced.client.creditedEscapePayouts, []);
});

test('a credited escape closes the note for expiry history', async () => {
    const deposit = { recordId: 'deposit-7', deploymentId: DEPLOYMENT_ID, noteId: NOTE_ID, status: 'confirmed',
        amount: 1_000_000, expiryTs: 1_000 };
    const closed = { deploymentId: DEPLOYMENT_ID, noteId: NOTE_ID, mode: 'escape', phase: 'closed', payoutVerified: false };
    assert.equal(deriveExpiryRecords([deposit], [closed], 2_000_000).length, 1, 'an unproven close keeps the expiry row');
    assert.deepEqual(deriveExpiryRecords([deposit], [{ ...closed, payoutCredited: true }], 2_000_000), []);
});

async function creditedScenario(extraRecords = []) {
    const credited = escapeRecord({ phase: 'closed', chainStatus: 'closed', payoutCredited: true,
        payoutVerified: false, creditedAmount: FINAL_BALANCE, payoutCreditEvidence: 'receipt',
        closeBlockNumber: CLOSE_BLOCK });
    const setup = await scenario({ records: [credited, ...extraRecords] });
    setup.chain.credits.set(DESTINATION, FINAL_BALANCE);
    return setup;
}

test('the claim action reads the credit, sends claimEscapePayout and proves delivery by its log', async () => {
    const sameDestination = escapeRecord({ noteId: 8, phase: 'closed_unconfirmed', chainStatus: 'closed',
        payoutCredited: true, payoutVerified: false, creditedAmount: 300_000, closeBlockNumber: CLOSE_BLOCK });
    const otherDestination = escapeRecord({ noteId: 9, destination: OTHER_DESTINATION, phase: 'closed',
        chainStatus: 'closed', payoutCredited: true, payoutVerified: false, creditedAmount: 1 });
    const { chain, client, record } = await creditedScenario([sameDestination, otherDestination]);
    chain.credits.set(DESTINATION, FINAL_BALANCE + 300_000);
    const statuses = [];
    const result = await client.claimEscapePayout(recordIdOf(NOTE_ID), message => statuses.push(message));
    assert.equal(result.status, 'claimed');
    assert.equal(result.transactionHash, CLAIM_HASH);
    assert.equal(result.amount, 1_000_000n);

    const creditRead = chain.calls.find(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits));
    assert.equal(creditRead.params[0].data, `${SELECTOR.credits}${word(DESTINATION)}`);
    assert.equal(chain.sent.length, 1);
    assert.equal(chain.sent[0].from, FROM);
    assert.equal(chain.sent[0].to, VAULT);
    assert.equal(chain.sent[0].data, `${SELECTOR.claim}${word(DESTINATION)}`);
    assert.equal(chain.sent[0].value, undefined, 'a claim sends no ETH');

    for (const noteId of [NOTE_ID, 8]) {
        const saved = await record(noteId);
        assert.equal(saved.payoutCredited, true);
        assert.equal(saved.payoutClaimed, true);
        assert.equal(saved.payoutVerified, true, 'the EscapePayoutClaimed log proves the payment');
        assert.equal(saved.payoutClaimEvidence, 'claim_receipt');
        assert.equal(saved.payoutClaimTransactionHash, CLAIM_HASH);
        assert.equal(saved.payoutClaimedAmount, 1_000_000);
        assert.deepEqual(saved.payoutClaimTransactionHashes, []);
    }
    const untouched = await record(9);
    assert.equal(untouched.payoutClaimed, undefined);
    assert.equal(untouched.payoutVerified, false);
    assert.match(statuses.at(-1), /delivered/);
    assert.deepEqual(client.creditedEscapePayouts.map(entry => entry.noteId), [9]);

    // Later sync and finality passes keep the claim's verification.
    chain.finalized = CLOSE_BLOCK + 10;
    await client.syncEscapeWithdrawals(() => {});
    const finalized = await record(8);
    assert.equal(finalized.phase, 'closed');
    assert.equal(finalized.payoutVerified, true);
    assert.equal(finalized.payoutClaimed, true);

    // A delivered payout is not claimed again.
    assert.equal((await client.claimEscapePayout(recordIdOf(NOTE_ID))).status, 'claimed');
    assert.equal(chain.sent.length, 1);
});

test('a claim receipt without a log for this destination is not proof of payment', async () => {
    const { chain, client, record } = await creditedScenario();
    chain.claimReceipt = claimReceipt({ destination: OTHER_DESTINATION });
    await assert.rejects(client.claimEscapePayout(recordIdOf(NOTE_ID)), /did not pay this destination/);
    const saved = await record();
    assert.equal(saved.payoutClaimed, undefined);
    assert.equal(saved.payoutVerified, false);
    assert.deepEqual(saved.payoutClaimTransactionHashes, [CLAIM_HASH], 'the sent hash stays recorded');
});

test('a destination that still rejects ETH keeps its credit without a wallet prompt', async () => {
    const { chain, client, record } = await creditedScenario();
    chain.claimRevert = SELECTOR.nativeTransferFailed;
    await assert.rejects(client.claimEscapePayout(recordIdOf(NOTE_ID)), error =>
        error.code === 'native_transfer_failed' && /still does not accept ETH/.test(error.shortMessage));
    assert.equal(chain.sent.length, 0);
    const saved = await record();
    assert.equal(saved.payoutCredited, true);
    assert.equal(saved.payoutClaimed, undefined);
    assert.equal(saved.payoutVerified, false);
});

test('a credit someone else already delivered is recognised from the vault state', async () => {
    const { chain, client, record } = await creditedScenario();
    chain.credits.set(DESTINATION, 0);
    const result = await client.claimEscapePayout(recordIdOf(NOTE_ID));
    assert.equal(result.status, 'claimed');
    assert.equal(chain.sent.length, 0);
    assert.ok(!chain.calls.some(call => call.method === 'eth_estimateGas'));
    const saved = await record();
    assert.equal(saved.payoutClaimed, true);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.payoutClaimEvidence, 'credit_cleared');
    assert.equal(saved.payoutClaimBlockNumber, chain.head);
    const noteRead = chain.calls.find(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.notes));
    assert.equal(noteRead.params[1], hex(chain.head), 'the note is read at the block of the zero credit');

    // A zero credit proves nothing while the note does not read Closed there.
    const lagging = await creditedScenario();
    lagging.chain.credits.set(DESTINATION, 0);
    lagging.chain.noteStatus.set(NOTE_ID, 2);
    await assert.rejects(lagging.client.claimEscapePayout(recordIdOf(NOTE_ID)), /not show this escape as closed/);
    assert.equal((await lagging.record()).payoutClaimed, undefined);

    // A claim that loses the race to another claimer (ZeroAmount at estimate).
    const raced = await creditedScenario();
    raced.chain.claimRevert = SELECTOR.zeroAmount;
    const originalRequest = raced.chain.provider.request;
    raced.chain.provider.request = async args => {
        if (args.method === 'eth_estimateGas') raced.chain.credits.set(DESTINATION, 0);
        return originalRequest(args);
    };
    assert.equal((await raced.client.claimEscapePayout(recordIdOf(NOTE_ID))).status, 'claimed');
    assert.equal((await raced.record()).payoutClaimEvidence, 'credit_cleared');
    assert.equal(raced.chain.sent.length, 0);
});

test('a pending or externally signed claim is resumed instead of sent twice', async () => {
    const { chain, client, record } = await creditedScenario();
    const saved = await record();
    await runtime.updateWithdrawal(saved.recordId, { payoutClaimTransactionHashes: [CLAIM_HASH] });
    await client.refresh();
    chain.transactions.set(CLAIM_HASH, { hash: CLAIM_HASH });
    const pending = await client.claimEscapePayout(recordIdOf(NOTE_ID));
    assert.equal(pending.status, 'pending');
    assert.equal(chain.sent.length, 0);

    chain.receipts.set(CLAIM_HASH, claimReceipt());
    chain.credits.set(DESTINATION, 0);
    const claimed = await client.claimEscapePayout(recordIdOf(NOTE_ID));
    assert.equal(claimed.status, 'claimed');
    assert.equal((await record()).payoutClaimEvidence, 'claim_receipt');
    assert.equal(chain.sent.length, 0);

    // A manual signer resumes its saved claim through the public recovery API.
    const manual = await creditedScenario();
    const transaction = { from: FROM, to: VAULT, data: `${SELECTOR.claim}${word(DESTINATION)}`, nonce: '0x3' };
    manual.chain.transactions.set(CLAIM_HASH, { ...transaction, hash: CLAIM_HASH, input: transaction.data, value: '0x0' });
    const acknowledged = [];
    manual.chain.provider.acknowledgeTransaction = async hash => { acknowledged.push(hash); };
    const context = {
        version: 1, kind: 'escape-payout-claim', deploymentId: DEPLOYMENT_ID, chainId: CHAIN_ID,
        contractAddress: VAULT, recordId: recordIdOf(NOTE_ID), noteId: NOTE_ID, destination: DESTINATION
    };
    const resumed = await manual.client.resumeExternalTransaction({ transaction, hash: CLAIM_HASH, context });
    assert.equal(resumed.kind, 'escape-payout-claim');
    assert.deepEqual(acknowledged, [CLAIM_HASH]);
    assert.deepEqual((await manual.record()).payoutClaimTransactionHashes, [CLAIM_HASH]);
    await assert.rejects(manual.client.resumeExternalTransaction({
        transaction: { ...transaction, data: `${SELECTOR.claim}${word(OTHER_DESTINATION)}` },
        hash: CLAIM_HASH,
        context: { ...context, destination: OTHER_DESTINATION }
    }), /no longer matches its saved escape payout claim|does not match/);
});

function siblingCredit(overrides = {}) {
    return escapeRecord({ noteId: 8, phase: 'closed_unconfirmed', chainStatus: 'closed', payoutCredited: true,
        payoutVerified: false, creditedAmount: 300_000, payoutCreditEvidence: 'receipt',
        closeBlockNumber: CLOSE_BLOCK, ...overrides });
}

test('a stored claim settles only the records of its destination credited before its block', async () => {
    // Note 8 escaped to the same destination and was credited at block
    // CLOSE_BLOCK + 30, after the claim stored on note 7 was mined (+20).
    const { chain, client, record } = await creditedScenario([siblingCredit({ closeBlockNumber: CLOSE_BLOCK + 30 })]);
    await runtime.updateWithdrawal(recordIdOf(NOTE_ID), { payoutClaimTransactionHashes: [CLAIM_HASH] });
    await client.refresh();
    chain.receipts.set(CLAIM_HASH, claimReceipt({ blockNumber: CLOSE_BLOCK + 20 }));
    chain.credits.set(DESTINATION, 300_000);
    chain.head = CLOSE_BLOCK + 40;

    const result = await client.claimEscapePayout(recordIdOf(NOTE_ID));
    assert.equal(result.status, 'claimed');
    assert.equal(result.transactionHash, CLAIM_HASH);
    assert.equal(chain.sent.length, 0);
    const paid = await record();
    assert.equal(paid.payoutClaimed, true);
    assert.equal(paid.payoutVerified, true);
    const held = await record(8);
    assert.equal(held.payoutCredited, true);
    assert.equal(held.payoutClaimed, undefined);
    assert.equal(held.payoutVerified, false, 'the vault still holds the later credit');
    assert.deepEqual(client.creditedEscapePayouts.map(entry => entry.noteId), [8]);

    // Later sync passes keep it credited, and its own claim delivers it.
    await client.syncEscapeWithdrawals(() => {});
    assert.equal((await record(8)).payoutVerified, false);
    chain.nextClaimHash = `0x${'c2'.repeat(32)}`;
    const second = await client.claimEscapePayout(recordIdOf(8));
    assert.equal(second.status, 'claimed');
    assert.equal(second.transactionHash, chain.nextClaimHash);
    assert.equal(second.amount, 300_000n);
    assert.equal(chain.sent.length, 1);
    const delivered = await record(8);
    assert.equal(delivered.payoutClaimed, true);
    assert.equal(delivered.payoutClaimTransactionHash, chain.nextClaimHash);
    assert.equal((await record()).payoutClaimTransactionHash, CLAIM_HASH, 'the earlier proof is unchanged');
    assert.deepEqual(client.creditedEscapePayouts, []);
});

test('a record without a close block is settled by the zero credit at its claim block', async () => {
    const { chain, client, record } = await creditedScenario();
    await runtime.updateWithdrawal(recordIdOf(NOTE_ID), { closeBlockNumber: 0 });
    await client.refresh();
    const result = await client.claimEscapePayout(recordIdOf(NOTE_ID));
    assert.equal(result.status, 'claimed');
    assert.equal(chain.sent.length, 1);
    assert.equal((await record()).payoutClaimEvidence, 'credit_cleared');
    const creditReads = chain.calls.filter(call => call.method === 'eth_call'
        && call.params[0].data.startsWith(SELECTOR.credits));
    assert.equal(creditReads.at(-1).params[1], hex(chain.head + 1), 'read at the claim block');
});

test('a claim pending for the destination is not sent again from another of its records', async () => {
    const { chain, client, record } = await creditedScenario([siblingCredit()]);
    chain.credits.set(DESTINATION, FINAL_BALANCE + 300_000);
    await runtime.updateWithdrawal(recordIdOf(NOTE_ID), { payoutClaimTransactionHashes: [CLAIM_HASH] });
    await client.refresh();
    chain.transactions.set(CLAIM_HASH, { hash: CLAIM_HASH });
    for (const noteId of [NOTE_ID, 8]) {
        const pending = await client.claimEscapePayout(recordIdOf(noteId));
        assert.equal(pending.status, 'pending', `note ${noteId}`);
        assert.equal(pending.transactionHash, CLAIM_HASH);
    }
    assert.equal(chain.sent.length, 0);
    assert.ok(!chain.calls.some(call => call.method === 'eth_estimateGas'));

    // Once mined, that claim proves both credits, which precede its block.
    chain.receipts.set(CLAIM_HASH, claimReceipt({ amount: FINAL_BALANCE + 300_000 }));
    chain.credits.set(DESTINATION, 0);
    const claimed = await client.claimEscapePayout(recordIdOf(8));
    assert.equal(claimed.status, 'claimed');
    assert.equal(claimed.transactionHash, CLAIM_HASH);
    for (const noteId of [NOTE_ID, 8]) {
        const saved = await record(noteId);
        assert.equal(saved.payoutClaimEvidence, 'claim_receipt', `note ${noteId}`);
        assert.deepEqual(saved.payoutClaimTransactionHashes, []);
    }
    assert.equal(chain.sent.length, 0);
});

test('the claim action refuses a withdrawal the vault did not credit', async () => {
    const { client } = await scenario({ records: [escapeRecord({ phase: 'closed', chainStatus: 'closed',
        payoutVerified: true })] });
    await assert.rejects(client.claimEscapePayout(recordIdOf(NOTE_ID)), /holds no escape payout/);
});

test('the escape destination check simulates the vault push with the payout gas', async () => {
    const calls = [];
    let outcome = null;
    globalThis.ethereum = {
        async request({ method, params }) {
            calls.push({ method, params });
            if (method === 'eth_chainId') return hex(CHAIN_ID);
            if (method === 'eth_call') {
                if (outcome) throw outcome;
                return '0x';
            }
            throw new Error(`unexpected RPC ${method}`);
        }
    };
    const client = new ZkapiClient();
    client.config = { funding: { chain_id: CHAIN_ID, contract_address: VAULT } };
    runtime.browserConfig = { trusted_deployment: { vault_revision: 2 } };

    assert.deepEqual(await client.checkEscapeDestination(DESTINATION),
        { destination: DESTINATION, accepts: true, warning: null });
    const [call] = calls.filter(entry => entry.method === 'eth_call');
    assert.deepEqual(call.params, [{
        from: VAULT,
        to: DESTINATION,
        value: hex(1_000_000_000n),
        gas: hex(21_000 + 100_000 + 2_300)
    }, 'latest']);

    // MetaMask wraps the node's revert inside an internal JSON-RPC error.
    outcome = { code: -32603, message: 'Internal JSON-RPC error.', data: { code: 3, message: 'execution reverted' } };
    const rejected = await client.checkEscapeDestination(DESTINATION);
    assert.equal(rejected.accepts, false);
    assert.match(rejected.warning, /100,000-gas payout limit/);
    outcome = { code: -32000, message: 'out of gas' };
    assert.equal((await client.checkEscapeDestination(DESTINATION)).accepts, false);
    // Anvil (1.5) reports halts as "EVM error <HaltReason>" with -32603, as
    // observed for a destination that loops, jumps badly or hits 0xfe.
    for (const reason of ['OutOfGas', 'InvalidJump', 'InvalidFEOpcode', 'StackUnderflow', 'OpcodeNotFound']) {
        outcome = { code: -32603, message: `EVM error ${reason}` };
        assert.equal((await client.checkEscapeDestination(DESTINATION)).accepts, false, reason);
        // The same message wrapped by MetaMask's internal-error envelope.
        outcome = { code: -32603, message: 'Internal JSON-RPC error.', data: { code: -32603, message: `EVM error ${reason}` } };
        assert.equal((await client.checkEscapeDestination(DESTINATION)).accepts, false, `wrapped ${reason}`);
    }
    // An RPC or account failure is not a verdict.
    for (const message of ['header not found', 'Insufficient funds for gas * price + value']) {
        outcome = { code: message.startsWith('Insufficient') ? -32003 : -32000, message };
        assert.deepEqual(await client.checkEscapeDestination(DESTINATION),
            { destination: DESTINATION, accepts: null, warning: null }, message);
    }
    // A zero balance is never pushed.
    calls.length = 0;
    assert.equal((await client.checkEscapeDestination(DESTINATION, { finalBalance: 0 })).accepts, true);
    assert.ok(!calls.some(entry => entry.method === 'eth_call'));

    await assert.rejects(client.checkEscapeDestination(VAULT), /vault contract/);
});

test('an escape warns about its destination before proving, and a mutual close does not check it', async t => {
    for (const mode of ['escape', 'mutual']) {
        const order = [];
        const statuses = [];
        globalThis.ethereum = {
            async request({ method, params }) {
                if (method === 'eth_chainId') return hex(CHAIN_ID);
                if (method === 'eth_call') {
                    order.push(`eth_call:${params[0].to}`);
                    throw { code: 3, message: 'execution reverted' };
                }
                throw new Error(`unexpected RPC ${method}`);
            }
        };
        runtime.browserConfig = { trusted_deployment: { vault_revision: 2 } };
        const client = new ZkapiClient();
        client.config = { funding: { chain_id: CHAIN_ID, contract_address: VAULT } };
        client.wallet = { has_note: true, note: { note_id: NOTE_ID, current_balance: 5_000_000 } };
        for (const name of ['assertBalanceNotClaimed', 'settleActiveLease', 'refresh', 'rememberWithdrawal']) {
            t.mock.method(client, name, async () => {});
        }
        t.mock.method(client, 'connectWallet', async () => FROM);
        t.mock.method(client, 'readContractUint', async () => 1n);
        t.mock.method(client, 'recoverFailedWithdrawalSubmission', async () => null);
        t.mock.method(runtime, 'currentPreparedWithdrawal', async () => null);
        t.mock.method(runtime, 'prepareWithdrawal', async () => {
            order.push('prove');
            throw new Error('stop after proving');
        });
        await assert.rejects(client.performWithdrawal(mode, message => statuses.push(message),
            { destination: DESTINATION }), /stop after proving/);
        if (mode === 'escape') {
            assert.deepEqual(order, [`eth_call:${DESTINATION}`, 'prove']);
            const warning = statuses.findIndex(message => /100,000-gas payout limit/.test(message));
            assert.ok(warning >= 0 && warning < statuses.findIndex(message => /Preparing a unilateral escape/.test(message)));
        } else {
            assert.deepEqual(order, ['prove']);
        }
        t.mock.restoreAll();
    }
});
