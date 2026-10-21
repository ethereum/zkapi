// The client's sponsored (gasless) withdrawal path (design §3.2) over the
// real runtime and store, in the style of browser-wallet-exit-submission:
// the wallet is an EIP-1193 fake that signs with personal_sign and refuses
// eth_sendTransaction, the read RPC a scripted chain holding the vault, the
// EntryPoint, the paymaster and its factory, and the bundler a scripted
// JSON-RPC server over fetch that asserts the exact v0.7 shape of every
// operation and hashes it independently (sdk/test/helpers/fake-bundler.mjs).
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, VAULT, createHarness, depositPath, memoryIndexedDb, noteState, nullifierFor, within
} from './helpers/request-archive-harness.mjs';
import { deployedProfile } from './helpers/deployed-profile.mjs';
import {
    BUNDLER_URL, VECTORS, attemptsKeyOf, decodeHandleOps, failedOpData, fakeBundler, fakeGaslessChain, fakeWallet,
    gaslessProfileFromVectors, hashPacked, logs, revertError, userOperationHashFromJson, word
} from './helpers/fake-bundler.mjs';
import { addressOf, recover } from './helpers/secp256k1.mjs';

const storage = new Map();
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { FORWARD_NONCE_KEY, KIND, eip191Digest, unpackNonce } = await import('../services/zkapiGasless.mjs');
const { GASLESS_ABI, encodeClaimCredit, encodeCreateAccount, encodeFinalizeEscape, encodeSweep, encodeTransitWithdraw, encodeWithdrawal } = globalThis.zkapiWallet;

const CHAIN_ID = 11155111;
const OWNER_KEY = 0xa11ce0n;
const OWNER = addressOf(OWNER_KEY);
const OTHER = addressOf(0xb0bn);
const PAYEE = `0x${'9a'.repeat(20)}`;
const NOTE_ID = 7;
const ETH = 10n ** 18n;
const GWEI = 10n ** 9n;
const low = value => String(value).toLowerCase();
const wei = units => BigInt(units) * GWEI;

/**
 * The shared runtime under the harness with a gasless profile, a scripted
 * chain (the exit RPC and the pinned RPC), a scripted bundler over fetch and a
 * fake wallet that only signs.
 */
async function scenario({ state = noteState({ current_balance: 500_000_000, deposit_path: depositPath('0x51') }), profile = {},
    gasless = gaslessProfileFromVectors({ spelling: 'profile', ...profile }), from = OWNER, allow = [] } = {}) {
    indexedDB.clear();
    storage.clear();
    for (const name of ['exitRpc', 'pinnedRpc']) delete runtime[name];
    runtime.activeLease = null;
    runtime.exitGasPrice = null;
    runtime.gaslessStatus = null;
    runtime.bundlerChainCheck = null;
    runtime.exitRpcChainCheck = null;
    const h = createHarness(function SharedRuntime() { return runtime; });
    h.worker.mutate = plan => { plan.proof.proof = Buffer.alloc(256, h.worker.proofs).toString('base64'); };
    h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
    runtime.browserConfig.trusted_deployment = {
        ...deployedProfile('sepolia').trusted_deployment, contract_address: VAULT, chain_id: CHAIN_ID, native_asset_wei_per_unit: '1000000000',
        max_pause_duration: 604_800, vault_revision: 3, gasless
    };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await runtime.reload();
    const chain = gasless ? fakeGaslessChain({ chainId: CHAIN_ID, vault: VAULT, gasless, noteId: state.note_id, finalBalance: state.current_balance })
        : { request: async ({ method }) => { throw new Error(`no chain for ${method}`); }, calls: [] };
    runtime.exitRpc = () => chain.request;
    runtime.pinnedRpc = () => chain.request;
    const bundler = gasless ? fakeBundler({ chain }) : null;
    globalThis.fetch = bundler ? bundler.fetch : async () => { throw new Error('no fetch'); };
    const wallet = fakeWallet({ owner: from, privateKey: from === OWNER ? OWNER_KEY : 0xb0bn, chainId: CHAIN_ID, chain, allow });
    globalThis.ethereum = wallet;
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    client.wallet = { has_note: true, note: { note_id: state.note_id, current_balance: state.current_balance } };
    for (const name of ['assertBalanceNotClaimed', 'settleActiveLease']) client[name] = async () => {};
    client.refresh = async () => {
        await runtime.reload();
        const snapshot = runtime.snapshot();
        client.wallet = await runtime.walletStatus();
        client.withdrawals = snapshot.withdrawals;
        client.config = { ...runtime.config, ...snapshot.config };
        return client.snapshot();
    };
    client.connectWallet = async () => wallet.owner;
    client.walletAddress = wallet.owner;
    client.checkEscapeDestination = async destination => ({ destination, accepts: true, warning: null });
    client.recoverFailedWithdrawalSubmission = async () => null;
    client.submittedTransactionMetadata = async () => null;
    client.gaslessTimingOverrides = { receiptPollMs: 3, logPollMs: 6, resendAfterMs: 40, stopBeforeValidUntilSeconds: 60 };
    const statuses = [];
    const amounts = [];
    const onStatus = (message, extra) => { statuses.push(message); if (extra?.amounts) amounts.push(extra.amounts); };
    const withdraw = (mode, options = {}) => client.performWithdrawal(mode, onStatus, { destination: PAYEE, fees: 'payout', ...options });
    const S = gasless ? chain.transitAccount(OWNER, PAYEE) : null;
    const nullifier = nullifierFor(state.current_anchor);
    const closeKey = attemptsKeyOf(1, { nullifier });
    const record = async () => (await store.listBrowserWithdrawals(DEPLOYMENT)).find(entry => entry.noteId === state.note_id);
    const prepared = async () => (await store.readBrowserWallet()).preparedWithdrawal || null;
    /** The bundle a successful close settles with: a foreign note's close first (the noteId filter), then this note's, then Settled. */
    const closeBundle = ({ charged = wei(5_000_000), credited = false, received = wei(state.current_balance) } = {}) => (op, hash) => ({
        success: true,
        extraLogs: [
            logs.mutualClose(VAULT, { noteId: 99n, finalBalance: 1n, destination: `0x${'44'.repeat(20)}` }),
            logs.mutualClose(VAULT, { noteId: BigInt(state.note_id), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S }),
            logs.settled(chain.paymaster, { key: closeKey, sender: S, payee: PAYEE, kind: 1n, noteId: BigInt(state.note_id), received,
                charged, owedPaid: 0n, paidOut: credited ? 0n : received - charged }),
            ...(credited ? [logs.payoutCredited(chain.paymaster, PAYEE, received - charged)] : [])
        ],
        effects: chainState => {
            chainState.noteStatus(state.note_id, 3);
            chainState.paymasterState.attempts.set(closeKey, (chainState.paymasterState.attempts.get(closeKey) ?? 0n) + 1n);
            if (credited) chainState.paymasterState.credits.set(low(PAYEE), received - charged);
        }
    });
    return { h, chain, bundler, wallet, client, statuses, amounts, withdraw, S, nullifier, closeKey, record, prepared, closeBundle, state };
}

const proofs = (h, mode) => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === mode);
const dryRuns = chain => chain.calls.filter(call => call.method === 'eth_call' && low(call.params[0].to) === chain.entryPoint
    && call.params[0].data.startsWith(`0x${GASLESS_ABI.handleOps}`));

test('a sponsored close creates the transit account, signs the hash once, journals before the send and settles from the bundle', async () => {
    const { h, chain, bundler, wallet, client, statuses, amounts, withdraw, S, nullifier, record, prepared, closeBundle } = await scenario();
    let journalAtSend = null;
    bundler.onSend = async () => { journalAtSend = await prepared(); };
    bundler.autoMine = closeBundle();
    const result = await within(5_000, withdraw('mutual'), 'a sponsored close');
    assert.equal(result.status, 'closed');
    assert.equal(result.transitAccount, S);
    assert.equal(result.payout, PAYEE);
    assert.equal(result.amounts.chargedWei, wei(5_000_000).toString());
    assert.equal(result.amounts.paidOutWei, (wei(500_000_000) - wei(5_000_000)).toString());
    // No transaction left the wallet; one signature of the exact hash the bundler received.
    assert.deepEqual(wallet.sent, []);
    assert.deepEqual(wallet.calls.map(call => call.method), ['personal_sign'], 'the wallet only signs: every read went to the read RPC');
    assert.equal(wallet.signatures.length, 1);
    assert.equal(bundler.sent.length, 1);
    const { op, hash } = bundler.sent[0];
    assert.equal(wallet.signatures[0].message, hash);
    assert.equal(wallet.signatures[0].digest, eip191Digest(hash));
    assert.equal(recover(wallet.signatures[0].digest, op.signature), OWNER, 'the signature recovers the owner of S');
    assert.equal(result.userOpHash, hash);
    // The exact bytes: sender S, nonce key = the withdrawal nullifier, the factory initCode, the 836-byte vault call inside withdraw(bytes).
    assert.equal(op.sender, S);
    assert.equal(unpackNonce(op.nonce).key, BigInt(nullifier) & ((1n << 192n) - 1n));
    assert.equal(unpackNonce(op.nonce).sequence, 0n);
    assert.equal(op.factory, low(VECTORS.factory));
    assert.equal(op.factoryData, encodeCreateAccount(OWNER, PAYEE));
    const plan = (await record()).preparedWithdrawal;
    assert.equal(op.callData, encodeTransitWithdraw(encodeWithdrawal(plan, 'mutual', S, VAULT, { conceded: plan.public_inputs.conceded })));
    assert.equal(op.paymaster, low(VECTORS.paymaster));
    assert.equal(op.paymasterData, `0x${BigInt(VECTORS.policy.flat_fee_wei).toString(16).padStart(24, '0')}`, 'feeCapWei = the flat fee shown');
    assert.equal(BigInt(op.maxFeePerGas), 2n * chain.baseFee + chain.priorityFee);
    assert.equal(BigInt(op.maxPriorityFeePerGas), chain.priorityFee);
    assert.equal(BigInt(op.callGasLimit), 642_500n, 'the profile default, not the bundler estimate');
    assert.equal(BigInt(op.verificationGasLimit), 180_000n, 'verification_default_init');
    assert.equal(BigInt(op.paymasterPostOpGasLimit), 270_000n);
    assert.equal(BigInt(op.paymasterVerificationGasLimit), 430_000n);
    // Journaled before eth_sendUserOperation, with the signature; two dry runs (unsigned, then signed) and the EntryPoint hash cross-check.
    assert.equal(journalAtSend.userOpPhase, 'op_built');
    assert.deepEqual(journalAtSend.userOp, op);
    assert.equal(journalAtSend.userOpHash, hash);
    assert.equal(journalAtSend.feePayer, 'payout');
    assert.equal(journalAtSend.payout, PAYEE);
    assert.equal(journalAtSend.transit.account, S);
    assert.equal(journalAtSend.transit.owner, OWNER);
    assert.equal(journalAtSend.destination, S, 'the plan is bound to S');
    assert.equal(journalAtSend.userOpInitCode, true);
    assert.equal(dryRuns(chain).length, 2);
    assert.ok(chain.calls.some(call => call.method === 'eth_call' && call.params[0].data.startsWith(`0x${GASLESS_ABI.getUserOpHash}`)));
    // The record carries the transit identity and the settlement amounts.
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.feePayer, 'payout');
    assert.equal(saved.destination, S);
    assert.equal(saved.payout, PAYEE);
    assert.equal(saved.transit.account, S);
    assert.equal(saved.userOpHash, hash);
    assert.deepEqual(saved.userOpHashes, [hash]);
    assert.equal(saved.userOpSuccess, true);
    assert.equal(saved.chargedWei, wei(5_000_000).toString());
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(saved.transactionHash, result.transactionHash);
    assert.equal(await prepared(), null);
    assert.equal(proofs(h, 'mutual').length, 1);
    // Status text: the privacy sentence, the minimum received before signing, the settlement after.
    assert.ok(statuses.some(message => /becomes the on-chain owner/.test(message) && /fresh (owner )?account/.test(message)
        && /bundler .* sees the operation, with its note, transit account and payout address, together with this browser’s IP address/.test(message)));
    assert.ok(statuses.some(message => /receives at least 0\.4\d+ ETH/.test(message)), statuses.join('\n'));
    assert.ok(statuses.some(message => /settled: charged 0\.005 ETH, 0\.495 ETH paid out/.test(message)), statuses.join('\n'));
    assert.equal(amounts[0].minimumReceived, (wei(500_000_000) - BigInt(amounts[0].maxCost) - BigInt(VECTORS.policy.flat_fee_wei)).toString());
    assert.equal(amounts.at(-1).paidOutWei, result.amounts.paidOutWei);
    // The snapshot's gasless object and the client's view.
    const snapshot = runtime.snapshot().config.gasless;
    assert.equal(snapshot.supported, true);
    assert.equal(snapshot.bundler_url, BUNDLER_URL);
    assert.equal(snapshot.bundler_wrong_chain, false);
    assert.equal(snapshot.paymaster_deposit_wei, chain.paymasterState.deposit.toString());
    assert.equal(snapshot.policy.flat_fee_wei, VECTORS.policy.flat_fee_wei);
    assert.equal(snapshot.attempts_left, 3);
    assert.equal(client.wallet.has_note, false);
});

test('a close from an existing transit account carries no initCode; AA10 and AA25 in the dry run are rebuilt silently', async () => {
    const existing = await scenario();
    existing.chain.setCode(existing.S, '0x3660');
    existing.bundler.autoMine = existing.closeBundle();
    await within(5_000, existing.withdraw('mutual'), 'close from an existing S');
    assert.equal('factory' in existing.bundler.sent[0].op, false);
    assert.equal(BigInt(existing.bundler.sent[0].op.verificationGasLimit), 70_000n, 'verification_default without initCode');
    assert.equal((await existing.record()).phase, 'closed_unconfirmed');

    // AA10: the account exists after all (created by someone else between the read and the dry run).
    const created = await scenario();
    created.chain.dryRun = op => (op.initCode.length ? revertError(failedOpData('AA10 sender already constructed')) : null);
    created.bundler.autoMine = created.closeBundle();
    await within(5_000, created.withdraw('mutual'), 'AA10 rebuild');
    assert.equal('factory' in created.bundler.sent[0].op, false, 'rebuilt without initCode');
    assert.equal(created.wallet.signatures.length, 1, 'signed once, after the rebuild');
    assert.ok(!created.statuses.some(message => /AA10/.test(message)), 'silent');

    // AA25: the nonce moved; it is read again.
    const moved = await scenario();
    let refused = false;
    moved.chain.dryRun = () => {
        if (refused) return null;
        refused = true;
        moved.chain.setNonce(moved.S, BigInt(moved.nullifier), 1n);
        return revertError(failedOpData('AA25 invalid account nonce'));
    };
    moved.bundler.autoMine = moved.closeBundle();
    await within(5_000, moved.withdraw('mutual'), 'AA25 rebuild');
    assert.equal(unpackNonce(moved.bundler.sent[0].op.nonce).sequence, 1n);
    assert.equal(moved.wallet.signatures.length, 1);
});

test('the write-ahead record survives a reload: identical bytes are re-sent at op_built, polling resumes at op_submitted, never a second signature', async () => {
    // op_built: the bundler was unreachable after the journal was written.
    const { h, bundler, wallet, withdraw, prepared, record, closeBundle } = await scenario();
    bundler.unreachableMethods.add('eth_sendUserOperation');
    await assert.rejects(withdraw('mutual'), error => error.code === 'bundler_unavailable'
        && error.data.fallbacks.includes('self_bundle') && error.data.fallbacks.includes('direct_call'));
    let journal = await prepared();
    assert.equal(journal.userOpPhase, 'op_built');
    assert.equal(journal.phase, 'prepared', 'the claim is released: nothing left the browser');
    assert.equal(journal.submissionId, undefined);
    assert.ok(journal.userOp.signature.length === 132);
    const firstHash = journal.userOpHash;
    assert.equal(wallet.signatures.length, 1);
    // "Reload": the same durable plan, the bundler is back.
    bundler.unreachableMethods.clear();
    bundler.autoMine = closeBundle();
    const result = await within(5_000, withdraw('mutual'), 'resume at op_built');
    assert.equal(result.status, 'closed');
    assert.equal(wallet.signatures.length, 1, 'no second prompt');
    assert.equal(bundler.sent.length, 1);
    assert.equal(bundler.sent[0].hash, firstHash);
    assert.deepEqual(bundler.sent[0].op, journal.userOp, 'the identical bytes');
    assert.equal(proofs(h, 'mutual').length, 1, 'no re-proof');
    assert.deepEqual((await record()).userOpHashes, [firstHash]);

    // op_submitted: the client gave up polling (a closed tab); the next call resumes the poll.
    const second = await scenario();
    second.client.gaslessTimingOverrides.giveUpAfterMs = 25;
    second.bundler.hold = true;
    await assert.rejects(second.withdraw('mutual'), error => error.code === 'gasless_op_pending' && error.userOpSent === true);
    journal = await second.prepared();
    assert.equal(journal.userOpPhase, 'op_submitted');
    assert.equal(journal.phase, 'awaiting_wallet', 'the claim stays while the op may be in a mempool');
    assert.ok(journal.userOpSubmittedAt > 0);
    second.client.gaslessTimingOverrides.giveUpAfterMs = 0;
    second.bundler.release();
    second.bundler.autoMine = second.closeBundle();
    setTimeout(() => second.bundler.mine(journal.userOpHash, second.closeBundle()(null, journal.userOpHash)), 15);
    const resumed = await within(5_000, second.withdraw('mutual'), 'resume at op_submitted');
    assert.equal(resumed.status, 'closed');
    assert.equal(second.wallet.signatures.length, 1);
    assert.equal(second.bundler.sent.length, 1, 'not sent again while pending');
});

test('a bundler that forgets the operation is replaced by the EntryPoint logs; a dropped one is re-sent, then bumped by 12.5% within the ceilings', async () => {
    const forgot = await scenario();
    forgot.bundler.forgetReceipts = true;
    forgot.bundler.autoMine = forgot.closeBundle();
    const result = await within(5_000, forgot.withdraw('mutual'), 'inclusion by logs');
    assert.equal(result.status, 'closed');
    const logQuery = forgot.chain.calls.find(call => call.method === 'eth_getLogs' && low(call.params[0].address) === forgot.chain.entryPoint);
    assert.ok(logQuery, 'UserOperationEvent logs were asked for');
    assert.equal(logQuery.params[0].topics[0], GASLESS_ABI.userOperationEvent);
    assert.equal(low([].concat(logQuery.params[0].topics[1])[0]), forgot.bundler.sent[0].hash);
    assert.ok(forgot.bundler.calls.some(call => call.method === 'eth_getUserOperationReceipt'));

    const dropped = await scenario();
    let sends = 0;
    dropped.bundler.onSend = async () => {
        sends += 1;
        if (sends === 1) dropped.bundler.drop = true;
        if (sends === 2) return { error: { code: -32602, message: 'replacement underpriced: fee too low' } };
        if (sends === 3) {
            dropped.bundler.drop = false;
            dropped.bundler.autoMine = dropped.closeBundle();
        }
        return null;
    };
    const bumped = await within(8_000, dropped.withdraw('mutual'), 'resend and fee bump');
    assert.equal(bumped.status, 'closed');
    assert.equal(sends, 3);
    const [first, retry, raised] = dropped.bundler.sent;
    assert.equal(retry.hash, first.hash, 'the identical operation first');
    assert.notEqual(raised.hash, first.hash);
    assert.equal(BigInt(raised.op.maxFeePerGas), BigInt(first.op.maxFeePerGas) * 1125n / 1000n);
    assert.equal(BigInt(raised.op.maxPriorityFeePerGas), BigInt(first.op.maxPriorityFeePerGas) * 1125n / 1000n);
    assert.ok(BigInt(raised.op.maxFeePerGas) <= BigInt(VECTORS.policy.max_fee_ceiling));
    assert.equal(raised.op.nonce, first.op.nonce, 'a replacement at the same nonce');
    assert.equal(dropped.wallet.signatures.length, 2, 'the bump is a new signature');
    assert.deepEqual((await dropped.record()).userOpHashes, [first.hash, raised.hash], 'both hashes journaled');
    assert.ok(dropped.statuses.some(message => /raised by 12\.5%/.test(message)));
    assert.ok(dropped.bundler.calls.some(call => call.method === 'eth_getUserOperationByHash'));
});

test('the submission stops 60 s before validUntil, releases the operation and proves again', async () => {
    const { h, bundler, wallet, client, withdraw, prepared } = await scenario();
    client.gaslessWithdrawalAttempts = 2;
    bundler.hold = true;
    bundler.onSend = async () => { client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    // After the stop the released operation is followed until the bundler no longer knows it (§3.1); this bundler drops it.
    bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
    await assert.rejects(within(5_000, withdraw('mutual'), 'expiry stop'), { code: 'gasless_op_expired' });
    const journal = await prepared();
    assert.equal(journal.userOp, undefined, 'the operation is released');
    assert.deepEqual(journal.staleUserOpHashes, [bundler.sent[0].hash], 'its hash is remembered for a late inclusion');
    assert.equal(journal.phase, 'prepared');
    assert.equal(proofs(h, 'mutual').length, 2, 'proved again once, then the limit');
    assert.equal(wallet.signatures.length, 1, 'the second proof stopped before any prompt');
    assert.ok(bundler.calls.some(call => call.method === 'eth_getUserOperationByHash' && low(call.params[0]) === bundler.sent[0].hash),
        'the released operation was asked for before the plan was proved again');
});

test('a bundler that returns another hash makes the submission ambiguous and the chain decides', async () => {
    const { bundler, withdraw, prepared, record, closeBundle } = await scenario();
    bundler.returnHash = `0x${'77'.repeat(32)}`;
    let ambiguousJournal = null;
    bundler.onMethod = async method => {
        if (method === 'eth_getUserOperationReceipt' && !ambiguousJournal) ambiguousJournal = await prepared();
    };
    bundler.autoMine = closeBundle();
    const result = await within(5_000, withdraw('mutual'), 'ambiguous hash');
    assert.equal(result.status, 'closed');
    assert.equal(ambiguousJournal.userOpAmbiguous, true);
    assert.deepEqual(ambiguousJournal.userOpHashes.sort(), [bundler.sent[0].hash, `0x${'77'.repeat(32)}`].sort());
    assert.equal(result.userOpHash, bundler.sent[0].hash, 'found under the signed hash');
    assert.equal((await record()).userOpHash, bundler.sent[0].hash);
});

test('a reverted execution (NoteNotActive after a replay) leaves the payout in S: stranded, then collectTransitBalance forwards it', async () => {
    const { chain, bundler, wallet, client, withdraw, S, record, closeKey, state } = await scenario();
    const vaultFailed = `0x${'c3076dea'}${word(0x20)}${word(4)}${'61a83aab'.padEnd(64, '0')}`;
    bundler.autoMine = (op, hash) => ({
        success: false,
        revertReason: vaultFailed,
        extraLogs: [
            logs.sponsorshipFailed(chain.paymaster, { key: closeKey, sender: S, kind: 1n, noteId: BigInt(NOTE_ID), actualGasCost: 10n ** 15n }),
            logs.stranded(chain.paymaster, S)
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.setBalance(S, wei(state.current_balance));
            chainState.paymasterState.stranded.set(S, true);
        }
    });
    const result = await within(5_000, withdraw('mutual'), 'reverted execution');
    assert.equal(result.status, 'closed');
    assert.equal(result.fundsWaitingInTransit, true);
    assert.equal(result.reason, 'note_not_active');
    assert.equal(result.transitBalanceWei, wei(state.current_balance).toString());
    let saved = await record();
    assert.equal(saved.fundsWaitingInTransit, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.userOpSuccess, false);
    assert.equal(saved.transit.account, S);
    // The forward: FORWARD_NONCE_KEY, withdraw(0x), no initCode (S exists now), the balance minus the charge to the payee.
    const forwardKey = attemptsKeyOf(4, { sender: S });
    bundler.autoMine = (op, hash) => ({
        success: true,
        extraLogs: [logs.settled(chain.paymaster, { key: forwardKey, sender: S, payee: PAYEE, kind: 4n, noteId: 0xffffffffn,
            received: wei(state.current_balance), charged: wei(300_000), owedPaid: 0n, paidOut: wei(state.current_balance) - wei(300_000) })],
        effects: chainState => { chainState.setBalance(S, 0n); chainState.paymasterState.stranded.set(S, false); }
    });
    const collected = await within(5_000, client.collectTransitBalance(saved.recordId, () => {}), 'forward');
    assert.equal(collected.status, 'collected');
    assert.equal(collected.amounts.paidOutWei, (wei(state.current_balance) - wei(300_000)).toString());
    const forward = bundler.sent.at(-1).op;
    assert.equal(unpackNonce(forward.nonce).key, FORWARD_NONCE_KEY);
    assert.equal(forward.callData, encodeTransitWithdraw('0x'));
    assert.equal('factory' in forward, false);
    assert.equal(BigInt(forward.callGasLimit), 97_500n);
    assert.equal(wallet.signatures.length, 2);
    saved = await record();
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.forwardUserOpHash, bundler.sent.at(-1).hash);
    assert.equal(saved.forwardTransactionHash, collected.transactionHash);
    // Without evidence a forward is refused and the sweep is suggested; an empty account has nothing to collect.
    chain.setBalance(S, 1n);
    await assert.rejects(client.collectTransitBalance(saved.recordId, () => {}), { code: 'transit_not_stranded' });
    chain.setBalance(S, 0n);
    await assert.rejects(client.collectTransitBalance(saved.recordId, () => {}), { code: 'transit_balance_empty' });
});

test('refusals before any prompt: the wrong owner account, AA31, a paused paymaster, a paused vault, a fee spike, a small payout, the 25% rule, exhausted attempts', async () => {
    // wrong_owner_account: a plan whose transit account belongs to OWNER, signed from another account.
    const owner = await scenario();
    owner.wallet.rejectSign = true;
    await assert.rejects(owner.withdraw('mutual'), error => error.code === 4001);
    assert.equal((await owner.prepared()).transit.owner, OWNER);
    assert.equal((await owner.prepared()).phase, 'prepared', 'the claim is released after the rejection');
    owner.client.connectWallet = async () => OTHER;
    globalThis.ethereum = fakeWallet({ owner: OTHER, privateKey: 0xb0bn, chainId: CHAIN_ID });
    await assert.rejects(owner.withdraw('mutual'), error => error.code === 'wrong_owner_account' && error.data.expected === OWNER);
    assert.equal(globalThis.ethereum.signatures.length, 0);

    // AA31 in the dry run: the float is short.
    const underfunded = await scenario();
    underfunded.chain.dryRun = () => revertError(failedOpData('AA31 paymaster deposit too low'));
    await assert.rejects(underfunded.withdraw('mutual'), { code: 'paymaster_underfunded' });
    assert.equal(underfunded.wallet.signatures.length, 0);
    assert.equal((await underfunded.prepared()).phase, 'prepared');
    // Short before proving too (balanceOf < maxCost needs the op; the policy float check is per op).
    const paused = await scenario();
    paused.chain.paymasterState.policy.sponsorshipPaused = true;
    await assert.rejects(paused.withdraw('mutual'), { code: 'sponsorship_paused' });
    assert.equal(proofs(paused.h, 'mutual').length, 0, 'refused before the proof');
    assert.equal(runtime.snapshot().config.gasless.reason, 'sponsorship_paused');

    const vaultPaused = await scenario();
    vaultPaused.chain.vaultState.paused = true;
    vaultPaused.chain.vaultState.pausedAt = 1_700_000_000n;
    await assert.rejects(vaultPaused.withdraw('mutual'), error => error.code === 'exits_paused' && error.data.reopenAt === 1_700_000_000 + 604_800);
    assert.equal(proofs(vaultPaused.h, 'mutual').length, 0);

    // baseFee + tip above the 100 gwei ceiling (2 × baseFee + tip above it alone is capped, not refused).
    const spike = await scenario();
    spike.chain.baseFee = 99n * GWEI;
    await assert.rejects(spike.withdraw('mutual'), error => error.code === 'gas_above_paymaster_ceiling' && error.data.maxFeeCeiling === 100n * GWEI);
    assert.equal(spike.wallet.signatures.length, 0);
    assert.equal(proofs(spike.h, 'mutual').length, 0, 'the fee ceiling refuses in the pre-flight, before the proof binds S');

    const small = await scenario({ state: noteState({ current_balance: 20_000_000, deposit_path: depositPath('0x51') }) });
    await assert.rejects(small.withdraw('mutual'), { code: 'payout_below_gas' });

    const uneconomic = await scenario({ state: noteState({ current_balance: 100_000_000, deposit_path: depositPath('0x51') }) });
    await assert.rejects(uneconomic.withdraw('mutual'), error => error.code === 'gasless_uneconomic' && error.data.uneconomicFractionPercent === 25n);
    assert.equal(uneconomic.wallet.signatures.length, 0);
    uneconomic.bundler.autoMine = uneconomic.closeBundle();
    const allowed = await within(5_000, uneconomic.withdraw('mutual', { allowExpensiveGas: true }), 'allowExpensiveGas');
    assert.equal(allowed.status, 'closed');
    assert.equal(proofs(uneconomic.h, 'mutual').length, 1, 'the proof made before the refusal is reused');

    const exhausted = await scenario();
    exhausted.chain.paymasterState.attempts.set(exhausted.closeKey, 3n);
    await assert.rejects(exhausted.withdraw('mutual'), { code: 'gasless_attempts_exhausted' });
    assert.equal(proofs(exhausted.h, 'mutual').length, 0);
    assert.equal(runtime.snapshot().config.gasless.attempts_left, 0);

    const disabled = await scenario({ profile: { escapesEnabled: false } });
    await assert.rejects(disabled.withdraw('escape'), { code: 'escapes_disabled' });
    assert.equal(proofs(disabled.h, 'escape').length, 0);

    const mismatch = await scenario();
    mismatch.chain.setCode(mismatch.chain.paymaster, '0x6001');
    await assert.rejects(mismatch.withdraw('mutual'), error => error.code === 'gasless_unavailable' && error.data.reason === 'gasless_deployment_mismatch'
        && error.data.mismatches.some(entry => entry.field === 'withdrawal_paymaster_runtime_codehash'));

    const none = await scenario({ gasless: null });
    await assert.rejects(none.withdraw('mutual'), error => error.code === 'gasless_unavailable' && error.data.reason === 'not_pinned');
    assert.equal(runtime.snapshot().config.gasless.supported, false);
});

test('a sponsored escape records its initiation debt; its finalization after the deadline deducts the debt; an escape finalized by a third party is forwarded', async () => {
    const { chain, bundler, client, withdraw, S, nullifier, record, state, statuses: escapeStatuses, amounts: escapeAmounts } = await scenario();
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: escapeKey, sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
            chainState.paymasterState.escapeSponsored.set(NOTE_ID, true);
        }
    });
    const started = await within(5_000, withdraw('escape'), 'sponsored escape');
    assert.equal(started.status, 'pending_withdrawal');
    assert.equal(started.initiationDebtWei, wei(4_000_000).toString());
    // Before the escape is signed: the bound on this start's debt and an estimate, not an "at least" the finalization could break.
    const escapeShown = escapeStatuses.find(message => /The escape is sponsored/.test(message));
    assert.match(escapeShown, /at current fees the payout address would receive about [0-9.]+ ETH/);
    assert.doesNotMatch(escapeShown, /at least/);
    assert.equal(escapeAmounts[0].minimumReceived, null);
    assert.ok(BigInt(escapeAmounts[0].estimatedReceived) > 0n);
    assert.equal(unpackNonce(bundler.sent[0].op.nonce).key, BigInt(nullifier) & ((1n << 192n) - 1n));
    assert.equal(BigInt(bundler.sent[0].op.callGasLimit), 680_000n, 'the escape default');
    let saved = await record();
    assert.equal(saved.mode, 'escape');
    assert.equal(saved.phase, 'pending');
    assert.equal(saved.feePayer, 'payout');
    assert.equal(saved.initiationDebtWei, wei(4_000_000).toString());
    assert.equal(saved.destination, S);
    assert.equal(saved.payout, PAYEE);
    assert.ok(started.recordId);

    // Finalization through the paymaster: the debt is deducted, the rest reaches the payee.
    const finalizeKey = attemptsKeyOf(3, { noteId: NOTE_ID });
    bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S }),
            logs.settled(chain.paymaster, { key: finalizeKey, sender: S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID), received: wei(state.current_balance),
                charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: wei(state.current_balance) - wei(7_000_000) })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.vaultState.pending.delete(NOTE_ID);
            chainState.paymasterState.owed.set(S, 0n);
            chainState.paymasterState.escapeNotePlusOne.set(S, 0n);
        }
    });
    const statuses = [];
    const finalized = await within(5_000, client.finalizeEscape(saved.recordId, message => statuses.push(message)), 'sponsored finalization');
    assert.equal(finalized.status, 'closed');
    assert.equal(finalized.amounts.owedPaidWei, wei(4_000_000).toString());
    const finalizeOp = bundler.sent.at(-1).op;
    assert.equal(finalizeOp.callData, encodeTransitWithdraw(encodeFinalizeEscape(NOTE_ID)));
    assert.equal(unpackNonce(finalizeOp.nonce).key, BigInt(nullifier) & ((1n << 192n) - 1n), 'uint192(pending.withdrawalNullifier)');
    assert.equal(BigInt(finalizeOp.callGasLimit), 287_500n);
    assert.ok(statuses.some(message => /receives at least/.test(message)));
    assert.ok(statuses.some(message => /0\.004 ETH of debt paid/.test(message)), statuses.join('\n'));
    saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.owedPaidWei, wei(4_000_000).toString());
    assert.equal(saved.finalizeUserOpHash, bundler.sent.at(-1).hash);
    assert.equal(saved.finalizeTransactionHash, finalized.transactionHash);
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(globalThis.ethereum.sent.length, 0);

    // A third party finalized first: finalizeEscape goes straight to a forward with the escape evidence.
    const third = await scenario();
    third.bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(third.nullifier), finalBalance: BigInt(state.current_balance), destination: third.S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(third.chain.paymaster, { sender: third.S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(third.chain.paymaster, { key: escapeKey, sender: third.S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(third.nullifier), finalBalance: BigInt(state.current_balance), destination: third.S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(third.S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(third.S, BigInt(NOTE_ID) + 1n);
        }
    });
    const escape = await within(5_000, third.withdraw('escape'), 'escape before a third-party finalization');
    // Someone finalized it: the note is closed, the payout sits in S.
    third.chain.noteStatus(NOTE_ID, 3);
    third.chain.vaultState.pending.delete(NOTE_ID);
    third.chain.setBalance(third.S, wei(state.current_balance));
    const forwardKey = attemptsKeyOf(4, { sender: third.S });
    third.bundler.autoMine = () => ({
        success: true,
        extraLogs: [logs.settled(third.chain.paymaster, { key: forwardKey, sender: third.S, payee: PAYEE, kind: 4n, noteId: BigInt(NOTE_ID),
            received: wei(state.current_balance), charged: wei(300_000), owedPaid: wei(4_000_000), paidOut: wei(state.current_balance) - wei(4_300_000) })],
        effects: chainState => { chainState.setBalance(third.S, 0n); chainState.paymasterState.owed.set(third.S, 0n); chainState.paymasterState.escapeNotePlusOne.set(third.S, 0n); }
    });
    const forwarded = await within(5_000, third.client.finalizeEscape(escape.recordId, () => {}), 'forward after a third-party finalization');
    assert.equal(forwarded.status, 'collected');
    assert.equal(forwarded.amounts.owedPaidWei, wei(4_000_000).toString());
    assert.equal(unpackNonce(third.bundler.sent.at(-1).op.nonce).key, FORWARD_NONCE_KEY);
    const record3 = await third.record();
    assert.equal(record3.payoutVerified, true);
    assert.equal(record3.fundsWaitingInTransit, false);
    assert.equal(record3.forwardUserOpHash, third.bundler.sent.at(-1).hash);
});

test('a payout the payee rejects is credited by the paymaster and delivered by claimGaslessCredit from a funded wallet', async () => {
    const { chain, bundler, wallet, client, withdraw, record, closeBundle, state } = await scenario({ allow: ['eth_estimateGas', 'eth_sendTransaction', 'eth_getTransactionReceipt'] });
    bundler.autoMine = closeBundle({ credited: true });
    const result = await within(5_000, withdraw('mutual'), 'credited payout');
    assert.equal(result.status, 'closed');
    assert.equal(result.paymasterCredited, true);
    assert.equal(result.amounts.paidOutWei, '0');
    let saved = await record();
    assert.equal(saved.paymasterCredited, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.paymasterCreditedWei, (wei(state.current_balance) - wei(5_000_000)).toString());
    assert.equal(saved.payoutCredited, undefined, 'not a vault escape credit');
    await client.refresh();
    assert.deepEqual(client.paymasterCreditedPayouts.map(entry => entry.payout), [PAYEE]);
    // The claim: P.claimCredit(payee) from the connected wallet, proven by CreditClaimed.
    const claimHash = `0x${'c1'.repeat(32)}`;
    wallet.onSend = transaction => {
        chain.receipts.set(claimHash, { transactionHash: claimHash, blockNumber: '0x500', status: '0x1',
            logs: [logs.creditClaimed(chain.paymaster, PAYEE, wei(state.current_balance) - wei(5_000_000))] });
        chain.paymasterState.credits.set(low(PAYEE), 0n);
        return claimHash;
    };
    const claimed = await client.claimGaslessCredit(PAYEE, () => {});
    assert.equal(claimed.status, 'claimed');
    assert.equal(claimed.amount, (wei(state.current_balance) - wei(5_000_000)).toString());
    assert.equal(claimed.transactionHash, claimHash);
    assert.equal(wallet.sent.length, 1);
    assert.equal(low(wallet.sent[0].to), chain.paymaster);
    assert.equal(wallet.sent[0].data, encodeClaimCredit(PAYEE));
    assert.equal(wallet.sent[0].value, undefined);
    saved = await record();
    assert.equal(saved.paymasterCredited, false);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.creditClaimTransactionHash, claimHash);
    assert.deepEqual(await client.claimGaslessCredit(PAYEE, () => {}), { status: 'nothing_to_claim', payee: PAYEE, amount: '0' });
});

test('self-bundling: a funded wallet sends handleOps itself through the unchanged transaction path and the journal keeps the bundle hash', async () => {
    const { chain, bundler, wallet, withdraw, S, record, closeBundle } = await scenario({ allow: ['eth_estimateGas', 'eth_sendTransaction', 'eth_getTransactionReceipt'] });
    const bundleHash = `0x${'5e'.repeat(32)}`;
    wallet.onSend = transaction => {
        const { beneficiary, ops } = decodeHandleOps(transaction.data);
        assert.equal(beneficiary, OWNER, 'the wallet is the beneficiary and gets the refund');
        const hash = hashPacked(ops[0], chain.entryPoint, chain.chainId);
        chain.mineUserOperation({ hash, op: ops[0], transactionHash: bundleHash, ...closeBundle()(null, hash) });
        return bundleHash;
    };
    const result = await within(5_000, withdraw('mutual', { selfBundle: true }), 'self-bundle');
    assert.equal(result.status, 'closed');
    assert.equal(result.transactionHash, bundleHash);
    assert.equal(bundler.sent.length, 0, 'the bundler was not used');
    assert.equal(wallet.sent.length, 1);
    assert.equal(low(wallet.sent[0].to), chain.entryPoint);
    assert.equal(wallet.sent[0].data.slice(0, 10), `0x${GASLESS_ABI.handleOps}`);
    assert.equal(wallet.sent[0].gas, '0x17ed0', 'the wallet estimate (0x9c40), padded as today');
    assert.equal(wallet.signatures.length, 1, 'the operation is still owner-signed');
    const saved = await record();
    assert.equal(saved.transactionHash, bundleHash);
    assert.equal(saved.destination, S);
    assert.equal(saved.payoutVerified, true);
});

test('the direct-call fallback pays from the wallet to the transit account, then sweepTransit creates the account and forwards the payout', async () => {
    const { chain, bundler, wallet, client, withdraw, S, record, prepared, state } = await scenario({
        allow: ['eth_estimateGas', 'eth_getTransactionCount', 'eth_sendTransaction', 'eth_getTransactionReceipt', 'eth_call', 'eth_blockNumber']
    });
    // The sponsored plan exists (the bundler was down after the op was journaled).
    bundler.unreachableMethods.add('eth_sendUserOperation');
    await assert.rejects(withdraw('mutual'), { code: 'bundler_unavailable' });
    assert.equal((await prepared()).destination, S);
    // fees: 'wallet' reuses the plan bound to S: an ordinary vault transaction from the wallet.
    const closeHash = `0x${'d1'.repeat(32)}`;
    wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        chain.head += 1;
        chain.receipts.set(closeHash, { transactionHash: closeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.mutualClose(VAULT, { noteId: BigInt(NOTE_ID), finalBalance: BigInt(state.current_balance), destination: S })] });
        chain.noteStatus(NOTE_ID, 3);
        chain.setBalance(S, wei(state.current_balance));
        return closeHash;
    };
    const statuses = [];
    const direct = await within(5_000, client.performWithdrawal('mutual', message => statuses.push(message), { fees: 'wallet' }), 'direct call');
    assert.equal(direct.status, 'closed');
    assert.equal(direct.fundsWaitingInTransit, true);
    assert.equal(direct.transitAccount, S);
    const plan = (await record()).preparedWithdrawal;
    assert.equal(wallet.sent[0].data, encodeWithdrawal(plan, 'mutual', S, VAULT, { conceded: plan.public_inputs.conceded }), 'the unchanged calldata, destination S');
    assert.equal(wallet.signatures.length, 1, 'the earlier signature; no new prompt for the direct call');
    let saved = await record();
    assert.equal(saved.fundsWaitingInTransit, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.feePayer, 'payout');
    assert.equal(saved.payout, PAYEE);
    assert.equal(saved.transit.account, S);
    assert.ok(statuses.some(message => /sits in this withdrawal’s transit account/.test(message)));
    // A wallet-paid close leaves the paymaster no evidence: only the sweep is named, and a sponsored forward is refused.
    assert.ok(statuses.some(message => /Sweep it to the payout address from a funded wallet \(sweepTransit\)/.test(message)), statuses.join('\n'));
    assert.ok(!statuses.some(message => /sponsored forward/.test(message)), statuses.join('\n'));
    await assert.rejects(client.collectTransitBalance(saved.recordId, () => {}), { code: 'transit_not_stranded' });
    // The sweep: createAccount first (S has no code), then sweep(); Collected proves the payout.
    const createHash = `0x${'ca'.repeat(32)}`;
    const sweepHash = `0x${'5a'.repeat(32)}`;
    wallet.onSend = transaction => {
        if (low(transaction.to) === chain.factory) {
            assert.equal(transaction.data, encodeCreateAccount(OWNER, PAYEE));
            chain.receipts.set(createHash, { transactionHash: createHash, blockNumber: '0x600', status: '0x1',
                logs: [logs.accountCreated(chain.factory, { account: S, owner: OWNER, payee: PAYEE })] });
            chain.setCode(S, '0x3660');
            return createHash;
        }
        assert.equal(low(transaction.to), S);
        assert.equal(transaction.data, encodeSweep());
        chain.receipts.set(sweepHash, { transactionHash: sweepHash, blockNumber: '0x601', status: '0x1',
            logs: [logs.collected(chain.paymaster, { sender: S, payee: PAYEE, received: wei(state.current_balance), owedPaid: 0n, paidOut: wei(state.current_balance) })] });
        chain.setBalance(S, 0n);
        return sweepHash;
    };
    const swept = await within(5_000, client.sweepTransit(saved.recordId, () => {}), 'sweep');
    assert.equal(swept.status, 'swept');
    assert.equal(swept.createTransactionHash, createHash);
    assert.equal(swept.transactionHash, sweepHash);
    assert.equal(wallet.sent.length, 3);
    saved = await record();
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.sweepTransactionHash, sweepHash);
    assert.equal(saved.transitCreateTransactionHash, createHash);
    assert.equal(saved.paidOutWei, wei(state.current_balance).toString());
});

test('the read RPC ladder never touches the wallet provider unless the host opts in; the bundler URL is per origin', async () => {
    const first = await scenario();
    first.bundler.autoMine = first.closeBundle();
    await within(5_000, first.withdraw('mutual'), 'exit RPC reads');
    assert.deepEqual([...new Set(first.wallet.calls.map(call => call.method))], ['personal_sign']);
    assert.ok(first.chain.calls.length > 20);
    // The exit RPC fails: the pinned RPC answers; the wallet still only signs.
    const second = await scenario();
    const pinnedCalls = [];
    runtime.exitRpc = () => async () => { throw new Error('exit RPC down'); };
    runtime.pinnedRpc = () => async payload => { pinnedCalls.push(payload.method); return second.chain.request(payload); };
    second.bundler.autoMine = second.closeBundle();
    await within(5_000, second.withdraw('mutual'), 'pinned RPC reads');
    assert.ok(pinnedCalls.includes('eth_call'));
    assert.deepEqual([...new Set(second.wallet.calls.map(call => call.method))], ['personal_sign']);
    // Opted in, with both read RPCs down, the wallet provider answers the reads.
    const third = await scenario({ allow: ['eth_chainId', 'eth_call', 'eth_getCode', 'eth_getBalance', 'eth_getBlockByNumber', 'eth_blockNumber',
        'eth_maxPriorityFeePerGas', 'eth_getLogs', 'eth_getTransactionReceipt', 'eth_gasPrice'] });
    runtime.exitRpc = () => async () => { throw new Error('exit RPC down'); };
    runtime.pinnedRpc = () => async () => { throw new Error('pinned RPC down'); };
    third.client.gaslessReadsViaWallet = true;
    third.bundler.autoMine = third.closeBundle();
    await within(5_000, third.withdraw('mutual'), 'wallet reads when opted in');
    assert.ok(third.wallet.calls.some(call => call.method === 'eth_call'));
    // setBundlerUrl: validated, saved per origin, overrides the profile's; null restores it.
    const fourth = await scenario();
    assert.equal(fourth.client.getBundlerUrl(), null);
    assert.equal(runtime.snapshot().config.gasless.bundler_url, BUNDLER_URL);
    assert.throws(() => fourth.client.setBundlerUrl('http://bundler.example/'), { code: 'bundler_url_invalid' });
    assert.equal(fourth.client.setBundlerUrl('https://my-bundler.example/rpc'), 'https://my-bundler.example/rpc');
    assert.equal(storage.get('zkapi-bundler-url'), 'https://my-bundler.example/rpc');
    assert.equal(runtime.snapshot().config.gasless.bundler_url, 'https://my-bundler.example/rpc');
    fourth.bundler.url = 'https://my-bundler.example/rpc';
    fourth.bundler.chainId = 1n;
    const availability = await fourth.client.gaslessAvailability({ mode: 'mutual', destination: PAYEE });
    assert.equal(availability.available, false);
    assert.equal(availability.reason, 'bundler_wrong_chain');
    assert.equal(runtime.snapshot().config.gasless.bundler_wrong_chain, true);
    await assert.rejects(fourth.withdraw('mutual'), { code: 'bundler_wrong_chain' });
    assert.equal(fourth.client.setBundlerUrl(null), null);
    assert.equal(runtime.snapshot().config.gasless.bundler_url, BUNDLER_URL);
});

test('gaslessWithdrawalQuote and gaslessAvailability never prove, prompt or send', async () => {
    const { h, chain, wallet, client, S } = await scenario();
    const quote = await client.gaslessWithdrawalQuote('mutual', { destination: PAYEE });
    assert.equal(quote.available, true);
    assert.equal(quote.transitAccount, S);
    assert.equal(quote.owner, OWNER);
    assert.equal(quote.payout, PAYEE);
    assert.equal(quote.transitExists, false);
    assert.equal(quote.payoutWei, wei(500_000_000).toString());
    assert.equal(BigInt(quote.maxCost), (BigInt(quote.gas.preVerificationGas) + BigInt(quote.gas.verificationGasLimit) + BigInt(quote.gas.callGasLimit)
        + BigInt(quote.gas.paymasterVerificationGasLimit) + BigInt(quote.gas.paymasterPostOpGasLimit)) * BigInt(quote.fees.maxFeePerGas));
    assert.equal(quote.minimumReceivedWei, (wei(500_000_000) - BigInt(quote.maxCost) - BigInt(VECTORS.policy.flat_fee_wei)).toString());
    assert.equal(quote.flatFeeWei, VECTORS.policy.flat_fee_wei);
    assert.equal(quote.uneconomic, false);
    assert.equal(quote.bundlerUrl, BUNDLER_URL);
    assert.equal(quote.attemptsLeft, 3);
    assert.match(quote.privacy, /fresh account/);
    assert.match(quote.privacy, /bundler \(the operator’s unless you set your own\) sees the operation/, 'what the bundler learns is disclosed');
    assert.match(quote.privacy, /IP address and timing before it is included; for an escape it learns of the exit before the chain does/);
    assert.equal(proofs(h, 'mutual').length + proofs(h, 'escape').length, 0, 'no proof');
    assert.deepEqual(wallet.calls, [], 'no prompt, no wallet read');
    assert.equal(wallet.sent.length, 0);
    const escape = await client.gaslessWithdrawalQuote('escape', { destination: PAYEE });
    assert.equal(escape.available, true);
    assert.equal(escape.concededUnknown, true);
    assert.ok(BigInt(escape.amounts.finalizeReserveWei) > 0n);
    // An escape's net is an estimate at today's fees, never a floor: its finalization is charged at its own fees later.
    assert.equal(escape.minimumReceivedWei, null);
    assert.equal(escape.amounts.minimumReceived, null);
    assert.equal(escape.estimatedReceivedWei, (wei(500_000_000) - BigInt(escape.maxCost) - 2n * BigInt(VECTORS.policy.flat_fee_wei)
        - BigInt(escape.amounts.finalizeReserveWei)).toString());
    assert.equal(quote.estimatedReceivedWei, null);
    chain.paymasterState.policy.sponsorshipPaused = true;
    const paused = await client.gaslessWithdrawalQuote('mutual', { destination: PAYEE });
    assert.equal(paused.available, false);
    assert.equal(paused.reason, 'sponsorship_paused');
    const availability = await client.gaslessAvailability({ mode: 'mutual', destination: PAYEE });
    assert.equal(availability.available, false);
    assert.equal(availability.reason, 'sponsorship_paused');
    assert.equal(availability.transitAccount, S);
    assert.equal(availability.paymasterDepositWei, chain.paymasterState.deposit.toString());
    chain.paymasterState.policy.sponsorshipPaused = false;
    chain.paymasterState.deposit = 1n;
    const short = await client.gaslessWithdrawalQuote('mutual', { destination: PAYEE });
    assert.equal(short.reason, 'paymaster_underfunded');
    assert.deepEqual(wallet.calls, []);
});

test('a plan prepared for wallet fees is refused by the sponsored path, and a sponsored plan by another destination', async () => {
    const walletPlan = await scenario({ allow: ['eth_estimateGas', 'eth_getTransactionCount', 'eth_call'] });
    await assert.rejects(walletPlan.client.performWithdrawal('mutual', () => {}, { destination: PAYEE }), /never sends a transaction/);
    await assert.rejects(walletPlan.withdraw('mutual'), { code: 'gasless_plan_mismatch' });
    const bound = await scenario();
    bound.bundler.unreachableMethods.add('eth_sendUserOperation');
    await assert.rejects(bound.withdraw('mutual'), { code: 'bundler_unavailable' });
    await assert.rejects(bound.withdraw('mutual', { destination: `0x${'55'.repeat(20)}` }), /already bound to a different destination/);
    assert.equal(bound.wallet.signatures.length, 1);
});

test('fees: wallet is byte-for-byte today’s path, with or without a gasless profile', async () => {
    const transactions = [];
    const messages = [];
    // Each plan embeds valid_until = now + the proof validity: both runs read
    // a clock started at the same whole second, so the comparison stays
    // byte-for-byte even when the runs straddle a wall-clock second (forced
    // below, between the runs).
    const realNow = Date.now;
    const pinnedStart = Math.floor(realNow() / 1_000) * 1_000;
    try {
        for (const gasless of [gaslessProfileFromVectors({ spelling: 'profile' }), null]) {
            if (transactions.length) await new Promise(resolve => setTimeout(resolve, 1_000 - (realNow() % 1_000) + 5));
            const { wallet, client, statuses } = await scenario({ gasless, allow: ['eth_estimateGas', 'eth_getTransactionCount', 'eth_call'] });
            wallet.onSend = () => { throw { code: 4001, message: 'User rejected the request.' }; };
            wallet.allow.add('eth_sendTransaction');
            const runStart = realNow();
            Date.now = () => pinnedStart + (realNow() - runStart);
            await assert.rejects(client.performWithdrawal('escape', message => statuses.push(message), { destination: PAYEE }), error => error.code === 4001);
            Date.now = realNow;
            assert.equal(wallet.sent.length, 1);
            transactions.push(wallet.sent[0]);
            messages.push(statuses.filter(message => !/simulation/.test(message)));
            assert.equal(wallet.signatures.length, 0);
            assert.equal(runtime.snapshot().config.gasless.supported, Boolean(gasless));
            assert.equal(runtime.snapshot().config.prepared_withdrawal.fee_payer, 'wallet');
        }
    } finally {
        Date.now = realNow;
    }
    assert.deepEqual(transactions[0], transactions[1]);
    assert.deepEqual(messages[0], messages[1]);
    assert.equal(low(transactions[0].to), low(VAULT));
    assert.equal(transactions[0].gas, '0x17ed0', 'the wallet estimate (0x9c40), padded as today');
});

test('background recovery: syncWithdrawal finds a journaled operation on chain by its hash and settles it; syncEscapeWithdrawals finds a journaled finalization', async () => {
    // op_submitted, the tab gave up polling, the bundler forgot everything; the chain has the bundle.
    const { chain, bundler, wallet, client, withdraw, S, prepared, record, closeBundle } = await scenario({
        allow: ['eth_chainId']
    });
    client.gaslessTimingOverrides.giveUpAfterMs = 25;
    bundler.hold = true;
    await assert.rejects(withdraw('mutual'), { code: 'gasless_op_pending' });
    const journal = await prepared();
    assert.equal(journal.userOpPhase, 'op_submitted');
    bundler.release();
    bundler.mine(journal.userOpHash, closeBundle()(null, journal.userOpHash));
    bundler.ops.clear();
    bundler.forgetReceipts = true;
    await client.refresh();
    const statuses = [];
    const synced = await within(5_000, client.syncWithdrawal(message => statuses.push(message)), 'background sync');
    assert.equal(synced.status, 'closed');
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.transactionHash, bundler.mined.get(journal.userOpHash).transactionHash);
    assert.equal(saved.userOpHash, journal.userOpHash);
    assert.equal(saved.feePayer, 'payout');
    assert.ok(statuses.some(message => /included in/.test(message)));
    assert.equal(wallet.signatures.length, 1, 'no prompt in the background');
    assert.ok(!wallet.calls.some(call => call.method !== 'eth_chainId' && call.method !== 'personal_sign'), 'the background reads use the read RPC');
    const logQuery = chain.calls.find(call => call.method === 'eth_getLogs' && low(call.params[0].address) === chain.entryPoint);
    assert.ok(logQuery);

    // A journaled finalization (op_built, never followed) found by the escape sync's pre-pass.
    const escape = await scenario({ allow: ['eth_chainId'] });
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    escape.bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(escape.nullifier), finalBalance: BigInt(escape.state.current_balance), destination: escape.S, challengeDeadline: BigInt(deadline) }),
            logs.settled(escape.chain.paymaster, { key: escapeKey, sender: escape.S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(escape.nullifier), finalBalance: BigInt(escape.state.current_balance), destination: escape.S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(escape.state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(escape.S, wei(4_000_000));
        }
    });
    const started = await within(5_000, escape.withdraw('escape'), 'escape');
    escape.client.gaslessTimingOverrides.giveUpAfterMs = 25;
    escape.bundler.hold = true;
    escape.bundler.autoMine = null;
    await assert.rejects(escape.client.finalizeEscape(started.recordId, () => {}), { code: 'gasless_op_pending' });
    let saved2 = await escape.record();
    assert.equal(saved2.finalizeUserOpPhase, 'op_submitted');
    assert.equal(saved2.finalizeTransactionHash, undefined);
    const finalizeKey = attemptsKeyOf(3, { noteId: NOTE_ID });
    escape.bundler.release();
    escape.bundler.mine(saved2.finalizeUserOpHash, {
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(escape.nullifier), finalBalance: BigInt(escape.state.current_balance), destination: escape.S }),
            logs.settled(escape.chain.paymaster, { key: finalizeKey, sender: escape.S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID), received: wei(escape.state.current_balance),
                charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: wei(escape.state.current_balance) - wei(7_000_000) })
        ],
        effects: chainState => { chainState.noteStatus(NOTE_ID, 3); chainState.vaultState.pending.delete(NOTE_ID); }
    });
    escape.bundler.forgetReceipts = true;
    await escape.client.refresh();
    await within(5_000, escape.client.syncEscapeWithdrawals(() => {}), 'escape sync');
    saved2 = await escape.record();
    assert.equal(saved2.finalizeTransactionHash, escape.bundler.mined.get(saved2.finalizeUserOpHash).transactionHash);
    assert.equal(saved2.phase, 'closed_unconfirmed');
    // The finalization's own Settled event, not the initiation's amounts (§3.2 amounts table).
    assert.equal(saved2.payoutVerified, true);
    assert.equal(saved2.finalizeUserOpPhase, 'settled');
    assert.equal(saved2.chargedWei, wei(3_000_000).toString());
    assert.equal(saved2.owedPaidWei, wei(4_000_000).toString());
    assert.equal(saved2.paidOutWei, (wei(escape.state.current_balance) - wei(7_000_000)).toString());
    assert.equal(saved2.receivedWei, wei(escape.state.current_balance).toString());
    assert.equal(saved2.paymasterCredited, false);
    assert.ok(!escape.wallet.calls.some(call => !['eth_chainId', 'personal_sign'].includes(call.method)),
        `the escape sync reads the bundle receipts, the note and the logs through the read RPC: ${escape.wallet.calls.map(call => call.method).join(', ')}`);
});

test('the pre-flight prices the operation before any proof: an empty float, a fee spike and a cost above the policy refuse before proving', async () => {
    // balanceOf(P) < maxCost: refused by gaslessAvailability, the quote and withdraw alike, with no proof made.
    const short = await scenario();
    short.chain.paymasterState.deposit = 1n;
    const availability = await short.client.gaslessAvailability({ mode: 'mutual', destination: PAYEE });
    assert.equal(availability.available, false);
    assert.equal(availability.reason, 'paymaster_underfunded');
    assert.equal(availability.paymasterDepositWei, '1');
    assert.ok(availability.data.maxCost > 0n, 'the pre-flight priced the draft operation');
    await assert.rejects(short.withdraw('mutual'), error => error.code === 'paymaster_underfunded' && error.data.depositWei === 1n
        && error.data.maxCost === availability.data.maxCost);
    assert.equal(proofs(short.h, 'mutual').length, 0, 'refused before the proof binds S');
    assert.equal(short.wallet.signatures.length, 0);
    assert.equal(runtime.snapshot().config.gasless.reason, 'paymaster_underfunded');
    assert.equal(runtime.snapshot().config.gasless.max_cost_wei, availability.data.maxCost.toString());
    // The float covers the prefund again: the same call proves and settles.
    short.chain.paymasterState.deposit = 10n ** 18n;
    short.bundler.autoMine = short.closeBundle();
    assert.equal((await within(5_000, short.withdraw('mutual'), 'funded again')).status, 'closed');

    // baseFee + tip above the paymaster's max-fee ceiling: the quote and the pre-flight refuse, no proof.
    const spike = await scenario();
    spike.chain.baseFee = 99n * GWEI;
    const spiked = await spike.client.gaslessWithdrawalQuote('mutual', { destination: PAYEE });
    assert.equal(spiked.available, false);
    assert.equal(spiked.reason, 'gas_above_paymaster_ceiling');
    const spikeAvailability = await spike.client.gaslessAvailability({ mode: 'mutual', destination: PAYEE });
    assert.equal(spikeAvailability.reason, 'gas_above_paymaster_ceiling');
    await assert.rejects(spike.withdraw('mutual'), { code: 'gas_above_paymaster_ceiling' });
    assert.equal(proofs(spike.h, 'mutual').length, 0);

    // maxCost above policy.maxSponsoredCostWei at the current fees: refused before the proof.
    const costly = await scenario();
    costly.chain.paymasterState.policy.maxSponsoredCost = 10n ** 15n;
    await assert.rejects(costly.withdraw('mutual'), error => error.code === 'max_cost_above_policy' && error.data.cap === 10n ** 15n);
    assert.equal(proofs(costly.h, 'mutual').length, 0);
    assert.equal((await costly.client.gaslessAvailability({ mode: 'escape', destination: PAYEE })).reason, 'max_cost_above_policy');

    // The pre-flight order: a paused paymaster still outranks a fee refusal; the float check sees the real prefund.
    const paused = await scenario();
    paused.chain.baseFee = 99n * GWEI;
    paused.chain.paymasterState.policy.sponsorshipPaused = true;
    assert.equal((await paused.client.gaslessAvailability({ mode: 'mutual', destination: PAYEE })).reason, 'sponsorship_paused');
});

test('a bundler estimate between the signed default and the paymaster’s cap is accepted; only one above the cap is refused', async () => {
    const between = await scenario();
    between.bundler.estimate = { callGasLimit: '0xaae60' };
    between.bundler.autoMine = between.closeBundle();
    const result = await within(5_000, between.withdraw('mutual'), 'estimate between the default and the cap');
    assert.equal(result.status, 'closed');
    assert.equal(BigInt(between.bundler.sent[0].op.callGasLimit), 642_500n, 'the pinned default is still what is signed');
    const above = await scenario();
    above.bundler.estimate = { callGasLimit: '0xf4240' };
    await assert.rejects(above.withdraw('mutual'), error => error.code === 'gasless_estimate_above_cap'
        && error.data.above[0].name === 'callGasLimit' && error.data.above[0].cap === BigInt(VECTORS.gas_policy.call_hard_cap[0]));
    assert.equal(above.wallet.signatures.length, 0);
});

test('ERC-7769 -32508 (paymaster balance) and -32507 (signature) on the first send cost one signature and are never treated as a fee refusal', async () => {
    for (const [code, message, expected] of [
        [-32508, 'paymaster balance too low to cover all pending UserOperations', 'paymaster_underfunded'],
        [-32507, 'Invalid UserOp signature or paymaster signature', 'signature_rejected']
    ]) {
        const { bundler, wallet, withdraw, statuses } = await scenario();
        let sends = 0;
        bundler.onSend = async () => { sends += 1; return { error: { code, message } }; };
        await assert.rejects(within(5_000, withdraw('mutual'), `${code} on the first send`), { code: expected });
        assert.equal(sends, 1, `${code}: no re-send`);
        assert.equal(wallet.signatures.length, 1, `${code}: exactly one signature`);
        assert.ok(!statuses.some(text => /raised by 12\.5%/.test(text)), `${code}: no fee bump`);
    }
    // A fee refusal is decided by its wording: -32602 with fee words is one.
    assert.equal(new ZkapiClient().gaslessFeeTooLow({ rpcCode: -32602, rpcMessage: 'maxPriorityFeePerGas must be at least 1 gwei' }), true);
    assert.equal(new ZkapiClient().gaslessFeeTooLow({ rpcCode: -32508, rpcMessage: 'replacement underpriced' }), false);
    assert.equal(new ZkapiClient().gaslessFeeTooLow({ rpcCode: -32500, aa: 'AA31', rpcMessage: 'AA31 paymaster deposit too low: gas price' }), false);
});

test('a fee-too-low refusal with maxFeePerGas at the ceiling is the bump exhausted, not a signature per loop', async () => {
    const { chain, bundler, wallet, withdraw, prepared } = await scenario();
    chain.baseFee = 49n * GWEI; // 2 × 49 + 2 gwei = the 100 gwei ceiling
    let sends = 0;
    bundler.onSend = async () => {
        sends += 1;
        if (sends === 1) bundler.drop = true;
        if (sends >= 2) return { error: { code: -32602, message: 'replacement underpriced: fee too low' } };
        return null;
    };
    await assert.rejects(within(5_000, withdraw('mutual', { allowExpensiveGas: true }), 'bump exhausted'), { code: 'gasless_fee_bump_exhausted' });
    assert.equal(BigInt(bundler.sent[0].op.maxFeePerGas), 100n * GWEI);
    assert.equal(sends, 2, 'the identical re-send, then no replacement the bundler could accept');
    assert.equal(wallet.signatures.length, 1, 'no re-sign for a priority-only bump');
    assert.equal((await prepared()).phase, 'prepared');
});

test('a journaled operation is looked for on chain before any re-send, and a bundler whose nonce view lags cannot prompt again', async () => {
    // op_built, then the bundle mined while the bundler was unreachable; the bundler now answers AA25 to every send.
    const { chain, bundler, wallet, withdraw, prepared, record, closeBundle } = await scenario();
    bundler.unreachableMethods.add('eth_sendUserOperation');
    await assert.rejects(withdraw('mutual'), { code: 'bundler_unavailable' });
    const journal = await prepared();
    const mined = chain.mineUserOperation({ hash: journal.userOpHash, op: journal.userOp, ...closeBundle()(null, journal.userOpHash) });
    bundler.unreachableMethods.clear();
    bundler.failSend = { code: -32500, message: 'AA25 invalid account nonce' };
    const result = await within(5_000, withdraw('mutual'), 'the resume finds the inclusion');
    assert.equal(result.status, 'closed');
    assert.equal(result.transactionHash, mined.transactionHash);
    assert.equal(result.amounts.chargedWei, wei(5_000_000).toString());
    assert.equal(bundler.sent.length, 0, 'nothing was sent again');
    assert.equal(wallet.signatures.length, 1);
    const saved = await record();
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.userOpHash, journal.userOpHash);
    assert.equal(saved.transactionHash, mined.transactionHash);

    // AA25 from the bundler while the chain's nonce has not moved: the refusal is the bundler's, no second signature.
    const lagging = await scenario();
    lagging.bundler.failSend = { code: -32500, message: 'AA25 invalid account nonce' };
    await assert.rejects(lagging.withdraw('mutual'), error => error.code === 'bundler_rejected' && error.data.aa === 'AA25' && error.aa === 'AA25');
    assert.equal(lagging.wallet.signatures.length, 1);
    assert.equal(lagging.bundler.sent.length, 1);
    const kept = await lagging.prepared();
    assert.equal(kept.phase, 'prepared', 'the claim is released');
    assert.ok(kept.userOp, 'the journaled operation is kept for a resume');

    // AA25 from the bundler because the operation was mined between the dry run and the send: settled, not rebuilt.
    const raced = await scenario();
    raced.bundler.onSend = async (op, hash) => {
        raced.chain.mineUserOperation({ hash, op, ...raced.closeBundle()(null, hash) });
        return { error: { code: -32500, message: 'AA25 invalid account nonce' } };
    };
    const settled = await within(5_000, raced.withdraw('mutual'), 'AA25 after an inclusion');
    assert.equal(settled.status, 'closed');
    assert.equal(raced.wallet.signatures.length, 1);
    assert.equal(raced.bundler.sent.length, 1);
    assert.equal((await raced.record()).payoutVerified, true);

    // AA10 from the bundler while S has no code: refused, not rebuilt without initCode.
    const phantom = await scenario();
    phantom.bundler.failSend = { code: -32500, message: 'AA10 sender already constructed' };
    await assert.rejects(phantom.withdraw('mutual'), error => error.code === 'bundler_rejected' && error.data.aa === 'AA10');
    assert.equal(phantom.wallet.signatures.length, 1);
    assert.equal(phantom.bundler.sent.length, 1);

    // AA10 because S was created meanwhile: rebuilt without initCode once, bounded.
    const created = await scenario();
    let sends = 0;
    created.bundler.onSend = async op => {
        sends += 1;
        if (op.factory) {
            created.chain.setCode(created.S, '0x3660');
            return { error: { code: -32500, message: 'AA10 sender already constructed' } };
        }
        return null;
    };
    created.bundler.autoMine = created.closeBundle();
    assert.equal((await within(5_000, created.withdraw('mutual'), 'AA10 rebuild')).status, 'closed');
    assert.equal(sends, 2);
    assert.equal('factory' in created.bundler.sent[1].op, false);
    assert.equal(created.wallet.signatures.length, 2);
});

test('an operation released before its late inclusion is still settled from its stale hash in the background', async () => {
    const { bundler, client, withdraw, prepared, record, closeBundle } = await scenario();
    client.gaslessWithdrawalAttempts = 2;
    bundler.hold = true;
    bundler.onSend = async () => { client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    // After the stop the released operation is followed until the bundler no longer knows it (§3.1); this bundler drops it.
    bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
    await assert.rejects(within(5_000, withdraw('mutual'), 'expiry stop'), { code: 'gasless_op_expired' });
    const journal = await prepared();
    assert.equal(journal.userOp, undefined);
    const [stale] = journal.staleUserOpHashes;
    assert.ok(journal.staleSubmittedAtBlock > 0, 'the block the released operation was tracked from');
    // The old operation lands after all (another mempool still held it); the bundler forgets it.
    bundler.release();
    bundler.mine(stale, closeBundle()(null, stale));
    bundler.forgetReceipts = true;
    client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 60;
    await client.refresh();
    const synced = await within(5_000, client.syncWithdrawal(() => {}), 'stale inclusion');
    assert.equal(synced.status, 'closed');
    const saved = await record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.userOpHash, stale, 'the settled hash is restored on the record');
    assert.equal(saved.transactionHash, bundler.mined.get(stale).transactionHash);
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.chargedWei, wei(5_000_000).toString());
    assert.equal(saved.paidOutWei, (wei(500_000_000) - wei(5_000_000)).toString());
});

test('the escape sync settles a sponsored finalization from its bundle through the read RPC: a credited payout stays credited, a third-party finalization waits in S', async () => {
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    const finalizeKey = attemptsKeyOf(3, { noteId: NOTE_ID });
    const startEscape = ({ chain, S, nullifier, state }) => () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: escapeKey, sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
        }
    });
    const walletReads = wallet => [...new Set(wallet.calls.map(call => call.method))].filter(method => !['eth_chainId', 'personal_sign'].includes(method));

    // (1) The sponsored finalization credited the payee (PayoutCredited, paidOut 0): the background pass keeps it credited.
    const credited = await scenario({ allow: ['eth_chainId'] });
    credited.bundler.autoMine = startEscape(credited);
    const started = await within(5_000, credited.withdraw('escape'), 'sponsored escape');
    const paid = wei(credited.state.current_balance) - wei(7_000_000);
    credited.bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(credited.nullifier), finalBalance: BigInt(credited.state.current_balance), destination: credited.S }),
            logs.settled(credited.chain.paymaster, { key: finalizeKey, sender: credited.S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID),
                received: wei(credited.state.current_balance), charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: 0n }),
            logs.payoutCredited(credited.chain.paymaster, PAYEE, paid)
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.vaultState.pending.delete(NOTE_ID);
            chainState.paymasterState.owed.set(credited.S, 0n);
            chainState.paymasterState.escapeNotePlusOne.set(credited.S, 0n);
            chainState.paymasterState.credits.set(low(PAYEE), paid);
        }
    });
    const finalized = await within(5_000, credited.client.finalizeEscape(started.recordId, () => {}), 'credited finalization');
    assert.equal(finalized.paymasterCredited, true);
    let saved = await credited.record();
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.paymasterCredited, true);
    credited.wallet.calls.length = 0;
    for (let pass = 0; pass < 2; pass += 1) {
        await within(5_000, credited.client.syncEscapeWithdrawals(() => {}), 'escape sync');
        saved = await credited.record();
        assert.equal(saved.phase, 'closed_unconfirmed');
        assert.equal(saved.payoutVerified, false, 'a paymaster credit is never reported as paid by the background pass');
        assert.equal(saved.paymasterCredited, true);
        assert.equal(saved.paymasterCreditedWei, paid.toString());
        assert.equal(saved.paidOutWei, '0');
        assert.equal(saved.owedPaidWei, wei(4_000_000).toString());
        assert.equal(saved.chargedWei, wei(3_000_000).toString());
        assert.equal(saved.fundsWaitingInTransit, false);
    }
    assert.deepEqual(walletReads(credited.wallet), [], 'the bundle receipts, the note and the logs are read through the read RPC only');
    await credited.client.refresh();
    assert.deepEqual(credited.client.paymasterCreditedPayouts.map(entry => entry.recordId), [started.recordId]);
    await assert.rejects(credited.client.finalizeEscape(started.recordId, () => {}), /no pending escape/);

    // (2) A third party finalized the sponsored escape: the sync reports the payout waiting in S; finalizeEscape forwards it.
    const third = await scenario({ allow: ['eth_chainId'] });
    third.bundler.autoMine = startEscape(third);
    const escape = await within(5_000, third.withdraw('escape'), 'escape');
    third.chain.noteStatus(NOTE_ID, 3);
    third.chain.vaultState.pending.delete(NOTE_ID);
    third.chain.setBalance(third.S, wei(third.state.current_balance));
    third.chain.head += 1;
    third.wallet.calls.length = 0;
    const statuses = [];
    await within(5_000, third.client.syncEscapeWithdrawals(message => statuses.push(message)), 'third-party close');
    saved = await third.record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.payoutVerified, false);
    assert.equal(saved.fundsWaitingInTransit, true);
    assert.equal(saved.transitBalanceWei, wei(third.state.current_balance).toString());
    assert.ok(statuses.some(message => /sits in this withdrawal’s transit account/.test(message)), statuses.join('\n'));
    assert.deepEqual(walletReads(third.wallet), []);
    const forwardKey = attemptsKeyOf(4, { sender: third.S });
    third.bundler.autoMine = () => ({
        success: true,
        extraLogs: [logs.settled(third.chain.paymaster, { key: forwardKey, sender: third.S, payee: PAYEE, kind: 4n, noteId: BigInt(NOTE_ID),
            received: wei(third.state.current_balance), charged: wei(300_000), owedPaid: wei(4_000_000), paidOut: wei(third.state.current_balance) - wei(4_300_000) })],
        effects: chainState => { chainState.setBalance(third.S, 0n); chainState.paymasterState.owed.set(third.S, 0n); chainState.paymasterState.escapeNotePlusOne.set(third.S, 0n); }
    });
    const forwarded = await within(5_000, third.client.finalizeEscape(escape.recordId, () => {}), 'forward of a closed sponsored escape');
    assert.equal(forwarded.status, 'collected');
    assert.equal(forwarded.amounts.owedPaidWei, wei(4_000_000).toString());
    saved = await third.record();
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(saved.forwardTransactionHash, forwarded.transactionHash);
    await within(5_000, third.client.syncEscapeWithdrawals(() => {}), 'sync after the forward');
    saved = await third.record();
    assert.equal(saved.payoutVerified, true, 'a forwarded payout stays proven');
    assert.equal(saved.fundsWaitingInTransit, false);
});

test('a bundler that refuses the first send for its fee gets the operation signed again with both fees raised by 12.5%; its own tip is used when offered', async () => {
    const { bundler, wallet, withdraw, record, closeBundle, statuses } = await scenario();
    let sends = 0;
    bundler.onSend = async () => {
        sends += 1;
        if (sends === 1) return { error: { code: -32602, message: 'replacement underpriced: fee too low' } };
        bundler.autoMine = closeBundle();
        return null;
    };
    const result = await within(5_000, withdraw('mutual'), 'first-send fee bump');
    assert.equal(result.status, 'closed');
    assert.equal(sends, 2, 'the refused op, then its replacement');
    const [first, raised] = bundler.sent;
    assert.notEqual(raised.hash, first.hash);
    assert.equal(BigInt(raised.op.maxFeePerGas), BigInt(first.op.maxFeePerGas) * 1125n / 1000n);
    assert.equal(BigInt(raised.op.maxPriorityFeePerGas), BigInt(first.op.maxPriorityFeePerGas) * 1125n / 1000n);
    assert.equal(raised.op.nonce, first.op.nonce);
    assert.equal(wallet.signatures.length, 2, 'the replacement is signed again');
    assert.deepEqual((await record()).userOpHashes, [first.hash, raised.hash], 'both hashes journaled');
    assert.ok(statuses.some(message => /raised by 12\.5%/.test(message)));

    // The bundler's own minimum tip (Pimlico's standard tier) is what is signed, not the chain's 2 gwei.
    const pimlico = await scenario();
    pimlico.bundler.pimlicoTip = 3n * GWEI;
    pimlico.bundler.autoMine = pimlico.closeBundle();
    assert.equal((await within(5_000, pimlico.withdraw('mutual'), 'pimlico tip')).status, 'closed');
    assert.equal(BigInt(pimlico.bundler.sent[0].op.maxPriorityFeePerGas), 3n * GWEI);
    assert.equal(BigInt(pimlico.bundler.sent[0].op.maxFeePerGas), 2n * pimlico.chain.baseFee + 3n * GWEI);
    // Rundler's suggestion above the paymaster's tip ceiling is clamped to it.
    const rundler = await scenario();
    rundler.bundler.rundlerTip = 9n * GWEI;
    rundler.bundler.autoMine = rundler.closeBundle();
    assert.equal((await within(5_000, rundler.withdraw('mutual'), 'rundler tip')).status, 'closed');
    assert.equal(BigInt(rundler.bundler.sent[0].op.maxPriorityFeePerGas), BigInt(VECTORS.policy.priority_fee_ceiling));
    assert.ok(rundler.bundler.calls.some(call => call.method === 'rundler_maxPriorityFeePerGas'));
});

test('a sponsored finalization included while no one followed it settles as the record’s own, not as a third party’s; a pending one is resumed without a prompt', async () => {
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    const finalizeKey = attemptsKeyOf(3, { noteId: NOTE_ID });
    const startEscape = ({ chain, S, nullifier, state }) => () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: escapeKey, sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
        }
    });
    const finalizeBundle = ({ chain, S, nullifier, state }) => ({
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S }),
            logs.settled(chain.paymaster, { key: finalizeKey, sender: S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID), received: wei(state.current_balance),
                charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: wei(state.current_balance) - wei(7_000_000) })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.vaultState.pending.delete(NOTE_ID);
            chainState.paymasterState.owed.set(S, 0n);
            chainState.paymasterState.escapeNotePlusOne.set(S, 0n);
            chainState.setBalance(S, 0n);
        }
    });

    // op_submitted, the tab stopped following; the bundle carrying it is mined meanwhile (the paymaster already paid the payee).
    const away = await scenario();
    away.bundler.autoMine = startEscape(away);
    const started = await within(5_000, away.withdraw('escape'), 'sponsored escape');
    away.client.gaslessTimingOverrides.giveUpAfterMs = 25;
    away.bundler.hold = true;
    away.bundler.autoMine = null;
    await assert.rejects(away.client.finalizeEscape(started.recordId, () => {}), { code: 'gasless_op_pending' });
    let saved = await away.record();
    assert.equal(saved.finalizeUserOpPhase, 'op_submitted');
    const finalizeHash = saved.finalizeUserOpHash;
    const sent = away.bundler.sent.length;
    const signatures = away.wallet.signatures.length;
    away.bundler.release();
    const mined = away.bundler.mine(finalizeHash, finalizeBundle(away));
    away.bundler.forgetReceipts = true;
    away.bundler.ops.clear();
    away.client.gaslessTimingOverrides.giveUpAfterMs = 0;
    await away.client.refresh();
    const statuses = [];
    const finalized = await within(5_000, away.client.finalizeEscape(started.recordId, message => statuses.push(message)), 'own finalization found');
    assert.equal(finalized.status, 'closed');
    assert.equal(finalized.transactionHash, mined.transactionHash);
    assert.equal(finalized.userOpHash, finalizeHash);
    assert.equal(finalized.amounts.chargedWei, wei(3_000_000).toString());
    assert.equal(finalized.amounts.owedPaidWei, wei(4_000_000).toString());
    assert.ok(!statuses.some(message => /someone else/.test(message)), statuses.join('\n'));
    assert.equal(away.bundler.sent.length, sent, 'nothing sent again');
    assert.equal(away.wallet.signatures.length, signatures, 'no prompt');
    saved = await away.record();
    assert.equal(saved.phase, 'closed_unconfirmed');
    assert.equal(saved.finalizeTransactionHash, mined.transactionHash);
    assert.equal(saved.finalizeUserOpPhase, 'settled');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.chargedWei, wei(3_000_000).toString());
    assert.equal(saved.paidOutWei, (wei(away.state.current_balance) - wei(7_000_000)).toString());

    // op_submitted and still pending: the next finalizeEscape takes the claim over and follows the same operation.
    const pending = await scenario();
    pending.bundler.autoMine = startEscape(pending);
    const startedAgain = await within(5_000, pending.withdraw('escape'), 'sponsored escape');
    pending.client.gaslessTimingOverrides.giveUpAfterMs = 25;
    pending.bundler.hold = true;
    pending.bundler.autoMine = null;
    await assert.rejects(pending.client.finalizeEscape(startedAgain.recordId, () => {}), { code: 'gasless_op_pending' });
    const journaled = await pending.record();
    const before = { sent: pending.bundler.sent.length, signatures: pending.wallet.signatures.length };
    pending.client.gaslessTimingOverrides.giveUpAfterMs = 0;
    pending.bundler.release();
    setTimeout(() => pending.bundler.mine(journaled.finalizeUserOpHash, finalizeBundle(pending)), 15);
    await pending.client.refresh();
    const resumed = await within(5_000, pending.client.finalizeEscape(startedAgain.recordId, () => {}), 'resumed finalization');
    assert.equal(resumed.status, 'closed');
    assert.equal(resumed.userOpHash, journaled.finalizeUserOpHash);
    assert.equal(pending.wallet.signatures.length, before.signatures, 'no second prompt');
    assert.equal(pending.bundler.sent.length, before.sent, 'not sent again while the bundler still holds it');
});

test('the direct-call fallback accepts the payout address the sponsored attempt named, and still pays the transit account', async () => {
    const { chain, bundler, wallet, client, withdraw, S, record, state } = await scenario({
        allow: ['eth_estimateGas', 'eth_getTransactionCount', 'eth_sendTransaction', 'eth_getTransactionReceipt', 'eth_call', 'eth_blockNumber']
    });
    bundler.unreachableMethods.add('eth_sendUserOperation');
    await assert.rejects(withdraw('mutual'), { code: 'bundler_unavailable' });
    // Another address is still refused.
    await assert.rejects(client.performWithdrawal('mutual', () => {}, { fees: 'wallet', destination: OTHER }), /already bound to a different destination/);
    assert.equal(wallet.sent.length, 0);
    const closeHash = `0x${'d2'.repeat(32)}`;
    wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        chain.head += 1;
        chain.receipts.set(closeHash, { transactionHash: closeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.mutualClose(VAULT, { noteId: BigInt(NOTE_ID), finalBalance: BigInt(state.current_balance), destination: S })] });
        chain.noteStatus(NOTE_ID, 3);
        chain.setBalance(S, wei(state.current_balance));
        return closeHash;
    };
    const direct = await within(5_000, client.performWithdrawal('mutual', () => {}, { fees: 'wallet', destination: PAYEE }), 'direct call naming Y');
    assert.equal(direct.status, 'closed');
    assert.equal(direct.transitAccount, S);
    assert.equal(direct.fundsWaitingInTransit, true);
    const plan = (await record()).preparedWithdrawal;
    assert.equal(wallet.sent[0].data, encodeWithdrawal(plan, 'mutual', S, VAULT, { conceded: plan.public_inputs.conceded }), 'the vault call still pays S');
});

test('an operation released before a re-proof is found by its stale hash from the block it was tracked at, not from the new operation’s', async () => {
    const { h, chain, bundler, wallet, client, withdraw, prepared, record, closeBundle } = await scenario();
    client.gaslessWithdrawalAttempts = 2;
    bundler.hold = true;
    // Op A is sent, then the expiry stop releases it; the second proof runs with the normal stop again.
    bundler.onSend = async () => { client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    // After the stop the released operation is followed until the bundler no longer knows it (§3.1); this bundler drops it.
    bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
    const mutate = h.worker.mutate;
    let exitProofs = 0;
    h.worker.mutate = plan => {
        mutate(plan);
        if (plan.mode === 'mutual') exitProofs += 1;
        if (exitProofs >= 2) {
            client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 60;
            bundler.onSend = null;
        }
    };
    // Op A lands after op C passed its dry runs, before C's journal reads its block; the chain moves on.
    let staleA = null;
    let minedA = null;
    const request = chain.request;
    chain.request = async payload => {
        if (payload.method === 'eth_blockNumber' && wallet.signatures.length === 2 && !minedA) {
            staleA = (await prepared()).staleUserOpHashes[0];
            minedA = bundler.mine(staleA, closeBundle()(null, staleA));
            chain.head += 3;
            bundler.failSend = { code: -32500, message: 'AA25 invalid account nonce' };
            bundler.forgetReceipts = true;
        }
        return request(payload);
    };
    runtime.exitRpc = () => chain.request;
    runtime.pinnedRpc = () => chain.request;
    const result = await within(5_000, withdraw('mutual'), 'stale inclusion found');
    assert.ok(minedA, 'op A was mined between C’s dry run and its journal');
    assert.equal(result.status, 'closed');
    assert.equal(result.transactionHash, minedA.transactionHash);
    assert.equal(result.userOpHash, staleA);
    assert.equal(wallet.signatures.length, 2, 'no third prompt: no rebuild of C');
    assert.equal(proofs(h, 'mutual').length, 2);
    const saved = await record();
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.transactionHash, minedA.transactionHash);
});

test('a second client of the runtime is refused while the first still follows the sponsored operation', async () => {
    const { bundler, wallet, client, withdraw, prepared, closeBundle } = await scenario();
    bundler.hold = true;
    const first = withdraw('mutual');
    const deadlineAt = Date.now() + 3_000;
    while ((await prepared())?.userOpPhase !== 'op_submitted') {
        assert.ok(Date.now() < deadlineAt, 'the first client submitted');
        await new Promise(resolve => setTimeout(resolve, 5));
    }
    const other = new ZkapiClient();
    for (const name of ['browserMode', 'config', 'wallet', 'refresh', 'connectWallet', 'walletAddress', 'checkEscapeDestination',
        'recoverFailedWithdrawalSubmission', 'submittedTransactionMetadata', 'assertBalanceNotClaimed', 'settleActiveLease']) other[name] = client[name];
    other.gaslessTimingOverrides = { ...client.gaslessTimingOverrides };
    const claimBefore = (await prepared()).submissionId;
    await assert.rejects(other.performWithdrawal('mutual', () => {}, { destination: PAYEE, fees: 'payout' }),
        error => error.code === 'withdrawal_wallet_pending' && /already awaiting MetaMask/.test(error.message));
    assert.equal((await prepared()).submissionId, claimBefore, 'the claim stays with the first client');
    assert.equal(wallet.signatures.length, 1);
    bundler.release();
    bundler.mine(bundler.sent[0].hash, closeBundle()(null, bundler.sent[0].hash));
    assert.equal((await within(5_000, first, 'the first client settles')).status, 'closed');
});

test('the paymaster’s time window is checked against the latest block before the prompt: AA24 in the unsigned dry run masks AA32', async () => {
    // A chain whose dry run behaves like EntryPoint v0.7.0: unsigned → AA24
    // (checked before the time range), signed out of range → AA32.
    const deadline = Math.floor(Date.now() / 1_000) - 3;
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    const finalizeKey = attemptsKeyOf(3, { noteId: NOTE_ID });
    const escapeOf = ({ chain, S, nullifier, state }) => () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: escapeKey, sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
        }
    });
    const finalizeOf = ({ chain, S, nullifier, state }) => () => ({
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S }),
            logs.settled(chain.paymaster, { key: finalizeKey, sender: S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID), received: wei(state.current_balance),
                charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: wei(state.current_balance) - wei(7_000_000) })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.vaultState.pending.delete(NOTE_ID);
            chainState.paymasterState.owed.set(S, 0n);
            chainState.paymasterState.escapeNotePlusOne.set(S, 0n);
        }
    });
    const notDue = chain => op => (op.signature.length && BigInt(op.callData.length) > 0n && chain.timestamp() < deadline
        && op.callData === encodeTransitWithdraw(encodeFinalizeEscape(NOTE_ID)) ? revertError(failedOpData('AA32 paymaster expired or not due')) : null);

    // The local clock is past the deadline, the latest block 9 s behind it; the
    // finalization waits for a block at the deadline, then prompts once.
    const lagging = await scenario();
    lagging.bundler.autoMine = escapeOf(lagging);
    const started = await within(5_000, lagging.withdraw('escape'), 'sponsored escape');
    // Block reads after the unsigned dry run: the chain reaches the deadline on the third.
    let unsignedDryRun = false;
    let blockReads = 0;
    lagging.chain.timestamp = () => (blockReads >= 3 ? deadline : deadline - 9);
    const request = lagging.chain.request;
    lagging.chain.request = async payload => {
        if (payload.method === 'eth_getBlockByNumber' && payload.params[0] === 'latest' && unsignedDryRun) blockReads += 1;
        return request(payload);
    };
    runtime.exitRpc = () => lagging.chain.request;
    runtime.pinnedRpc = () => lagging.chain.request;
    const lagDryRun = notDue(lagging.chain);
    lagging.chain.dryRun = op => {
        if (!op.signature.length) unsignedDryRun = true;
        return lagDryRun(op);
    };
    lagging.bundler.autoMine = finalizeOf(lagging);
    const statuses = [];
    const finalized = await within(5_000, lagging.client.finalizeEscape(started.recordId, message => statuses.push(message)), 'finalization after the chain reached the deadline');
    assert.equal(finalized.status, 'closed');
    assert.equal(lagging.wallet.signatures.length, 2, 'the escape, then one finalization signature');
    assert.ok(statuses.some(message => /Waiting for the chain to reach the end of the safety window/.test(message)));
    assert.ok(blockReads >= 3);

    // A chain that does not reach the deadline in time: refused before any prompt, never paymaster_time_window after one.
    const stuck = await scenario();
    stuck.bundler.autoMine = escapeOf(stuck);
    const stuckEscape = await within(5_000, stuck.withdraw('escape'), 'sponsored escape');
    stuck.chain.timestamp = () => deadline - 9;
    stuck.chain.dryRun = notDue(stuck.chain);
    stuck.client.gaslessTimingOverrides.notDueWaitMs = 30;
    await assert.rejects(within(5_000, stuck.client.finalizeEscape(stuckEscape.recordId, () => {}), 'not due'),
        error => error.code === 'escape_not_due' && error.data.validAfter === deadline);
    assert.equal(stuck.wallet.signatures.length, 1, 'no finalization prompt');
    assert.equal(stuck.bundler.sent.length, 1);
    assert.equal((await stuck.record()).finalizeUserOp ?? null, null, 'nothing journaled');

    // A close whose proof is already past validUntil − 60 s by the chain's clock (local clock behind): stopped before the prompt.
    const ahead = await scenario();
    ahead.client.gaslessWithdrawalAttempts = 1;
    ahead.chain.timestamp = () => Math.floor(Date.now() / 1_000) + 4 * 3_600;
    ahead.chain.dryRun = op => (op.signature.length ? revertError(failedOpData('AA32 paymaster expired or not due')) : null);
    await assert.rejects(within(5_000, ahead.withdraw('mutual'), 'chain past validUntil'), { code: 'gasless_op_expired' });
    assert.equal(ahead.wallet.signatures.length, 0, 'no prompt for an operation the EntryPoint would refuse');
    assert.equal(ahead.bundler.sent.length, 0);
});

test('a forward included while no one followed it is collected as the record’s own on the next collect, not reported as nothing to collect', async () => {
    const { chain, bundler, wallet, client, withdraw, S, record, closeKey, state } = await scenario();
    const vaultFailed = `0x${'c3076dea'}${word(0x20)}${word(4)}${'61a83aab'.padEnd(64, '0')}`;
    bundler.autoMine = () => ({
        success: false,
        revertReason: vaultFailed,
        extraLogs: [
            logs.sponsorshipFailed(chain.paymaster, { key: closeKey, sender: S, kind: 1n, noteId: BigInt(NOTE_ID), actualGasCost: 10n ** 15n }),
            logs.stranded(chain.paymaster, S)
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.setBalance(S, wei(state.current_balance));
            chainState.paymasterState.stranded.set(S, true);
        }
    });
    const result = await within(5_000, withdraw('mutual'), 'reverted execution');
    assert.equal(result.fundsWaitingInTransit, true);
    const recordId = (await record()).recordId;
    // The forward reaches the bundler; this client stops following it (op_submitted).
    bundler.autoMine = null;
    bundler.hold = true;
    client.gaslessTimingOverrides.giveUpAfterMs = 25;
    await assert.rejects(client.collectTransitBalance(recordId, () => {}), { code: 'gasless_op_pending' });
    let saved = await record();
    assert.equal(saved.forwardUserOpPhase, 'op_submitted');
    const forwardHash = saved.forwardUserOpHash;
    const sends = bundler.sent.length;
    const signatures = wallet.signatures.length;
    // Its bundle is mined while no one follows it: S is emptied to the payee.
    const forwardKey = attemptsKeyOf(4, { sender: S });
    bundler.release();
    const mined = bundler.mine(forwardHash, {
        success: true,
        extraLogs: [logs.settled(chain.paymaster, { key: forwardKey, sender: S, payee: PAYEE, kind: 4n, noteId: 0xffffffffn,
            received: wei(state.current_balance), charged: wei(300_000), owedPaid: 0n, paidOut: wei(state.current_balance) - wei(300_000) })],
        effects: chainState => { chainState.setBalance(S, 0n); chainState.paymasterState.stranded.set(S, false); }
    });
    bundler.forgetReceipts = true;
    bundler.ops.clear();
    client.gaslessTimingOverrides.giveUpAfterMs = 0;
    const collected = await within(5_000, client.collectTransitBalance(recordId, () => {}), 'the own forward is found');
    assert.equal(collected.status, 'collected');
    assert.equal(collected.transactionHash, mined.transactionHash);
    assert.equal(collected.userOpHash, forwardHash);
    assert.equal(collected.amounts.paidOutWei, (wei(state.current_balance) - wei(300_000)).toString());
    assert.equal(bundler.sent.length, sends, 'nothing sent again');
    assert.equal(wallet.signatures.length, signatures, 'no prompt');
    saved = await record();
    assert.equal(saved.forwardTransactionHash, mined.transactionHash);
    assert.equal(saved.forwardUserOpPhase, 'settled');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.paidOutWei, (wei(state.current_balance) - wei(300_000)).toString());
    assert.equal(saved.fundsWaitingInTransit, false);
    // Settled once: a further collect finds nothing (and does not settle the old forward again).
    await assert.rejects(client.collectTransitBalance(recordId, () => {}), { code: 'transit_balance_empty' });
});

test('after the expiry stop the released operation is followed before any replacement: it settles the withdrawal whether it lands while followed or during the re-proof', async () => {
    // (a) The bundler still holds op A after the stop; A is bundled while it is followed: no second proof, no second prompt.
    const held = await scenario();
    held.client.gaslessWithdrawalAttempts = 2;
    held.bundler.hold = true;
    held.bundler.onSend = async () => { held.client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    let minedA = null;
    held.bundler.onMethod = async method => {
        if (method === 'eth_getUserOperationByHash' && !minedA) {
            const hash = held.bundler.sent[0].hash;
            held.bundler.release();
            minedA = held.bundler.mine(hash, held.closeBundle()(null, hash));
            held.bundler.hold = true;
            held.bundler.forgetReceipts = true;
        }
    };
    const settled = await within(5_000, held.withdraw('mutual'), 'the released op lands while followed');
    assert.equal(settled.status, 'closed');
    assert.equal(settled.userOpHash, held.bundler.sent[0].hash);
    assert.equal(settled.transactionHash, minedA.transactionHash);
    assert.equal(proofs(held.h, 'mutual').length, 1, 'no re-proof');
    assert.equal(held.wallet.signatures.length, 1);
    assert.equal(held.bundler.sent.length, 1);
    assert.equal((await held.record()).payoutVerified, true);

    // (b) The bundler drops A (unknown), the plan is proved again, and A lands
    // from another mempool during the re-proof: the chain's dry run of a
    // replacement would now fail with NoteNotActive. A is found before any
    // replacement is built.
    const { h, chain, bundler, wallet, client, withdraw, record, closeBundle } = await scenario();
    client.gaslessWithdrawalAttempts = 2;
    bundler.hold = true;
    bundler.onSend = async () => { client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
    const mutate = h.worker.mutate;
    let exitProofs = 0;
    let landed = null;
    h.worker.mutate = plan => {
        mutate(plan);
        if (plan.mode === 'mutual') exitProofs += 1;
        if (exitProofs >= 2 && !landed) {
            client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 60;
            bundler.onSend = null;
            const staleA = bundler.sent[0].hash;
            bundler.release();
            landed = bundler.mine(staleA, closeBundle()(null, staleA));
            bundler.hold = true;
            bundler.forgetReceipts = true;
            chain.dryRun = () => revertError(failedOpData('AA33 reverted', '0x61a83aab'));
        }
    };
    const result = await within(5_000, withdraw('mutual'), 'the released op lands during the re-proof');
    assert.ok(landed);
    assert.equal(result.status, 'closed');
    assert.equal(result.userOpHash, bundler.sent[0].hash);
    assert.equal(result.transactionHash, landed.transactionHash);
    assert.equal(proofs(h, 'mutual').length, 2);
    assert.equal(wallet.signatures.length, 1, 'no replacement was signed');
    assert.equal(bundler.sent.length, 1, 'nor sent');
    const saved = await record();
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.transactionHash, landed.transactionHash);
});

test('another tab is refused while the first still follows an operation pending longer than the live window; a quiet claim is taken over', async () => {
    const asTab = async (owner, action) => {
        const saved = { ownerId: runtime.ownerId, live: runtime.liveGaslessClaims };
        runtime.ownerId = owner;
        runtime.liveGaslessClaims = new Set();
        try {
            return await action();
        } finally {
            runtime.ownerId = saved.ownerId;
            runtime.liveGaslessClaims = saved.live;
        }
    };
    const waitFor = async (predicate, label) => {
        const deadlineAt = Date.now() + 3_000;
        while (!(await predicate())) {
            assert.ok(Date.now() < deadlineAt, label);
            await new Promise(resolve => setTimeout(resolve, 5));
        }
    };
    // A close: tab A follows the op the bundler keeps pending for 4× the live window (the re-send window, 150 ms here).
    const { bundler, wallet, client, withdraw, prepared, closeBundle } = await scenario();
    client.gaslessTimingOverrides.resendAfterMs = 150;
    bundler.hold = true;
    const first = withdraw('mutual');
    try {
        await waitFor(async () => (await prepared())?.userOpPhase === 'op_submitted', 'tab A submitted');
        const { submissionId: claimBefore, userOpSubmittedAt } = await prepared();
        await new Promise(resolve => setTimeout(resolve, 600));
        const beat = await prepared();
        assert.ok(beat.userOpFollowedAt > userOpSubmittedAt + 400, 'the following tab keeps its claim live');
        await assert.rejects(asTab('tab-b', () => runtime.claimPreparedWithdrawalUserOp({ liveWindowMs: client.gaslessTiming.resendAfterMs })),
            error => error.code === 'withdrawal_wallet_pending');
        assert.equal((await prepared()).submissionId, claimBefore);
    } catch (error) {
        client.gaslessTimingOverrides.giveUpAfterMs = 1;
        await first.catch(() => null);
        throw error;
    }
    bundler.release();
    bundler.mine(bundler.sent[0].hash, closeBundle()(null, bundler.sent[0].hash));
    assert.equal((await within(5_000, first, 'tab A settles')).status, 'closed');
    assert.equal(wallet.signatures.length, 1);

    // A sponsored finalization: the record's journal beats the same way.
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    const escape = await scenario();
    escape.bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(escape.nullifier), finalBalance: BigInt(escape.state.current_balance), destination: escape.S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(escape.chain.paymaster, { sender: escape.S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(escape.chain.paymaster, { key: attemptsKeyOf(2, { noteId: NOTE_ID }), sender: escape.S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(escape.nullifier), finalBalance: BigInt(escape.state.current_balance), destination: escape.S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(escape.state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(escape.S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(escape.S, BigInt(NOTE_ID) + 1n);
        }
    });
    const started = await within(5_000, escape.withdraw('escape'), 'sponsored escape');
    escape.client.gaslessTimingOverrides.resendAfterMs = 150;
    escape.bundler.autoMine = null;
    escape.bundler.hold = true;
    const finalizing = escape.client.finalizeEscape(started.recordId, () => {}).catch(error => error);
    try {
        await waitFor(async () => (await escape.record())?.finalizeUserOpPhase === 'op_submitted', 'finalization submitted');
        const finalizeSubmittedAt = (await escape.record()).finalizeUserOpSubmittedAt;
        await new Promise(resolve => setTimeout(resolve, 600));
        assert.ok((await escape.record()).finalizeUserOpFollowedAt > finalizeSubmittedAt + 400, 'the finalization claim beats');
        await assert.rejects(asTab('tab-b', () => runtime.claimWithdrawalFinalization(started.recordId, {
            resumeUserOp: true, liveWindowMs: escape.client.gaslessTiming.resendAfterMs
        })), error => error.code === 'withdrawal_wallet_pending' && error.status === 409 && /already awaiting MetaMask/.test(error.message));
        // A second client of the same runtime calling finalizeEscape gets the same coded refusal.
        const second = new ZkapiClient();
        Object.assign(second, { browserMode: true, config: escape.client.config, wallet: escape.client.wallet, refresh: escape.client.refresh,
            connectWallet: escape.client.connectWallet, walletAddress: escape.client.walletAddress, gaslessTimingOverrides: escape.client.gaslessTimingOverrides });
        second.withdrawals = escape.client.withdrawals;
        await assert.rejects(second.finalizeEscape(started.recordId, () => {}),
            error => error.code === 'withdrawal_wallet_pending' && error.status === 409);
    } catch (error) {
        escape.client.gaslessTimingOverrides.giveUpAfterMs = 1;
        await finalizing;
        throw error;
    }
    // Tab A stops following; once its beat is older than the window, tab B takes the claim over without a prompt.
    escape.client.gaslessTimingOverrides.giveUpAfterMs = 1;
    const stopped = await within(5_000, finalizing, 'tab A gives up');
    assert.equal(stopped.code, 'gasless_op_pending');
    await new Promise(resolve => setTimeout(resolve, 300));
    const takeover = await asTab('tab-b', () => runtime.claimWithdrawalFinalization(started.recordId, {
        resumeUserOp: true, liveWindowMs: escape.client.gaslessTiming.resendAfterMs
    }));
    assert.equal(takeover.status, 'resumed');
    assert.equal(escape.wallet.signatures.length, 2, 'the escape and one finalization');
});

test('an inclusion the bundler names only under its own hash settles under the hash the EntryPoint emitted', async () => {
    // eth_sendUserOperation answers X; the op is bundled under the signed hash H, and the bundler serves its receipt by X only.
    const X = `0x${'77'.repeat(32)}`;
    const receiptOnlyUnderX = await scenario();
    receiptOnlyUnderX.bundler.returnHash = X;
    receiptOnlyUnderX.bundler.onSend = async (op, hash) => {
        const { bundler, closeBundle } = receiptOnlyUnderX;
        bundler.mine(hash, closeBundle()(null, hash));
        bundler.mined.set(X, bundler.mined.get(hash));
        bundler.mined.delete(hash);
        return null;
    };
    const result = await within(5_000, receiptOnlyUnderX.withdraw('mutual'), 'receipt under the bundler hash');
    const H = receiptOnlyUnderX.bundler.sent[0].hash;
    assert.equal(result.status, 'closed');
    assert.equal(result.userOpHash, H, 'settled under the emitted hash, not the bundler’s');
    assert.equal((await receiptOnlyUnderX.record()).userOpHash, H);
    assert.ok(receiptOnlyUnderX.bundler.calls.some(call => call.method === 'eth_getUserOperationReceipt' && low(call.params[0]) === X),
        'the inclusion came from the receipt under X');
    assert.equal(receiptOnlyUnderX.wallet.signatures.length, 1);

    // After the expiry stop: the released op is followed, and the bundler names its bundle by X only (eth_getUserOperationByHash).
    const byHashUnderX = await scenario();
    const { bundler, client, closeBundle } = byHashUnderX;
    client.gaslessWithdrawalAttempts = 2;
    bundler.returnHash = X;
    bundler.hold = true;
    bundler.forgetReceipts = true;
    bundler.onSend = async () => { client.gaslessTimingOverrides.stopBeforeValidUntilSeconds = 10_800 + 60; };
    let mined = null;
    bundler.onMethod = async method => {
        if (method !== 'eth_getUserOperationByHash' || mined) return;
        const hash = bundler.sent[0].hash;
        mined = bundler.mine(hash, closeBundle()(null, hash));
        bundler.ops.set(X, bundler.ops.get(hash));
        bundler.mined.set(X, bundler.mined.get(hash));
        bundler.mined.delete(hash);
    };
    const released = await within(5_000, byHashUnderX.withdraw('mutual'), 'released op named by X');
    assert.equal(released.status, 'closed');
    assert.equal(released.userOpHash, bundler.sent[0].hash);
    assert.equal(released.transactionHash, mined.transactionHash);
    assert.equal(proofs(byHashUnderX.h, 'mutual').length, 1, 'no re-proof: the released op settled');
});

test('a proof that expires while the signature prompt is open (AA32 in the signed dry run) is proved again', async () => {
    const { h, chain, bundler, wallet, client, withdraw, closeBundle } = await scenario();
    client.gaslessWithdrawalAttempts = 3;
    bundler.autoMine = closeBundle();
    // The latest block is inside the window when the prompt opens; the chain passes validUntil once the first signature returns.
    let pastValidUntil = false;
    const request = wallet.request.bind(wallet);
    wallet.request = async payload => {
        const answer = await request(payload);
        if (payload.method === 'personal_sign' && wallet.signatures.length === 1) pastValidUntil = true;
        return answer;
    };
    chain.dryRun = op => {
        if (!op.signature.length || !pastValidUntil) return null;
        pastValidUntil = false;
        return revertError(failedOpData('AA32 paymaster expired or not due'));
    };
    const result = await within(5_000, withdraw('mutual'), 'expiry during the prompt');
    assert.equal(result.status, 'closed');
    assert.equal(proofs(h, 'mutual').length, 2, 'proved again after the expiry');
    assert.equal(wallet.signatures.length, 2);
    assert.equal(bundler.sent.length, 1, 'the expired op was never sent');
});

test('an operation that lands while its fee-bumped replacement is signed settles the withdrawal; a canceled bump prompt leaves it journaled as sent', async () => {
    // The bundler accepts A, then forgets it; the identical re-send is refused for its fee; A is mined while the bump prompt is open.
    const landed = await scenario();
    {
        const { chain, bundler, wallet, withdraw, record, closeBundle } = landed;
        bundler.hold = true;
        let sends = 0;
        bundler.onSend = async () => {
            sends += 1;
            return sends === 2 ? { error: { code: -32602, message: 'replacement underpriced: fee too low' } } : null;
        };
        bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
        const request = wallet.request.bind(wallet);
        let minedA = null;
        wallet.request = async payload => {
            if (payload.method === 'personal_sign' && wallet.signatures.length === 1 && !minedA) {
                const A = bundler.sent[0].hash;
                minedA = bundler.mine(A, closeBundle()(null, A));
                bundler.forgetReceipts = true;
                // The EntryPoint now refuses the replacement at A's nonce.
                chain.dryRun = op => (op.signature.length ? revertError(failedOpData('AA25 invalid account nonce')) : null);
            }
            return request(payload);
        };
        const result = await within(5_000, withdraw('mutual'), 'A lands during the bump prompt');
        const A = bundler.sent[0].hash;
        assert.equal(result.status, 'closed');
        assert.equal(result.userOpHash, A);
        assert.equal(result.transactionHash, minedA.transactionHash);
        assert.equal(wallet.signatures.length, 2, 'A, then the replacement that was never sent');
        assert.deepEqual(bundler.sent.map(item => item.hash), [A, A], 'A and its identical re-send; no replacement');
        assert.equal((await record()).userOpHash, A);
    }

    // The same bump prompt canceled while A is still pending: refused as sent, A stays journaled for the background check.
    const canceled = await scenario();
    {
        const { bundler, wallet, withdraw, prepared } = canceled;
        bundler.hold = true;
        let sends = 0;
        bundler.onSend = async () => {
            sends += 1;
            return sends === 2 ? { error: { code: -32602, message: 'replacement underpriced: fee too low' } } : null;
        };
        bundler.onMethod = async method => { if (method === 'eth_getUserOperationByHash') bundler.ops.clear(); };
        const request = wallet.request.bind(wallet);
        wallet.request = async payload => {
            if (payload.method === 'personal_sign' && wallet.signatures.length === 1) wallet.rejectSign = true;
            return request(payload);
        };
        const failure = await within(5_000, withdraw('mutual').catch(error => error), 'bump prompt canceled');
        assert.ok(failure instanceof Error);
        assert.equal(failure.userOpSent, true);
        assert.equal(failure.withdrawalNeedsAction, true);
        const journal = await prepared();
        assert.equal(journal.userOpHash, bundler.sent[0].hash, 'A is still the journaled operation');
        assert.equal(journal.userOpPhase, 'op_submitted');
    }
});

test('a bundler estimate asking for more preVerificationGas than reserved, within the cap, is what is signed', async () => {
    const { bundler, wallet, withdraw, closeBundle } = await scenario();
    const wanted = 140_000n;
    assert.ok(wanted <= BigInt(VECTORS.gas_policy.pvg_cap));
    bundler.estimate = { preVerificationGas: `0x${wanted.toString(16)}` };
    bundler.autoMine = closeBundle();
    const result = await within(5_000, withdraw('mutual'), 'higher preVerificationGas estimate');
    assert.equal(result.status, 'closed');
    assert.equal(BigInt(bundler.sent[0].op.preVerificationGas), wanted);
    assert.equal(wallet.signatures.length, 1, 'rebuilt before the prompt');
});

// Phase D: recovery of an existing record must not depend on the current
// profile's gasless pins. `gasless: null` (the paymaster's retirement) or
// pins naming another paymaster stop sponsored recovery with
// gasless_record_not_pinned; the sweep, the credit claim and the
// wallet-paid finalization use the addresses journaled with the record.
const WALLET_SENDS = ['eth_estimateGas', 'eth_getTransactionCount', 'eth_sendTransaction', 'eth_getTransactionReceipt', 'eth_call', 'eth_blockNumber'];
const OTHER_PAYMASTER = `0x${'7e'.repeat(20)}`;

function retireProfile({ paymaster = null } = {}) {
    const trusted = runtime.browserConfig.trusted_deployment;
    runtime.browserConfig.trusted_deployment = {
        ...trusted,
        gasless: paymaster ? { ...trusted.gasless, withdrawal_paymaster_address: paymaster } : null
    };
    assert.equal(paymaster ? runtime.gaslessPins().paymaster : runtime.gaslessPins(), paymaster ? paymaster : null);
}

test('a new sponsored withdrawal after the profile retired its pins is refused with gasless_unavailable, not gasless_record_not_pinned', async () => {
    const s = await scenario({ allow: WALLET_SENDS });
    retireProfile();
    await s.client.refresh();
    for (const mode of ['mutual', 'escape']) {
        await assert.rejects(s.client.withdraw(mode, () => {}, { fees: 'payout' }), error => error.code === 'gasless_unavailable'
            && error.data.reason === 'not_pinned', mode);
    }
    assert.equal(s.bundler.sent.length, 0);
    assert.equal(s.wallet.signatures.length, 0);
});

/** The reverted-execution scenario up to the payout stranded in S (no forward yet). */
async function strandedTransit() {
    const s = await scenario({ allow: WALLET_SENDS });
    const vaultFailed = `0x${'c3076dea'}${word(0x20)}${word(4)}${'61a83aab'.padEnd(64, '0')}`;
    s.bundler.autoMine = () => ({
        success: false,
        revertReason: vaultFailed,
        extraLogs: [
            logs.sponsorshipFailed(s.chain.paymaster, { key: s.closeKey, sender: s.S, kind: 1n, noteId: BigInt(NOTE_ID), actualGasCost: 10n ** 15n }),
            logs.stranded(s.chain.paymaster, s.S)
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.setBalance(s.S, wei(s.state.current_balance));
            chainState.paymasterState.stranded.set(s.S, true);
        }
    });
    const result = await within(5_000, s.withdraw('mutual'), 'reverted execution');
    assert.equal(result.fundsWaitingInTransit, true);
    return s;
}

/** The wallet answers the sweep (and the account's creation first, when S has no code). */
function answerSweep(s) {
    const createHash = `0x${'ca'.repeat(32)}`;
    const sweepHash = `0x${'5a'.repeat(32)}`;
    s.wallet.onSend = transaction => {
        if (low(transaction.to) === s.chain.factory) {
            assert.equal(transaction.data, encodeCreateAccount(OWNER, PAYEE));
            s.chain.receipts.set(createHash, { transactionHash: createHash, blockNumber: '0x600', status: '0x1',
                logs: [logs.accountCreated(s.chain.factory, { account: s.S, owner: OWNER, payee: PAYEE })] });
            s.chain.setCode(s.S, '0x3660');
            return createHash;
        }
        assert.equal(low(transaction.to), s.S);
        assert.equal(transaction.data, encodeSweep());
        s.chain.receipts.set(sweepHash, { transactionHash: sweepHash, blockNumber: '0x601', status: '0x1',
            logs: [logs.collected(s.chain.paymaster, { sender: s.S, payee: PAYEE, received: wei(s.state.current_balance), owedPaid: 0n,
                paidOut: wei(s.state.current_balance) })] });
        s.chain.setBalance(s.S, 0n);
        return sweepHash;
    };
    return sweepHash;
}

test('a retired profile (gasless: null) refuses the sponsored collect with gasless_record_not_pinned and still sweeps from the journaled contracts', async () => {
    const s = await strandedTransit();
    const saved = await s.record();
    const sent = s.bundler.sent.length;
    retireProfile();
    await assert.rejects(s.client.collectTransitBalance(saved.recordId, () => {}), error => error.code === 'gasless_record_not_pinned'
        && error.data.reason === 'not_pinned' && error.data.paymaster === s.chain.paymaster && error.data.factory === s.chain.factory
        && error.data.alternatives.includes('sweepTransit'));
    // finalizeEscape's forward branch of a closed record is the same sponsored recovery.
    await assert.rejects(s.client.finalizeEscape(saved.recordId, () => {}), { code: 'gasless_record_not_pinned' });
    const sweepHash = answerSweep(s);
    const swept = await within(5_000, s.client.sweepTransit(saved.recordId, () => {}), 'sweep under a retired profile');
    assert.equal(swept.status, 'swept');
    assert.equal(swept.transactionHash, sweepHash);
    assert.equal(swept.amounts.paidOutWei, wei(s.state.current_balance).toString());
    // The getAddress check went to the journaled factory through the read RPC.
    assert.ok(s.chain.calls.some(call => call.method === 'eth_call' && low(call.params[0].to) === s.chain.factory
        && call.params[0].data.startsWith(`0x${GASLESS_ABI.getAddress}`)));
    const after = await s.record();
    assert.equal(after.fundsWaitingInTransit, false);
    assert.equal(after.payoutVerified, true);
    assert.equal(after.sweepTransactionHash, sweepHash);
    assert.equal(s.bundler.sent.length, sent, 'nothing went to the bundler');
});

test('a profile naming another paymaster refuses sponsored recovery the same way; the sweep keeps the journaled paymaster', async () => {
    const s = await strandedTransit();
    const saved = await s.record();
    retireProfile({ paymaster: OTHER_PAYMASTER });
    await assert.rejects(s.client.collectTransitBalance(saved.recordId, () => {}), error => error.code === 'gasless_record_not_pinned'
        && error.data.reason === 'pins_mismatch' && error.data.pinnedPaymaster === OTHER_PAYMASTER && error.data.paymaster === s.chain.paymaster);
    answerSweep(s);
    const swept = await within(5_000, s.client.sweepTransit(saved.recordId, () => {}), 'sweep under another paymaster');
    assert.equal(swept.status, 'swept');
    assert.ok(s.wallet.sent.every(transaction => low(transaction.to) !== OTHER_PAYMASTER));
});

test('a sweep is refused before any prompt when the journaled factory derives another account', async () => {
    const s = await strandedTransit();
    const saved = await s.record();
    retireProfile();
    // An edited journal: the factory derives the real S for (owner, payee), not this one.
    await store.updateBrowserWithdrawal(saved.recordId, { transit: { ...saved.transit, account: `0x${'5d'.repeat(20)}` } });
    await assert.rejects(s.client.sweepTransit(saved.recordId, () => {}), error => error.code === 'gasless_unavailable'
        && error.data.reason === 'gasless_deployment_mismatch');
    assert.equal(s.wallet.sent.length, 0);
});

test('a retired profile still delivers a credited payout from the journaled paymaster', async () => {
    const { chain, bundler, wallet, client, withdraw, record, closeBundle, state } = await scenario({ allow: ['eth_estimateGas', 'eth_sendTransaction', 'eth_getTransactionReceipt'] });
    bundler.autoMine = closeBundle({ credited: true });
    assert.equal((await within(5_000, withdraw('mutual'), 'credited payout')).paymasterCredited, true);
    retireProfile();
    const credited = wei(state.current_balance) - wei(5_000_000);
    const claimHash = `0x${'c1'.repeat(32)}`;
    wallet.onSend = () => {
        chain.receipts.set(claimHash, { transactionHash: claimHash, blockNumber: '0x500', status: '0x1',
            logs: [logs.creditClaimed(chain.paymaster, PAYEE, credited)] });
        chain.paymasterState.credits.set(low(PAYEE), 0n);
        return claimHash;
    };
    const claimed = await client.claimGaslessCredit(PAYEE, () => {});
    assert.equal(claimed.status, 'claimed');
    assert.equal(claimed.paymaster, chain.paymaster);
    assert.equal(claimed.amount, credited.toString());
    assert.equal(low(wallet.sent[0].to), chain.paymaster);
    assert.equal(wallet.sent[0].data, encodeClaimCredit(PAYEE));
    const saved = await record();
    assert.equal(saved.paymasterCredited, false);
    assert.equal(saved.creditClaimTransactionHash, claimHash);
    assert.deepEqual(await client.claimGaslessCredit(PAYEE, () => {}), { status: 'nothing_to_claim', payee: PAYEE, amount: '0' });
});

for (const pinned of [null, OTHER_PAYMASTER]) test(`${pinned ? 'a profile naming another paymaster' : 'a retired profile'} refuses the sponsored finalization of a pending sponsored escape and finalizes it from the wallet`, async () => {
    const s = await scenario({ allow: WALLET_SENDS });
    const { chain, bundler, client, withdraw, S, nullifier, record, state } = s;
    const escapeKey = attemptsKeyOf(2, { noteId: NOTE_ID });
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: escapeKey, sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
        }
    });
    const started = await within(5_000, withdraw('escape'), 'sponsored escape');
    assert.equal(started.status, 'pending_withdrawal');
    const sent = bundler.sent.length;
    retireProfile({ paymaster: pinned });
    await client.refresh();
    await assert.rejects(client.finalizeEscape(started.recordId, () => {}), error => error.code === 'gasless_record_not_pinned'
        && error.data.reason === (pinned ? 'pins_mismatch' : 'not_pinned')
        && error.data.alternatives.includes("finalizeEscape({ fees: 'wallet' })")
        && !error.data.alternatives.some(alternative => alternative.startsWith('withdraw(')), 'the escape is on chain: no wallet-paid exit is named');
    assert.equal(bundler.sent.length, sent);
    const finalizeHash = `0x${'f1'.repeat(32)}`;
    s.wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        assert.equal(transaction.data, encodeFinalizeEscape(NOTE_ID));
        chain.head += 1;
        chain.receipts.set(finalizeHash, { transactionHash: finalizeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S })] });
        chain.noteStatus(NOTE_ID, 3);
        chain.vaultState.pending.delete(NOTE_ID);
        chain.setBalance(S, wei(state.current_balance));
        return finalizeHash;
    };
    const finalized = await within(5_000, client.finalizeEscape(started.recordId, () => {}, { fees: 'wallet' }), 'wallet finalization under a retired profile');
    assert.equal(finalized.status, 'closed');
    assert.equal(finalized.fundsWaitingInTransit, true);
    assert.equal(finalized.transitAccount, S);
    assert.equal(s.wallet.sent.length, 1);
    const saved = await record();
    assert.equal(saved.fundsWaitingInTransit, true);
    assert.equal(saved.payoutVerified, false);
    assert.equal(bundler.sent.length, sent, 'nothing went to the bundler');
});

/** A sponsored escape whose initiation lands (deadline passed) and whose sponsored finalization the tab then stopped following (op_submitted). */
async function interruptedSponsoredFinalization() {
    const s = await scenario({ allow: WALLET_SENDS });
    const { chain, bundler, client, withdraw, S, nullifier, state } = s;
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    bundler.autoMine = () => ({
        success: true,
        extraLogs: [
            logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S, challengeDeadline: BigInt(deadline) }),
            logs.escapeInitiationOwed(chain.paymaster, { sender: S, noteId: BigInt(NOTE_ID), owedWei: wei(4_000_000) }),
            logs.settled(chain.paymaster, { key: attemptsKeyOf(2, { noteId: NOTE_ID }), sender: S, payee: PAYEE, kind: 2n, noteId: BigInt(NOTE_ID), received: 0n, charged: wei(4_000_000), owedPaid: 0n, paidOut: 0n })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 2);
            chainState.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S,
                challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
            chainState.paymasterState.owed.set(S, wei(4_000_000));
            chainState.paymasterState.escapeNotePlusOne.set(S, BigInt(NOTE_ID) + 1n);
        }
    });
    const started = await within(5_000, withdraw('escape'), 'sponsored escape');
    client.gaslessTimingOverrides.giveUpAfterMs = 25;
    bundler.hold = true;
    bundler.autoMine = null;
    await assert.rejects(client.finalizeEscape(started.recordId, () => {}), { code: 'gasless_op_pending' });
    const saved = await s.record();
    assert.equal(saved.finalizeUserOpPhase, 'op_submitted');
    assert.ok(saved.finalizeSubmissionId && saved.finalizeUserOp && saved.finalizeUserOpHash);
    client.gaslessTimingOverrides.giveUpAfterMs = 0;
    return { ...s, recordId: started.recordId, finalizeHash: saved.finalizeUserOpHash };
}

/** The bundle of the sponsored finalization: the vault pays S, the paymaster settles the debt and pays the payee. */
function sponsoredFinalizeBundle({ chain, S, nullifier, state }) {
    return {
        success: true,
        extraLogs: [
            logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S }),
            logs.settled(chain.paymaster, { key: attemptsKeyOf(3, { noteId: NOTE_ID }), sender: S, payee: PAYEE, kind: 3n, noteId: BigInt(NOTE_ID), received: wei(state.current_balance),
                charged: wei(3_000_000), owedPaid: wei(4_000_000), paidOut: wei(state.current_balance) - wei(7_000_000) })
        ],
        effects: chainState => {
            chainState.noteStatus(NOTE_ID, 3);
            chainState.vaultState.pending.delete(NOTE_ID);
            chainState.paymasterState.owed.set(S, 0n);
            chainState.setBalance(S, 0n);
        }
    };
}

test('a sponsored finalization in flight when the profile retired its pins is released after the re-send window, and the wallet then finalizes', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, client, recordId, S, chain, state, nullifier } = s;
    const sent = bundler.sent.length;
    retireProfile();
    await client.refresh();
    // The sponsored resume is refused and names the wallet-paid finalization.
    await assert.rejects(client.finalizeEscape(recordId, () => {}), error => error.code === 'gasless_record_not_pinned'
        && error.data.alternatives.includes("finalizeEscape({ fees: 'wallet' })"));
    // Within the re-send window the operation may still land: the wallet waits, nothing is prompted.
    await assert.rejects(client.finalizeEscape(recordId, () => {}, { fees: 'wallet' }), error => error.code === 'user_op_pending'
        && error.data.userOpHash === s.finalizeHash && error.data.retryAfterMs > 0);
    assert.equal(s.wallet.sent.length, 0);
    assert.ok((await s.record()).finalizeSubmissionId, 'the claim is kept while the operation may land');
    // Long after (the tab was closed): released, then finalized from the wallet.
    client.gaslessTimingOverrides.resendAfterMs = 1;
    await new Promise(resolve => setTimeout(resolve, 5));
    const finalizeHash = `0x${'f2'.repeat(32)}`;
    s.wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        assert.equal(transaction.data, encodeFinalizeEscape(NOTE_ID));
        chain.head += 1;
        chain.receipts.set(finalizeHash, { transactionHash: finalizeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S })] });
        chain.noteStatus(NOTE_ID, 3);
        chain.vaultState.pending.delete(NOTE_ID);
        chain.setBalance(S, wei(state.current_balance));
        return finalizeHash;
    };
    const statuses = [];
    const finalized = await within(5_000, client.finalizeEscape(recordId, message => statuses.push(message), { fees: 'wallet' }),
        'wallet finalization after the release');
    assert.equal(finalized.status, 'closed');
    assert.equal(finalized.fundsWaitingInTransit, true);
    assert.ok(statuses.some(message => /was released/.test(message)), statuses.join('\n'));
    assert.equal(s.wallet.sent.length, 1);
    assert.equal(bundler.sent.length, sent, 'nothing went to the bundler');
    const saved = await s.record();
    assert.equal(saved.finalizeTransactionHash, finalizeHash);
    assert.equal(saved.finalizeUserOp ?? null, null);
    assert.equal(saved.finalizeUserOpPhase, 'released');
    assert.equal(saved.finalizeUserOpHash, s.finalizeHash, 'its hash stays journaled for a late inclusion');
    assert.equal(saved.fundsWaitingInTransit, true);
});

test('a sponsored finalization in flight when the profile retired its pins that landed meanwhile is recorded, not finalized again from the wallet', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, client, recordId } = s;
    retireProfile({ paymaster: OTHER_PAYMASTER });
    bundler.release();
    const mined = bundler.mine(s.finalizeHash, sponsoredFinalizeBundle(s));
    bundler.forgetReceipts = true;
    bundler.ops.clear();
    await client.refresh();
    const sent = bundler.sent.length;
    const result = await within(5_000, client.finalizeEscape(recordId, () => {}, { fees: 'wallet' }), 'the landed finalization');
    assert.deepEqual(result, { status: 'finalizing', recordId, sponsored: true, transactionHash: mined.transactionHash, userOpHash: s.finalizeHash });
    assert.equal(s.wallet.sent.length, 0, 'nothing signed');
    assert.equal(bundler.sent.length, sent);
    const saved = await s.record();
    assert.equal(saved.finalizeTransactionHash, mined.transactionHash);
    assert.equal(saved.finalizeUserOpPhase, 'settled');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.chargedWei, wei(3_000_000).toString());
});

/** The bundle of a sponsored finalization whose vault call reverted (SponsorshipFailed): S is charged nothing more, the escape stays as it was. */
function revertedFinalizeBundle({ chain, S }, effects = () => {}) {
    const vaultFailed = `0x${'c3076dea'}${word(0x20)}${word(4)}${'61a83aab'.padEnd(64, '0')}`;
    return {
        success: false,
        revertReason: vaultFailed,
        extraLogs: [logs.sponsorshipFailed(chain.paymaster, { key: attemptsKeyOf(3, { noteId: NOTE_ID }), sender: S, kind: 3n, noteId: BigInt(NOTE_ID), actualGasCost: 10n ** 15n })],
        effects
    };
}

test('a sponsored finalization in flight when the profile retired its pins that landed reverted is released, and the wallet then finalizes', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, client, recordId, chain, S, state, nullifier } = s;
    retireProfile();
    bundler.release();
    const mined = bundler.mine(s.finalizeHash, revertedFinalizeBundle(s));
    bundler.forgetReceipts = true;
    bundler.ops.clear();
    await client.refresh();
    const sent = bundler.sent.length;
    const finalizeHash = `0x${'f3'.repeat(32)}`;
    s.wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        assert.equal(transaction.data, encodeFinalizeEscape(NOTE_ID));
        chain.head += 1;
        chain.receipts.set(finalizeHash, { transactionHash: finalizeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.escapeFinalized(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: S })] });
        chain.noteStatus(NOTE_ID, 3);
        chain.vaultState.pending.delete(NOTE_ID);
        chain.setBalance(S, wei(state.current_balance));
        return finalizeHash;
    };
    const statuses = [];
    const finalized = await within(5_000, client.finalizeEscape(recordId, message => statuses.push(message), { fees: 'wallet' }),
        'wallet finalization after a reverted sponsored one');
    assert.equal(finalized.status, 'closed', 'the wallet path ran, not a sponsored "finalizing"');
    assert.equal(finalized.fundsWaitingInTransit, true);
    assert.ok(statuses.some(message => message.includes('reverted')), statuses.join('\n'));
    assert.equal(s.wallet.sent.length, 1);
    assert.equal(bundler.sent.length, sent, 'nothing went to the bundler');
    const saved = await s.record();
    assert.equal(saved.finalizeTransactionHash, finalizeHash, 'the bundle transaction is never this record\'s finalization');
    assert.ok(!(saved.finalizeTransactionHashes || []).includes(mined.transactionHash));
    assert.equal(saved.finalizeUserOp ?? null, null);
    assert.equal(saved.finalizeUserOpPhase, 'reverted');
    assert.equal(saved.finalizeUserOpRevertedTransactionHash, mined.transactionHash);
    assert.equal(saved.finalizeUserOpHash, s.finalizeHash, 'its hash stays journaled');
    // The background pass does not record the reverted inclusion again.
    assert.equal(client.recordUserOpUnresolved(saved, 'finalize'), false);
});

test('a sponsored finalization in flight when the profile retired its pins that reverted because a third party finalized first leaves the payout to sweep', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, client, recordId, S, state } = s;
    retireProfile({ paymaster: OTHER_PAYMASTER });
    bundler.release();
    // A third party finalized the escape (the vault paid S); the sponsored finalization then reverted.
    bundler.mine(s.finalizeHash, revertedFinalizeBundle(s, chainState => {
        chainState.noteStatus(NOTE_ID, 3);
        chainState.vaultState.pending.delete(NOTE_ID);
        chainState.setBalance(S, wei(state.current_balance));
    }));
    bundler.forgetReceipts = true;
    bundler.ops.clear();
    await client.refresh();
    const sent = bundler.sent.length;
    const result = await within(5_000, client.finalizeEscape(recordId, () => {}, { fees: 'wallet' }), 'third party finalized first');
    assert.equal(result.status, 'closed');
    assert.equal(result.finalizedByThirdParty, true);
    assert.equal(result.fundsWaitingInTransit, true);
    assert.equal(result.transitAccount, S);
    assert.equal(s.wallet.sent.length, 0, 'nothing signed');
    assert.equal(bundler.sent.length, sent);
    const saved = await s.record();
    assert.ok(['closed', 'closed_unconfirmed'].includes(saved.phase), saved.phase);
    assert.equal(saved.fundsWaitingInTransit, true);
    assert.equal(saved.finalizeUserOpPhase, 'reverted');
    assert.equal(saved.finalizeSubmissionId ?? null, null);
    assert.equal(saved.finalizeTransactionHash ?? null, null);
});

test('the background pass records a sponsored finalization and a forward that landed after the profile retired its pins', async () => {
    // A finalization: the escape sync's pre-pass reads the journaled EntryPoint and closes the record from its settlement.
    const escape = await interruptedSponsoredFinalization();
    retireProfile();
    escape.bundler.release();
    const mined = escape.bundler.mine(escape.finalizeHash, sponsoredFinalizeBundle(escape));
    escape.bundler.forgetReceipts = true;
    await escape.client.refresh();
    const warnings = [];
    const warn = console.warn;
    console.warn = (...args) => warnings.push(args.map(String).join(' '));
    try {
        await within(5_000, escape.client.syncEscapeWithdrawals(() => {}), 'escape sync under a retired profile');
    } finally {
        console.warn = warn;
    }
    assert.deepEqual(warnings.filter(line => /sponsored operations/.test(line)), []);
    const finalized = await escape.record();
    assert.equal(finalized.finalizeTransactionHash, mined.transactionHash);
    assert.equal(finalized.phase, 'closed_unconfirmed');
    assert.equal(finalized.finalizeUserOpPhase, 'settled');
    assert.equal(finalized.payoutVerified, true);
    assert.equal(finalized.paidOutWei, (wei(escape.state.current_balance) - wei(7_000_000)).toString());

    // A forward: submitted, the tab closed, included, then the profile retired.
    const s = await strandedTransit();
    const { chain, bundler, client, S, state } = s;
    const recordId = (await s.record()).recordId;
    bundler.autoMine = null;
    bundler.hold = true;
    client.gaslessTimingOverrides.giveUpAfterMs = 25;
    await assert.rejects(client.collectTransitBalance(recordId, () => {}), { code: 'gasless_op_pending' });
    const forwardHash = (await s.record()).forwardUserOpHash;
    bundler.release();
    const forwarded = bundler.mine(forwardHash, {
        success: true,
        extraLogs: [logs.settled(chain.paymaster, { key: attemptsKeyOf(4, { sender: S }), sender: S, payee: PAYEE, kind: 4n, noteId: 0xffffffffn,
            received: wei(state.current_balance), charged: wei(300_000), owedPaid: 0n, paidOut: wei(state.current_balance) - wei(300_000) })],
        effects: chainState => { chainState.setBalance(S, 0n); chainState.paymasterState.stranded.set(S, false); }
    });
    bundler.forgetReceipts = true;
    retireProfile();
    await within(5_000, client.recoverGaslessRecordOperations(), 'background pass under a retired profile');
    const saved = await s.record();
    assert.equal(saved.forwardTransactionHash, forwarded.transactionHash);
    assert.equal(saved.forwardUserOpPhase, 'settled');
    assert.equal(saved.payoutVerified, true);
    assert.equal(saved.fundsWaitingInTransit, false);
    assert.equal(saved.paidOutWei, (wei(state.current_balance) - wei(300_000)).toString());
});

test('a sponsored close in flight when the profile retired its pins settles from its inclusion, or is released after the re-send window for the wallet-paid close', async () => {
    const interrupted = async () => {
        const s = await scenario({ allow: WALLET_SENDS });
        s.client.gaslessTimingOverrides.giveUpAfterMs = 25;
        s.bundler.hold = true;
        await assert.rejects(s.withdraw('mutual'), { code: 'gasless_op_pending' });
        assert.equal((await s.prepared()).userOpPhase, 'op_submitted');
        s.client.gaslessTimingOverrides.giveUpAfterMs = 0;
        return s;
    };
    // Included after the retirement: the background sync finds it through the journaled EntryPoint and settles it.
    const landed = await interrupted();
    const journal = await landed.prepared();
    retireProfile();
    landed.bundler.release();
    landed.bundler.mine(journal.userOpHash, landed.closeBundle()(null, journal.userOpHash));
    landed.bundler.ops.clear();
    landed.bundler.forgetReceipts = true;
    await landed.client.refresh();
    const sent = landed.bundler.sent.length;
    assert.equal((await within(5_000, landed.client.syncWithdrawal(() => {}), 'sync under a retired profile')).status, 'closed');
    const closed = await landed.record();
    assert.equal(closed.phase, 'closed_unconfirmed');
    assert.equal(closed.transactionHash, landed.bundler.mined.get(journal.userOpHash).transactionHash);
    assert.equal(closed.payoutVerified, true);
    assert.equal(landed.bundler.sent.length, sent, 'nothing re-sent');

    // Not included: within the re-send window it stays journaled; after it, the sync releases it and the wallet pays the close.
    const s = await interrupted();
    retireProfile({ paymaster: OTHER_PAYMASTER });
    await s.client.refresh();
    const sentBefore = s.bundler.sent.length;
    await within(5_000, s.client.syncWithdrawal(() => {}), 'sync within the window');
    assert.equal((await s.prepared()).userOpPhase, 'op_submitted', 'kept while it may still land');
    await assert.rejects(s.client.withdraw('mutual', () => {}, { fees: 'wallet' }), { code: 'withdrawal_wallet_pending' });
    s.client.gaslessTimingOverrides.resendAfterMs = 1;
    await new Promise(resolve => setTimeout(resolve, 5));
    const statuses = [];
    await within(5_000, s.client.syncWithdrawal(message => statuses.push(message)), 'sync after the window');
    assert.ok(statuses.some(message => /was released/.test(message)), statuses.join('\n'));
    const released = await s.prepared();
    assert.equal(released.userOp ?? null, null);
    assert.equal(released.submissionId ?? null, null);
    assert.ok(released.staleUserOpHashes.includes(s.bundler.sent.at(-1).hash), 'its hash stays journaled for a late inclusion');
    // A sponsored retry is refused, naming the wallet-paid close first: the note is still open.
    await assert.rejects(s.client.withdraw('mutual', () => {}, { fees: 'payout' }), error => error.code === 'gasless_record_not_pinned'
        && error.data.alternatives[0] === "withdraw('mutual', onStatus, { fees: 'wallet' })" && error.data.alternatives.includes('sweepTransit'));
    assert.equal(s.wallet.sent.length, 0);
    const closeHash = `0x${'d1'.repeat(32)}`;
    s.wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        s.chain.head += 1;
        s.chain.receipts.set(closeHash, { transactionHash: closeHash, blockNumber: `0x${s.chain.head.toString(16)}`, status: '0x1',
            logs: [logs.mutualClose(VAULT, { noteId: BigInt(NOTE_ID), finalBalance: BigInt(s.state.current_balance), destination: s.S })] });
        s.chain.noteStatus(NOTE_ID, 3);
        s.chain.setBalance(s.S, wei(s.state.current_balance));
        return closeHash;
    };
    const paid = await within(5_000, s.client.withdraw('mutual', () => {}, { fees: 'wallet' }), 'wallet-paid close');
    assert.equal(paid.status, 'closed');
    assert.equal(paid.fundsWaitingInTransit, true, 'the payout waits in S for sweepTransit');
    assert.equal(s.wallet.sent.length, 1);
    assert.equal(s.bundler.sent.length, sentBefore, 'nothing re-sent');
});

test('a sponsored close that reverts while the note stays active is retried with a new operation, not re-settled from the reverted one', async () => {
    const { chain, bundler, wallet, withdraw, S, record, prepared, closeKey, closeBundle } = await scenario();
    // The vault call runs out of gas: SponsorshipFailed, nothing stranded, the note stays Active.
    bundler.autoMine = () => ({
        success: false,
        extraLogs: [logs.sponsorshipFailed(chain.paymaster, { key: closeKey, sender: S, kind: 1n, noteId: BigInt(NOTE_ID), actualGasCost: 10n ** 15n })],
        effects: chainState => chainState.paymasterState.attempts.set(closeKey, (chainState.paymasterState.attempts.get(closeKey) ?? 0n) + 1n)
    });
    await assert.rejects(within(5_000, withdraw('mutual'), 'reverted close'), { code: 'gasless_op_reverted' });
    const reverted = bundler.sent[0].hash;
    const plan = await prepared();
    assert.ok(plan, 'the plan stays for a retry');
    assert.ok(!(plan.staleUserOpHashes || []).includes(reverted), 'a reverted inclusion is not a late inclusion to settle again');
    assert.equal(wallet.signatures.length, 1);
    // The retry the error message names: a new operation is signed, sent and settles the close.
    bundler.autoMine = closeBundle();
    const result = await within(5_000, withdraw('mutual'), 'retried close');
    assert.equal(result.status, 'closed');
    assert.equal(bundler.sent.length, 2, 'a new operation was sent');
    assert.notEqual(bundler.sent[1].hash, reverted);
    assert.equal(wallet.signatures.length, 2);
    assert.equal(result.userOpHash, bundler.sent[1].hash);
    assert.equal((await record()).userOpSuccess, true);
});

test('a sponsored finalization that reverted while the escape stays pending is retried with a new operation at the next nonce', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, client, recordId } = s;
    bundler.release();
    bundler.mine(s.finalizeHash, revertedFinalizeBundle(s));
    await assert.rejects(within(5_000, client.finalizeEscape(recordId, () => {}), 'the reverted finalization'), { code: 'gasless_op_reverted' });
    let saved = await s.record();
    assert.equal(saved.phase, 'pending');
    assert.equal(saved.finalizeUserOpPhase, 'reverted');
    // The retry the error message names: a new operation, at the next nonce, settles the finalization.
    const sent = bundler.sent.length;
    bundler.autoMine = () => sponsoredFinalizeBundle(s);
    const result = await within(5_000, client.finalizeEscape(recordId, () => {}), 'the retried finalization');
    assert.equal(result.status, 'closed');
    assert.equal(bundler.sent.length, sent + 1, 'a new operation was sent');
    const retried = bundler.sent.at(-1);
    assert.notEqual(retried.hash, s.finalizeHash);
    assert.equal(unpackNonce(retried.op.nonce).sequence, unpackNonce(bundler.sent.find(entry => entry.hash === s.finalizeHash).op.nonce).sequence + 1n);
    assert.equal(result.userOpHash, retried.hash);
    saved = await s.record();
    assert.equal(saved.finalizeUserOpPhase, 'settled');
    assert.equal(saved.finalizeUserOpHash, retried.hash);
    assert.deepEqual(saved.finalizeRevertedUserOpHashes, [s.finalizeHash], 'the reverted hash is set aside, never looked for again');
});

test('a sponsored finalization past finality is not looked for again on every escape sync', async () => {
    const s = await interruptedSponsoredFinalization();
    const { bundler, chain, client, recordId } = s;
    bundler.release();
    bundler.autoMine = () => sponsoredFinalizeBundle(s);
    bundler.mine(s.finalizeHash, sponsoredFinalizeBundle(s));
    const finalized = await within(5_000, client.finalizeEscape(recordId, () => {}), 'the sponsored finalization');
    assert.equal(finalized.status, 'closed');
    // Finality: the sanitized record drops the bundle transaction hash and keeps the operation hashes and their outcome.
    await runtime.updateWithdrawal(recordId, { phase: 'closed' }, { sanitize: true });
    let saved = await s.record();
    assert.equal(saved.finalizeTransactionHash, undefined);
    assert.equal(saved.finalizeUserOpPhase, 'settled');
    assert.equal(client.recordUserOpUnresolved(saved, 'finalize'), false);
    const warnings = [];
    const warn = console.warn;
    console.warn = (...args) => warnings.push(args.map(String).join(' '));
    try {
        const getLogs = () => chain.calls.filter(call => call.method === 'eth_getLogs').length;
        const before = getLogs();
        for (let pass = 0; pass < 2; pass += 1) await client.recoverGaslessRecordOperations();
        assert.equal(getLogs(), before, 'no log search for a settled finalization');
        // An outcome finality overtook (the op still journaled as submitted) is recorded once, without a claim, then left alone.
        await runtime.updateWithdrawal(recordId, { finalizeUserOpPhase: 'op_submitted' });
        await client.recoverGaslessRecordOperations();
        saved = await s.record();
        assert.equal(saved.phase, 'closed');
        assert.equal(saved.finalizeUserOpPhase, 'settled');
        const after = getLogs();
        await client.recoverGaslessRecordOperations();
        assert.equal(getLogs(), after);
    } finally {
        console.warn = warn;
    }
    assert.deepEqual(warnings, []);
});

test('the pre-proof quote is an upper bound on the signed operation: its vault call is sized as worst-case nonzero calldata', async () => {
    const { client, bundler, withdraw, closeBundle, amounts } = await scenario();
    const quote = await client.gaslessWithdrawalQuote('mutual', { destination: PAYEE });
    assert.equal(quote.available, true);
    bundler.autoMine = closeBundle();
    await within(5_000, withdraw('mutual'), 'a sponsored close');
    const signed = bundler.sent[0].op;
    assert.equal(BigInt(signed.maxFeePerGas), BigInt(quote.fees.maxFeePerGas), 'the same fees, so the gas alone decides');
    assert.ok(BigInt(quote.gas.preVerificationGas) >= BigInt(signed.preVerificationGas),
        `quoted preVerificationGas ${quote.gas.preVerificationGas} below the signed ${BigInt(signed.preVerificationGas)}`);
    assert.ok(BigInt(quote.maxCost) >= BigInt(amounts[0].maxCost), 'the quoted maxCost bounds the signed one');
    assert.ok(BigInt(quote.minimumReceivedWei) <= BigInt(amounts[0].minimumReceived), 'the quoted minimum is never above the one shown at signing');
});

test('with escapes disabled, a direct escape started from the wallet is finalized from the wallet: no plan is bound to the transit account', async () => {
    const { h, chain, wallet, client, withdraw, nullifier, state, record } = await scenario({ profile: { escapesEnabled: false }, allow: WALLET_SENDS });
    const refused = await withdraw('escape').then(() => null, error => error);
    assert.equal(refused?.code, 'escapes_disabled');
    assert.equal(proofs(h, 'escape').length, 0, 'refused before any proof, so nothing binds the transit account');
    assert.doesNotMatch(refused.message, /can still be sponsored/);
    assert.match(refused.message, /otherwise finalize it from the wallet/);
    // The wallet-paid start the message names: an ordinary escape to the payout address, not to S.
    const deadline = Math.floor(Date.now() / 1_000) - 10;
    const escapeHash = `0x${'e5'.repeat(32)}`;
    wallet.onSend = transaction => {
        assert.equal(low(transaction.to), low(VAULT));
        chain.head += 1;
        chain.receipts.set(escapeHash, { transactionHash: escapeHash, blockNumber: `0x${chain.head.toString(16)}`, status: '0x1',
            logs: [logs.escapeInitiated(VAULT, { noteId: BigInt(NOTE_ID), nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance),
                destination: PAYEE, challengeDeadline: BigInt(deadline) })] });
        chain.noteStatus(NOTE_ID, 2);
        chain.setPending(NOTE_ID, { nullifier: BigInt(nullifier), finalBalance: BigInt(state.current_balance), destination: PAYEE,
            challengeDeadline: BigInt(deadline), stateBalance: BigInt(state.current_balance), conceded: 0n, nextNullifier: 0x5n });
        return escapeHash;
    };
    const started = await within(5_000, withdraw('escape', { fees: 'wallet' }), 'wallet-paid escape');
    assert.equal(started.status, 'pending_withdrawal');
    const saved = await record();
    assert.equal(low(saved.destination), low(PAYEE));
    assert.equal(saved.feePayer, undefined);
    // Its finalization cannot be sponsored: the record has no transit account.
    await assert.rejects(client.finalizeEscape(started.recordId, () => {}, { fees: 'payout' }), { code: 'gasless_plan_mismatch' });
});
