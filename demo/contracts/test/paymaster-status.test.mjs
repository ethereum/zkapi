// scripts/paymaster-status.mjs against a fake RPC: the event decoding (topic positions and data
// words, declared here from the contracts' event signatures, independently of the script), the
// open-debt and stranded reconciliation, the EntryPoint queries (filtered by paymaster topic and
// by the Sponsored senders, chunked) and the state reads, with every filter the script sends
// recorded. CI's Anvil run only ever sees a deployment with zero events.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { CANONICAL_ENTRY_POINT, keccak256, selector } from '../../../scripts/expected-codehashes.mjs';
import { paymasterStatus } from '../../../scripts/paymaster-status.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

const EP = CANONICAL_ENTRY_POINT;
const P = '0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9';
const F = '0xd8058efe0198ae9dd7d563e1b4938dcbc86a1f81';
const Q = '0x00000000000000000000000000000000000000aa'; // another app's paymaster
const OWNER = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const PAYEE = '0x0000000000000000000000000000000000000bee';
const S1 = '0x0000000000000000000000000000000000000a01';
const S2 = '0x0000000000000000000000000000000000000a02';
const S3 = '0x0000000000000000000000000000000000000a03';
const S4 = '0x0000000000000000000000000000000000000a04';
const X = '0x0000000000000000000000000000000000000a99'; // a sender the paymaster never sponsored

const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const words = values => `0x${values.map(value => word(value).slice(2)).join('')}`;
const topic = signature => keccak256(new TextEncoder().encode(signature));
const ETH = 10n ** 18n;

// The contracts' event declarations (ZkApiWithdrawalPaymaster.sol, IERC4337.sol): indexed
// parameters in order, then the data words.
const EVENTS = {
    Sponsored: 'Sponsored(bytes32,address,address,uint8,uint32,uint256)',
    Settled: 'Settled(bytes32,address,address,uint8,uint32,uint256,uint256,uint256,uint256)',
    SponsorshipFailed: 'SponsorshipFailed(bytes32,address,uint8,uint32,uint256)',
    EscapeInitiationOwed: 'EscapeInitiationOwed(address,uint32,uint256)',
    Shortfall: 'Shortfall(address,uint32,uint256)',
    PayoutCredited: 'PayoutCredited(address,uint256)',
    CreditClaimed: 'CreditClaimed(address,uint256)',
    Collected: 'Collected(address,address,uint256,uint256,uint256)',
    Stranded: 'Stranded(address)',
    ForwardAllowed: 'ForwardAllowed(address)',
    DebtWrittenOff: 'DebtWrittenOff(address,uint256)',
    PolicySet: 'PolicySet((uint256,uint256,uint256,bool,bool))',
    UserOperationEvent: 'UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)',
    PostOpRevertReason: 'PostOpRevertReason(bytes32,address,uint256,bytes)',
    UserOperationPrefundTooLow: 'UserOperationPrefundTooLow(bytes32,address,uint256)',
};
const [CLOSE, ESCAPE, FINALIZE, FORWARD] = [1n, 2n, 3n, 4n];
const key = n => word(0x1000 + n);
const hash = n => word(0x2000 + n);
// A `bytes` argument of 4 bytes after one static word: offset, length, the bytes left-aligned.
const revertBytes = [64n, 4n, 0xdeadbeefn << 224n];

/// The chain's logs, in emission order (log index), each as eth_getLogs returns it.
function chainLogs(more = () => {}) {
    const logs = [];
    const emit = (address, block, name, topics, data) => logs.push({
        address, blockNumber: hex(block), logIndex: hex(logs.length), transactionHash: word(0x3000 + logs.length),
        topics: [topic(EVENTS[name]), ...topics.map(word)], data: words(data),
    });
    // S1: an escape whose initiation debt (1000) is partly paid by its settlement (400) and a later collection (100).
    emit(P, 101, 'Sponsored', [key(1), S1, PAYEE], [ESCAPE, 7n, 5n * 10n ** 16n]);
    emit(EP, 101, 'UserOperationEvent', [hash(1), S1, P], [0n, 1n, 123n, 456n]);
    emit(P, 101, 'EscapeInitiationOwed', [S1, 7n], [1000n]);
    emit(P, 101, 'Settled', [key(1), S1, PAYEE], [ESCAPE, 7n, 0n, 300n, 400n, 0n]);
    emit(EP, 102, 'UserOperationEvent', [hash(9), S1, Q], [0n, 1n, 999n, 1n]); // another paymaster's operation
    emit(P, 103, 'Collected', [S1, PAYEE], [900n, 100n, 800n]);
    // S2: a failed close that strands it, then a forward that settles it; its debt is written off.
    emit(P, 104, 'Sponsored', [key(2), S2, PAYEE], [CLOSE, 8n, 5n * 10n ** 16n]);
    emit(P, 104, 'SponsorshipFailed', [key(2), S2], [CLOSE, 8n, 777n]);
    emit(EP, 104, 'UserOperationEvent', [hash(2), S2, P], [0n, 0n, 777n, 2n]);
    emit(P, 104, 'Stranded', [S2], []);
    emit(P, 104, 'EscapeInitiationOwed', [S2, 8n], [30n]);
    emit(P, 105, 'ForwardAllowed', [S2], []);
    emit(P, 105, 'Sponsored', [key(4), S3, PAYEE], [FINALIZE, 9n, 5n * 10n ** 16n]);
    emit(P, 106, 'Sponsored', [key(3), S2, PAYEE], [FORWARD, 8n, 5n * 10n ** 16n]);
    emit(P, 106, 'Settled', [key(3), S2, PAYEE], [FORWARD, 8n, 0n, 50n, 0n, 0n]);
    emit(EP, 106, 'UserOperationEvent', [hash(3), S2, P], [1n, 1n, 50n, 3n]);
    // S3: stranded with nothing after it.
    emit(P, 107, 'Stranded', [S3], []);
    emit(P, 108, 'PayoutCredited', [PAYEE], [200n]);
    emit(P, 109, 'CreditClaimed', [PAYEE], [200n]);
    emit(P, 110, 'Shortfall', [S1], [7n, 55n]);
    emit(P, 111, 'DebtWrittenOff', [S2], [30n]);
    emit(P, 111, 'PolicySet', [], [1n, 2n, 3n, 0n, 0n]); // not accounted, must not trip the decoder
    emit(EP, 112, 'PostOpRevertReason', [hash(5), S1], [1n, ...revertBytes]);
    emit(EP, 112, 'PostOpRevertReason', [hash(6), X], [0n, ...revertBytes]); // a sender the paymaster never named
    emit(EP, 113, 'UserOperationPrefundTooLow', [hash(7), S3], [0n]);
    emit(EP, 113, 'UserOperationPrefundTooLow', [hash(8), X], [0n]);
    more(emit);
    return logs;
}

/// Whether `log` is what eth_getLogs returns for `filter`: the address, the block range and
/// each topic position (null matches anything, an array any of its values).
function matches(filter, log) {
    const from = BigInt(filter.fromBlock);
    const to = BigInt(filter.toBlock);
    if (log.address !== filter.address || BigInt(log.blockNumber) < from || BigInt(log.blockNumber) > to) return false;
    return (filter.topics ?? []).every((want, i) =>
        want === null || (Array.isArray(want) ? want : [want]).some(value => value.toLowerCase() === log.topics[i]?.toLowerCase()));
}

/// A fake node: the state the status reads, the logs above, and every eth_getLogs filter sent.
function fakeNode({ chainId = 31_337n, latest = 120n, stranded = { [S3]: 1n }, owed = { [S1]: 500n, [S2]: 0n }, more,
    balances = { [P]: 7n, [S3]: 42n }, codes = { [S1]: '0xef0100', [S2]: '0xef0100', [S3]: '0xef0100' } } = {}) {
    const logs = chainLogs(more);
    const filters = [];
    const calls = (to, data) => {
        const method = data.slice(0, 10);
        const argument = `0x${data.slice(-40)}`;
        const answers = to === EP ? {
            [selector('balanceOf(address)')]: () => words([argument === P ? ETH : 0n]),
            [selector('getDepositInfo(address)')]: () => words([argument === P ? ETH : 0n, 1n, ETH / 10n, 86_400n, 0n]),
        } : to === P ? {
            [selector('policy()')]: () => words([5n * 10n ** 16n, 0n, 10n ** 16n, 0n, 0n]),
            [selector('maxFeeCeiling()')]: () => words([10n ** 11n]),
            [selector('priorityFeeCeiling()')]: () => words([3n * 10n ** 9n]),
            [selector('feeKeeper()')]: () => word(0n),
            [selector('owner()')]: () => word(OWNER),
            [selector('pendingOwner()')]: () => word(0n),
            [selector('lostWei()')]: () => words([5n]),
            [selector('shortfallWei()')]: () => words([55n]),
            [selector('totalCredits()')]: () => words([0n]),
            [selector('callCap(uint8)')]: () => words([100_000n * BigInt(argument)]),
            [selector('owed(address)')]: () => words([owed[argument] ?? fail(`owed(${argument}) was not expected`)]),
            [selector('stranded(address)')]: () => words([stranded[argument] ?? fail(`stranded(${argument}) was not expected`)]),
        } : {};
        return (answers[method] ?? fail(`unexpected eth_call ${method} at ${to}`))();
    };
    const rpc = async (method, params) => {
        switch (method) {
            case 'eth_chainId': return hex(chainId);
            case 'eth_blockNumber': return hex(latest);
            case 'eth_call': return calls(params[0].to.toLowerCase(), params[0].data);
            case 'eth_getBalance': return hex(balances[params[0].toLowerCase()] ?? 0n);
            case 'eth_getCode': return codes[params[0].toLowerCase()] ?? '0x';
            case 'eth_getLogs': filters.push(params[0]); return logs.filter(log => matches(params[0], log));
            default: return fail(`unexpected ${method}`);
        }
    };
    return { rpc, filters, logs };
}

function fail(message) {
    throw new Error(message);
}

const DEPLOYMENT = { deploymentStatus: 'deployed', chainId: 31_337, deployBlock: 100, entryPoint: EP, withdrawalPaymaster: P, withdrawalAccountFactory: F };

const EXPECTED = {
    chain_id: 31_337,
    block: 120,
    entry_point: EP,
    paymaster: P,
    factory: F,
    deposit_wei: '1000000000000000000',
    deposit_covers_operations: 20,
    paymaster_stake: { deposit_wei: '1000000000000000000', staked: true, stake_wei: '100000000000000000', unstake_delay_seconds: 86_400, withdraw_time: 0 },
    factory_stake: { deposit_wei: '0', staked: true, stake_wei: '100000000000000000', unstake_delay_seconds: 86_400, withdraw_time: 0 },
    policy: { max_sponsored_cost_wei: '50000000000000000', flat_fee_wei: '0', min_escape_net_wei: '10000000000000000', escapes_enabled: false,
        sponsorship_paused: false },
    fee_ceilings: { max_fee_wei: '100000000000', priority_fee_wei: '3000000000' },
    call_caps: { close: 100_000, escape: 200_000, finalize: 300_000, forward: 400_000 },
    fee_keeper: `0x${'0'.repeat(40)}`,
    owner: OWNER,
    pending_owner: `0x${'0'.repeat(40)}`,
    lost_wei: '5',
    shortfall_wei: '55',
    total_credits_wei: '0',
    paymaster_balance_wei: '7',
    unaccounted_balance_wei: '7',
    open_owed_total_wei: '500',
    open_owed: { [S1]: { from_events_wei: '500', on_chain_wei: '500' } },
    stranded_open: [{ account: S3, since_block: 107, transaction: word(0x3000 + 16), evidence: 'stranded', stranded_flag_on_chain: true,
        has_code: true, balance_wei: '42' }],
    events: {
        from_block: 100,
        to_block: 120,
        counts: { Sponsored: 4, Settled: 2, SponsorshipFailed: 1, EscapeInitiationOwed: 2, Shortfall: 1, PayoutCredited: 1, CreditClaimed: 1,
            Collected: 1, Stranded: 2, ForwardAllowed: 1, DebtWrittenOff: 1 },
        by_kind: { close: { sponsored: 1, settled: 0, failed: 1 }, escape: { sponsored: 1, settled: 1, failed: 0 },
            finalize: { sponsored: 1, settled: 0, failed: 0 }, forward: { sponsored: 1, settled: 1, failed: 0 } },
        totals: { settled_received_wei: '0', settled_charged_wei: '350', settled_owed_paid_wei: '400', settled_paid_out_wei: '0',
            failed_actual_gas_cost_wei: '777', shortfall_wei: '55', credited_wei: '200', claimed_wei: '200', collected_received_wei: '900',
            collected_owed_paid_wei: '100' },
    },
    user_operations: { total: 3, succeeded: 2, failed: 1, actual_gas_cost_wei: '950' },
    entry_point_alarms: { post_op_revert_reason: 1, user_operation_prefund_too_low: 1 },
};

const USER_OPERATION_FILTER = [topic(EVENTS.UserOperationEvent), null, null, word(P)];
const ALARM_FILTER = [[topic(EVENTS.PostOpRevertReason), topic(EVENTS.UserOperationPrefundTooLow)], null, [word(S1), word(S2), word(S3)]];

test('paymaster status: events, open debt, stranded accounts and the EntryPoint queries', async () => {
    const node = fakeNode();
    const status = await paymasterStatus({ deployment: DEPLOYMENT, rpc: node.rpc });
    assert.deepEqual(status, EXPECTED);
    assert.deepEqual(JSON.parse(JSON.stringify(status)), EXPECTED, 'the report is plain JSON');
    // One query of the paymaster's logs, then the EntryPoint only for this paymaster's
    // operations and for the alarms of the senders it sponsored, in the order Sponsored named them.
    assert.deepEqual(node.filters, [
        { address: P, fromBlock: '0x64', toBlock: '0x78' },
        { address: EP, fromBlock: '0x64', toBlock: '0x78', topics: USER_OPERATION_FILTER },
        { address: EP, fromBlock: '0x64', toBlock: '0x78', topics: ALARM_FILTER },
    ]);
    // Every log the fake holds for the EntryPoint that the filters left out is another app's.
    const seen = node.filters.flatMap(filter => node.logs.filter(log => matches(filter, log)));
    const left = node.logs.filter(log => !seen.includes(log));
    assert.deepEqual(left.map(log => log.topics[1 + (log.topics[0] === topic(EVENTS.UserOperationEvent) ? 2 : 1)]),
        [word(Q), word(X), word(X)]);
});

test('paymaster status: --log-chunk splits every query into block ranges without changing the report', async () => {
    const node = fakeNode();
    const status = await paymasterStatus({ deployment: DEPLOYMENT, rpc: node.rpc, chunk: 10n });
    assert.deepEqual(status, EXPECTED);
    const ranges = [['0x64', '0x6d'], ['0x6e', '0x77'], ['0x78', '0x78']];
    assert.deepEqual(node.filters, [
        ...ranges.map(([fromBlock, toBlock]) => ({ address: P, fromBlock, toBlock })),
        ...ranges.map(([fromBlock, toBlock]) => ({ address: EP, fromBlock, toBlock, topics: USER_OPERATION_FILTER })),
        ...ranges.map(([fromBlock, toBlock]) => ({ address: EP, fromBlock, toBlock, topics: ALARM_FILTER })),
    ]);
});

test('paymaster status: the block range, and the reconciliation against the chain', async () => {
    // From block 105 on: S1's debt events are before the window, S2's forward settles it, S3 stays stranded.
    const node = fakeNode();
    const later = await paymasterStatus({ deployment: DEPLOYMENT, rpc: node.rpc, fromBlock: 105n, toBlock: 113n });
    assert.deepEqual(later.events.from_block, 105);
    assert.deepEqual(later.events.to_block, 113);
    assert.deepEqual(later.events.counts.Sponsored, 2);
    assert.deepEqual(later.open_owed, {});
    assert.deepEqual(later.stranded_open.map(entry => entry.account), [S3]);
    assert.deepEqual(later.user_operations, { total: 1, succeeded: 1, failed: 0, actual_gas_cost_wei: '50' });
    assert.deepEqual(later.entry_point_alarms, { post_op_revert_reason: 0, user_operation_prefund_too_low: 1 });
    assert.equal(node.filters.at(-1).topics[2].length, 2, 'only the senders Sponsored named in the window');
    // The chain's own figures are reported beside the events' (a sweep the window missed, a stranded flag cleared).
    const drifted = fakeNode({ owed: { [S1]: 0n, [S2]: 0n }, stranded: { [S3]: 0n } });
    const status = await paymasterStatus({ deployment: DEPLOYMENT, rpc: drifted.rpc });
    assert.deepEqual(status.open_owed, { [S1]: { from_events_wei: '500', on_chain_wei: '0' } });
    assert.equal(status.open_owed_total_wei, '0');
    assert.equal(status.stranded_open[0].stranded_flag_on_chain, false);
    // No Sponsored sender in the window: the EntryPoint is not asked for alarms at all.
    const quiet = fakeNode();
    await paymasterStatus({ deployment: DEPLOYMENT, rpc: quiet.rpc, fromBlock: 107n, toBlock: 120n });
    assert.deepEqual(quiet.filters.map(filter => filter.address), [P, EP]);
});

test('paymaster status: an account the owner allowed to forward may have no code yet, and says so', async () => {
    // A close replayed before any sponsored operation: the vault paid S4 directly, S4's
    // first sponsored operation (carrying its initCode) failed validation, so S4 holds the
    // payout with no code. The owner's allowForward(S4) lists it; sweep() to it would be a
    // no-op transfer, so the report says the factory must create it first.
    const node = fakeNode({ more: emit => emit(P, 114, 'ForwardAllowed', [S4], []), stranded: { [S3]: 1n, [S4]: 1n },
        balances: { [P]: 7n, [S3]: 42n, [S4]: 9n } });
    const status = await paymasterStatus({ deployment: DEPLOYMENT, rpc: node.rpc });
    assert.deepEqual(status.stranded_open, [
        EXPECTED.stranded_open[0],
        { account: S4, since_block: 114, transaction: word(0x3000 + node.logs.length - 1), evidence: 'forward_allowed',
            stranded_flag_on_chain: true, has_code: false, balance_wei: '9' },
    ]);
    // Once created, the same entry reports code; the evidence is still the owner's.
    const created = fakeNode({ more: emit => emit(P, 114, 'ForwardAllowed', [S4], []), stranded: { [S3]: 1n, [S4]: 1n },
        codes: { [S3]: '0xef0100', [S4]: '0x6080' } });
    const after = await paymasterStatus({ deployment: DEPLOYMENT, rpc: created.rpc });
    assert.deepEqual(after.stranded_open.map(entry => [entry.account, entry.evidence, entry.has_code]),
        [[S3, 'stranded', true], [S4, 'forward_allowed', true]]);
});

test('paymaster status refuses a manifest that is not a finalized paymaster deployment, and another chain', async () => {
    await assert.rejects(paymasterStatus({ deployment: { ...DEPLOYMENT, deploymentStatus: 'pending' }, rpc: fakeNode().rpc }), /pass the finalized manifest/);
    await assert.rejects(paymasterStatus({ deployment: { ...DEPLOYMENT, withdrawalPaymaster: null }, rpc: fakeNode().rpc }), /withdrawalPaymaster is null/);
    await assert.rejects(paymasterStatus({ deployment: DEPLOYMENT, rpc: fakeNode({ chainId: 11_155_111n }).rpc }), /serves chain 11155111, the manifest is for chain 31337/);
    await assert.rejects(paymasterStatus({ deployment: DEPLOYMENT, rpc: fakeNode().rpc, fromBlock: 121n }), /--from-block 121 is after --to-block 120/);
});

/// `node script args`, run while this process keeps serving the fake node (spawnSync would block it).
function run(script, args) {
    return new Promise((done, reject) => {
        const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', chunk => { stdout += chunk; });
        child.stderr.on('data', chunk => { stderr += chunk; });
        child.on('error', reject);
        child.on('close', status => done({ status, stdout, stderr }));
    });
}

test('the command line prints the report of the manifest file over JSON-RPC', async () => {
    const node = fakeNode();
    const server = http.createServer((request, response) => {
        let body = '';
        request.on('data', chunk => { body += chunk; });
        request.on('end', async () => {
            const { id, method, params } = JSON.parse(body);
            const reply = result => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ jsonrpc: '2.0', id, result })); };
            reply(await node.rpc(method, params));
        });
    });
    await new Promise(done => server.listen(0, '127.0.0.1', done));
    const dir = mkdtempSync(join(tmpdir(), 'zkapi-paymaster-status-'));
    try {
        const file = join(dir, 'deployment.json');
        writeFileSync(file, JSON.stringify(DEPLOYMENT));
        const url = `http://127.0.0.1:${server.address().port}`;
        const script = join(ROOT, 'scripts/paymaster-status.mjs');
        const report = await run(script, ['--deployment', file, '--rpc', url, '--log-chunk', '10']);
        assert.equal(report.status, 0, report.stderr);
        assert.deepEqual(JSON.parse(report.stdout), EXPECTED);
        assert.equal(node.filters.length, 9, 'three chunked queries');
        writeFileSync(file, JSON.stringify({ ...DEPLOYMENT, withdrawalPaymaster: null }));
        const refused = await run(script, ['--deployment', file, '--rpc', url]);
        assert.equal(refused.status, 2);
        assert.match(refused.stderr, /^paymaster-status: .*withdrawalPaymaster is null/);
        const usage = await run(script, ['--deployment', file]);
        assert.equal(usage.status, 2);
        assert.match(usage.stderr, /--deployment \(a finalized manifest\) and --rpc are required/);
    } finally {
        rmSync(dir, { recursive: true, force: true });
        server.close();
    }
});
