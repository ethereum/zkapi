import assert from 'node:assert/strict';
import test from 'node:test';
import { deriveExpiryRecords, EXPIRED_CLAIMED_TOPIC, readFinalizedExpiryClaims } from '../services/zkapiExpiryHistory.mjs';
import { ABI } from '../wallet.js';

test('the expiry topic is vault revision 4\'s ExpiredClaimed(uint32,uint128)', () => {
    assert.equal(EXPIRED_CLAIMED_TOPIC, ABI.expiredClaimedEvent);
});

const VAULT = `0x${'12'.repeat(20)}`;
const OTHER_VAULT = `0x${'34'.repeat(20)}`;
const hash = number => `0x${BigInt(number).toString(16).padStart(64, '0')}`;
const hex = number => `0x${number.toString(16)}`;
const deposit = (noteId = 7, extra = {}) => ({ recordId: `test:deposit:${noteId}`,
    deploymentId: 'test', status: 'confirmed', noteId, amount: 2_000_000,
    expiryTs: 1000, ...extra });
const log = (noteId = 7, blockNumber = 12, extra = {}) => ({
    address: VAULT, topics: [EXPIRED_CLAIMED_TOPIC, hash(noteId)],
    data: `0x${hash(2_000_000).slice(2)}`,
    removed: false, blockNumber: hex(blockNumber), blockHash: hash(blockNumber),
    transactionHash: hash(100 + noteId), ...extra
});

function rpc({ logs = [log()], head = 20, maxRange = Infinity, blockOverride = () => ({}), chainId = 1 } = {}) {
    const calls = [];
    const request = async ({ method, params }) => {
        calls.push({ method, params: structuredClone(params) });
        if (method === 'eth_chainId') return hex(chainId);
        if (method === 'eth_getBlockByNumber') {
            const number = params[0] === 'finalized' ? head : Number(BigInt(params[0]));
            return { number: hex(number), hash: hash(number), timestamp: hex(1000 + number),
                ...blockOverride(number, params[0]) };
        }
        if (method === 'eth_getCode') return Number(BigInt(params[1])) >= 8 ? '0x1234' : '0x';
        if (method === 'eth_getLogs') {
            const { address, topics, fromBlock, toBlock } = params[0];
            assert.equal(address, VAULT);
            assert.deepEqual(topics, [EXPIRED_CLAIMED_TOPIC]);
            assert.deepEqual(Object.keys(params[0]).sort(), ['address', 'fromBlock', 'toBlock', 'topics']);
            const from = Number(BigInt(fromBlock));
            const to = Number(BigInt(toBlock));
            if (to - from + 1 > maxRange) throw new Error('Provider block range limit');
            return logs.filter(item => Number(BigInt(item.blockNumber)) >= from
                && Number(BigInt(item.blockNumber)) <= to);
        }
        throw new Error(`Unexpected RPC ${method}`);
    };
    return { request, calls };
}

test('clock expiry creates only an informational deadline, never an automatic refund or transfer', () => {
    assert.deepEqual(deriveExpiryRecords([deposit()], [], 999_999), []);
    assert.deepEqual(deriveExpiryRecords([deposit()], [], NaN), []);
    const rows = deriveExpiryRecords([deposit(), deposit(8, { expiryTs: null }),
        deposit(9, { status: 'pending' })], [], 1_000_000);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].type, 'expiry');
    assert.equal(rows[0].status, 'expired');
    assert.equal(rows[0].amount, null);
    assert.equal(rows[0].transactionHash, null);
    assert.match(rows[0].detail, /No automatic refund/);
    assert.match(rows[0].detail, /does not transfer funds/);
});

test('only a complete valid claim becomes a treasury-transfer entry, including after withdrawal history exists', () => {
    const expiryClaim = { amount: 2_000_000, transactionHash: hash(107), blockHash: hash(12),
        blockNumber: 12, claimedAt: 1_012_000 };
    const withdrawals = [{ deploymentId: 'test', noteId: 7, phase: 'closed', payoutVerified: true }];
    assert.deepEqual(deriveExpiryRecords([deposit()], withdrawals, 2_000_000), []);
    assert.deepEqual(deriveExpiryRecords([deposit()], [{ ...withdrawals[0], phase: 'closed_unconfirmed' }], 2_000_000), []);
    for (const phase of ['closed', 'closed_unconfirmed']) {
        assert.equal(deriveExpiryRecords([deposit()], [{ deploymentId: 'test', noteId: 7, phase }], 2_000_000)[0].status, 'expired');
    }
    const [row] = deriveExpiryRecords([deposit(7, { expiryClaim })], withdrawals, 2_000_000);
    assert.equal(row.status, 'claimed');
    assert.equal(row.amount, 2_000_000);
    assert.equal(row.createdAt, expiryClaim.claimedAt);
    assert.match(row.detail, /service treasury.*not a refund/);
    for (const invalid of [{ ...expiryClaim, amount: 1 }, { ...expiryClaim, claimedAt: 999_999 },
        { ...expiryClaim, transactionHash: 'javascript:alert(1)' }, { ...expiryClaim, blockNumber: -1 }]) {
        assert.equal(deriveExpiryRecords([deposit(7, { expiryClaim: invalid })], [], 2_000_000)[0].status, 'expired');
    }
});

test('finalized pending escape suppresses deadline but unconfirmed or other-deployment withdrawals do not', () => {
    const withdrawal = { deploymentId: 'test', noteId: 7, mode: 'escape', phase: 'pending',
        chainStatus: 'pending_withdrawal', startBlockNumber: 12, finalizedBlockNumber: 13 };
    assert.deepEqual(deriveExpiryRecords([deposit()], [withdrawal], 2_000_000), []);
    for (const partial of [{ ...withdrawal, finalizedBlockNumber: null },
        { ...withdrawal, finalizedBlockNumber: 11 }, { ...withdrawal, deploymentId: 'other' }]) {
        assert.equal(deriveExpiryRecords([deposit()], [partial], 2_000_000)[0].status, 'expired');
    }
});

test('reader accepts only finalized canonical claims with exact amount and elapsed expiry', async () => {
    const service = rpc({ logs: [log(), log(8, 19), log(9, 21)] });
    const result = await readFinalizedExpiryClaims({ ...service, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit(), deposit(8, { expiryTs: 1020 }), deposit(9)] });
    assert.deepEqual(result.claims, [{ noteId: 7, amount: 2_000_000, transactionHash: hash(107),
        blockHash: hash(12), blockNumber: 12, claimedAt: 1_012_000 }]);
    assert.equal(result.scannedTo, 20);
    assert.equal(result.complete, true);
});

test('public RPC requests do not reveal owned note IDs through log filters or selected block lookups', async () => {
    const logs = [log(7, 12), log(8, 13)];
    const first = rpc({ logs });
    const second = rpc({ logs });
    const a = await readFinalizedExpiryClaims({ ...first, vaultAddress: VAULT, chainId: 1, deposits: [deposit(7)] });
    const b = await readFinalizedExpiryClaims({ ...second, vaultAddress: VAULT, chainId: 1, deposits: [deposit(8)] });
    assert.equal(a.claims[0].noteId, 7);
    assert.equal(b.claims[0].noteId, 8);
    assert.deepEqual(first.calls, second.calls);
    assert.ok(first.calls.some(call => call.method === 'eth_getBlockByNumber' && call.params[0] === '0xc'));
    assert.ok(first.calls.some(call => call.method === 'eth_getBlockByNumber' && call.params[0] === '0xd'));
    assert.ok(first.calls.every(call => ['eth_chainId', 'eth_getLogs', 'eth_getBlockByNumber'].includes(call.method)));
});

test('unrelated public events and mismatched owned amounts cannot become claims', async () => {
    const logs = [log(7, 12, { address: OTHER_VAULT }), log(7, 12, { topics: [hash(1), hash(7)] }),
        log(7, 12, { data: `0x${hash(1).slice(2)}` }), log(8, 12)];
    const result = await readFinalizedExpiryClaims({ ...rpc({ logs }), vaultAddress: VAULT,
        chainId: 1, deposits: [deposit()] });
    assert.deepEqual(result.claims, []);
});

test('large valid public uint128 claims are validated without blocking supported owned deposits', async () => {
    const service = rpc({ logs: [log(8, 11, {
        data: `0x${hash(2n ** 100n).slice(2)}`
    }), log(7, 12)] });
    const result = await readFinalizedExpiryClaims({ ...service, vaultAddress: VAULT,
        chainId: 1, deposits: [deposit()] });
    assert.equal(result.claims.length, 1);
    assert.equal(result.claims[0].noteId, 7);
    assert.equal(result.claims[0].amount, 2_000_000);
    assert.equal(result.complete, true);
    assert.ok(service.calls.some(call => call.method === 'eth_getBlockByNumber' && call.params[0] === '0xb'));
});

test('malformed matching events fail the scan immediately without range retries or a saved cursor', async () => {
    const malformed = [log(7, 12, { removed: true }), log(7, 12, { removed: undefined }),
        log(7, 12, { topics: [EXPIRED_CLAIMED_TOPIC, hash(7), hash(1)] }),
        log(7, 12, { data: '0x1234' }),
        log(7, 12, { data: `0x${hash(2n ** 128n).slice(2)}` }),
        // A revision-3 ExpiredClaimed carried a root word: another ABI.
        log(7, 12, { data: `0x${hash(2_000_000).slice(2)}${hash(9).slice(2)}` }),
        log(7, 12, { topics: [EXPIRED_CLAIMED_TOPIC, hash(2n ** 32n)] }),
        log(7, 12, { transactionHash: '0x1234' }), log(7, 12, { blockHash: '0x1234' }),
        log(7, 21), log(7, 12, { blockNumber: 'bad' })];
    for (const event of malformed) {
        const service = rpc();
        const request = async call => {
            if (call.method === 'eth_getLogs') { service.calls.push(call); return [event]; }
            return service.request(call);
        };
        await assert.rejects(readFinalizedExpiryClaims({ request, vaultAddress: VAULT, chainId: 1,
            deposits: [deposit()] }), error => error.code === 'expiry_history_invalid_event');
        assert.equal(service.calls.filter(call => call.method === 'eth_getLogs').length, 1);
        assert.ok(!service.calls.some(call => call.method === 'eth_getCode'));
    }
});

test('malformed data in a fallback chunk aborts instead of shrinking the range and skipping it', async () => {
    const service = rpc({ maxRange: 3, logs: [log(7, 12, { removed: true })] });
    await assert.rejects(readFinalizedExpiryClaims({ ...service, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit()], deploymentBlock: 8, chunkSize: 3 }),
    error => error.code === 'expiry_history_invalid_event');
    assert.equal(service.calls.filter(call => call.method === 'eth_getLogs').length, 3);
});

test('wrong network, unavailable finality and reorged blocks fail without advancing a scan', async () => {
    const wrongChain = rpc({ chainId: 11155111 });
    await assert.rejects(readFinalizedExpiryClaims({ ...wrongChain, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit()] }), /configured network/);
    assert.equal(wrongChain.calls.length, 1);
    const unavailable = rpc({ blockOverride: (_number, tag) => tag === 'finalized' ? { hash: null } : {} });
    await assert.rejects(readFinalizedExpiryClaims({ ...unavailable, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit()] }), /invalid finalized/);
    const reorg = rpc({ logs: [log(7, 12, { blockHash: hash(99) })] });
    await assert.rejects(readFinalizedExpiryClaims({ ...reorg, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit()] }), /changed.*Retry/);
    const headReorg = rpc({ blockOverride: (number, tag) => number === 20 && tag !== 'finalized'
        ? { hash: hash(99) } : {} });
    await assert.rejects(readFinalizedExpiryClaims({ ...headReorg, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit()] }), /head changed/);
});

test('wide-range rejection discovers public deployment block and returns a resumable bounded prefix', async () => {
    const service = rpc({ maxRange: 3, logs: [log(7, 12), log(8, 19)] });
    const result = await readFinalizedExpiryClaims({ ...service, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit(), deposit(8)], chunkSize: 3, maxLogRequests: 4 });
    assert.equal(result.deploymentBlock, 8);
    assert.equal(result.scannedTo, 16);
    assert.equal(result.complete, false);
    assert.equal(result.claims.length, 1);
    assert.equal(service.calls.filter(call => call.method === 'eth_getLogs').length, 4);
    assert.ok(service.calls.filter(call => call.method === 'eth_getCode')
        .every(call => call.params[0] === VAULT && call.params.length === 2));
    const followup = rpc({ maxRange: 3, logs: [log(7, 12), log(8, 19)] });
    const rest = await readFinalizedExpiryClaims({ ...followup, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit(), deposit(8)], fromBlock: result.scannedTo + 1,
        deploymentBlock: result.deploymentBlock, chunkSize: 3 });
    assert.equal(rest.complete, true);
    assert.equal(rest.claims[0].noteId, 8);
    assert.ok(!followup.calls.some(call => call.method === 'eth_getCode'));
});

test('canonical block lookup budget returns a public prefix independent of ownership', async () => {
    const service = rpc({ logs: [log(7, 12), log(8, 13)] });
    const result = await readFinalizedExpiryClaims({ ...service, vaultAddress: VAULT, chainId: 1,
        deposits: [deposit(8)], maxBlockRequests: 1 });
    assert.equal(result.scannedTo, 12);
    assert.equal(result.complete, false);
    assert.deepEqual(result.claims, []);
});
