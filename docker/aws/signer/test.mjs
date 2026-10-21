import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { Interface, Transaction, Wallet, keccak256 } from 'ethers';
import {
  ABSOLUTE_FEE_CEILING, ConfigError, DEFAULT_TX_FEE_CAP, ESCAPE_FINALIZED_TOPIC, GWEI, RpcError, UPSTREAM_TIMEOUT_MS,
  createSigner, createUpstream, parseChainId, parseSignerConfig, vaultInterface,
} from './signer.mjs';
import { createHttpServer } from './server.mjs';

const CHAIN_ID = 11155111n;
const here = dirname(fileURLToPath(import.meta.url));

// Public test key; never used or funded outside these offline tests.
const key = `0x${'1'.padStart(64, '0')}`;
const sender = new Wallet(key).address;
const vault = '0x0000000000000000000000000000000000001234';
const proof = `0x${'00'.repeat(256)}`;
const inputs = [2, CHAIN_ID, vault, 0, 1, 2, 0, 1, 0, 0, 0, 0];
const data = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, inputs, proof]);
const validTx = { from: sender, to: vault, data, gas: '0x7a1200', nonce: '0x4' };
// The revision-2 challenge: request inputs, proof and a zero-slot path.
const legacyChallenge = new Interface([
  'function challengeEscapeWithdrawal(uint32 noteId,(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256) inputs,bytes proof,uint256[32] siblings)',
]).encodeFunctionData('challengeEscapeWithdrawal', [0, inputs, proof, Array(32).fill(0)]);
const ONE_ETH = '0xde0b6b3a7640000';
const wei = value => `0x${value.toString(16)}`;
const fees = (maxFee, tip) => ({ maxFeePerGas: wei(maxFee), maxPriorityFeePerGas: wei(tip) });
const configError = message => error => error instanceof ConfigError && error.message === message;

function fixture(overrides = {}, options = {}) {
  const calls = [];
  const answers = {
    eth_chainId: `0x${CHAIN_ID.toString(16)}`,
    eth_call: '0x', eth_estimateGas: '0x6acfc0',
    eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x3b9aca00' },
    eth_getBalance: ONE_ETH, eth_getTransactionByHash: null,
    eth_sendRawTransaction: raw => keccak256(raw), eth_blockNumber: '0x1',
    // An escape of every note finalized (in the newest block range read).
    eth_getLogs: filter => [{ address: filter.address, topics: filter.topics, data: `0x${'00'.repeat(96)}`, removed: false }],
    ...overrides,
  };
  // Unexpected methods fail the test, which proves eth_gasPrice is never read.
  const rpc = async (method, params) => {
    calls.push({ method, params });
    assert.ok(Object.hasOwn(answers, method), `Unexpected RPC method ${method}`);
    if (answers[method] instanceof Error) throw answers[method];
    return typeof answers[method] === 'function' ? answers[method](...params) : answers[method];
  };
  const logs = [];
  return { calls, logs, signer: createSigner({ privateKey: key, vault, rpc, chainId: CHAIN_ID, log: line => logs.push(line), ...options }) };
}
const broadcasts = calls => calls.filter(call => call.method === 'eth_sendRawTransaction');

test('signs only the bounded Sepolia challenge as EIP-1559 at the default bid, preserving caller nonce', async () => {
  const { signer, calls } = fixture();
  const hash = await signer.handle('eth_sendTransaction', [validTx]);
  assert.deepEqual(calls.map(c => c.method), ['eth_chainId', 'eth_call', 'eth_estimateGas', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_sendRawTransaction']);
  const raw = calls.at(-1).params[0];
  const signed = Transaction.from(raw);
  assert.equal(hash, keccak256(raw));
  assert.equal(signed.hash, hash);
  assert.equal(signed.type, 2);
  assert.equal(signed.gasPrice, null);
  assert.equal(signed.maxFeePerGas, 10n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 1n * GWEI);
  assert.deepEqual(signed.accessList, []);
  assert.equal(signed.from, sender);
  assert.equal(signed.chainId, CHAIN_ID);
  assert.equal(signed.to.toLowerCase(), vault);
  assert.equal(signed.value, 0n);
  assert.equal(signed.nonce, 4);
  assert.equal(signed.data, data);
  assert.equal(signed.gasLimit, 8_000_000n);
  assert.deepEqual(calls[1].params, [{ from: sender.toLowerCase(), to: vault, data, value: '0x0' }, 'latest']);
  assert.deepEqual(calls[3].params, ['latest', false]);
  assert.deepEqual(calls[4].params, [sender.toLowerCase(), 'latest']);
});

test('signs daemon-proposed fees exactly and checks the balance against gas limit x proposed max fee', async () => {
  // The balance covers 8M gas at 3 gwei but not at the 10 gwei cap.
  const { signer, calls } = fixture({ eth_getBalance: wei(8_000_000n * 3n * GWEI) });
  const hash = await signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(3n * GWEI, 2n * GWEI) }]);
  const signed = Transaction.from(calls.at(-1).params[0]);
  assert.equal(signed.hash, hash);
  assert.equal(signed.type, 2);
  assert.equal(signed.maxFeePerGas, 3n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 2n * GWEI);
  // Bounds are inclusive: tip == max fee == cap == tip cap, and base fee == max fee.
  for (const [maxFee, tip] of [[10n * GWEI, 10n * GWEI], [GWEI, GWEI]]) {
    const inclusive = fixture();
    await inclusive.signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(maxFee, tip) }]);
    const bid = Transaction.from(inclusive.calls.at(-1).params[0]);
    assert.deepEqual([bid.maxFeePerGas, bid.maxPriorityFeePerGas], [maxFee, tip]);
  }
});

test('rejects unauthorized transaction changes before any RPC or signature', async () => {
  const modifications = [
    { from: vault }, { to: sender }, { to: null }, { value: '0x1' }, { chainId: '0x1' },
    { data: '0xdeadbeef' }, { data: `${data}00` }, { gas: '0xffffffff' }, { gas: '0x0' },
    { nonce: undefined }, { nonce: '0xffffffffffffffff' }, { nonce: '0x04' },
    { gasPrice: '0x1' }, { accessList: [] }, { authorizationList: [] }, { type: '0x2' }, { type: '0x0' }, { input: data },
    { maxFeePerBlobGas: '0x1' }, { blobVersionedHashes: [] }, { blobs: [] },
    { maxFeePerGas: '0x2540be400', maxPriorityFeePerGas: '0x03b9aca00' }, { maxFeePerGas: '0x02540be400', maxPriorityFeePerGas: '0x3b9aca00' },
    { maxFeePerGas: 10_000_000_000, maxPriorityFeePerGas: 1_000_000_000 }, { maxFeePerGas: null, maxPriorityFeePerGas: null },
    { maxFeePerGas: '0x', maxPriorityFeePerGas: '0x1' },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, 1, vault, ...inputs.slice(3)], proof]) },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, CHAIN_ID, sender, ...inputs.slice(3)], proof]) },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, inputs, '0x00']) },
    { data: vaultInterface.encodeFunctionData('raiseEscapeConcession', [0, [2, 1, vault, ...inputs.slice(3)], proof, 5]) },
    { data: vaultInterface.encodeFunctionData('raiseEscapeConcession', [0, inputs, '0x00', 5]) },
    // The revision-2 challenge with siblings, and other vault calls.
    { data: legacyChallenge },
    { data: new Interface(['function finalizeEscapeWithdrawal(uint32)']).encodeFunctionData('finalizeEscapeWithdrawal', [0]) },
    { data: new Interface(['function claimExpired(uint32)']).encodeFunctionData('claimExpired', [0]) },
  ];
  for (const modification of modifications) {
    const { signer, calls } = fixture();
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...modification }]), error => error instanceof RpcError && error.code === -32602, JSON.stringify(modification));
    assert.equal(calls.length, 0);
  }
});

test('signs the three concession-exit calls by their pinned selectors', async () => {
  // Selectors pinned in the concession-exit spec (sections 4.3-4.5).
  assert.equal(vaultInterface.getFunction('challengeEscapeWithdrawal').selector, '0xda0ce43d');
  assert.equal(vaultInterface.getFunction('raiseEscapeConcession').selector, '0xdd0064ba');
  assert.equal(vaultInterface.getFunction('retireClosedLeaf').selector, '0xe41f4c31');
  assert.equal(legacyChallenge.slice(0, 10), '0x8a43467c');
  assert.equal((data.length - 2) / 2, 740);
  const raise = vaultInterface.encodeFunctionData('raiseEscapeConcession', [0, inputs, proof, 123]);
  assert.equal((raise.length - 2) / 2, 772);
  const siblings = Array.from({ length: 32 }, (_, index) => index + 1);
  const retire = vaultInterface.encodeFunctionData('retireClosedLeaf', [9, siblings]);
  assert.equal((retire.length - 2) / 2, 1060);
  for (const call of [raise, retire]) {
    const { signer, calls } = fixture();
    const hash = await signer.handle('eth_sendTransaction', [{ ...validTx, data: call }]);
    const signed = Transaction.from(broadcasts(calls)[0].params[0]);
    assert.equal(signed.hash, hash);
    assert.equal(signed.data, call);
  }
  // A non-canonical encoding of an allowed call is refused before any RPC.
  const { signer, calls } = fixture();
  const padded = `${raise.slice(0, 10)}${'00'.repeat(32)}${raise.slice(10)}`;
  await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, data: padded }]), RpcError);
  assert.equal(calls.length, 0);
});

// A leaf retirement of a note on a nonce (default the shared test nonce 4).
const retire = (note, nonce = 4n) => ({ ...validTx, nonce: wei(nonce), data: vaultInterface.encodeFunctionData('retireClosedLeaf', [note, Array(32).fill(0)]) });

test('leaf retirements are capped per rolling day by nonce, reported, and never block defeats or raises', async t => {
  let clock = 1_700_000_000_000;
  const raise = { ...validTx, nonce: '0x8', data: vaultInterface.encodeFunctionData('raiseEscapeConcession', [0, inputs, proof, 5]) };
  const { signer, calls, logs } = fixture({}, { now: () => clock });
  await signer.handle('eth_sendTransaction', [retire(9, 4n)]);
  // A replacement of a counted retirement on its nonce needs no new budget.
  await signer.handle('eth_sendTransaction', [{ ...retire(9, 4n), ...fees(5n * GWEI, 2n * GWEI) }]);
  await signer.handle('eth_sendTransaction', [retire(10, 5n)]);
  assert.equal(broadcasts(calls).length, 3);
  const before = calls.length;
  const spent = { code: -32003, message: 'Leaf retirement budget for the last 24 hours is spent', data: { reason: 'retirement_budget_exhausted', max_retirements_per_day: '0x2' } };
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(11, 6n)]), spent);
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(11, 7n)]), spent);
  assert.equal(calls.length, before, 'refused before any upstream call');
  assert.deepEqual(logs.filter(line => line.event === 'challenge_refused'), [
    { event: 'challenge_refused', nonce: 6, code: -32003, reason: 'retirement_budget_exhausted', message: spent.message, max_retirements_per_day: '2' },
    { event: 'challenge_refused', nonce: 7, code: -32003, reason: 'retirement_budget_exhausted', message: spent.message, max_retirements_per_day: '2' },
  ]);
  // Defeats and raises still sign.
  await signer.handle('eth_sendTransaction', [{ ...validTx, nonce: '0x8' }]);
  await signer.handle('eth_sendTransaction', [raise]);
  assert.equal(broadcasts(calls).length, 5);
  const status = await signer.handle('zkapi_signerStatus', []);
  assert.deepEqual([status.retirements_last_24h, status.retirement_refusals, status.last_retirement_refusal_at], [2, 2, clock / 1000]);
  assert.deepEqual(status.warnings, ['retirement_budget_exhausted']);
  const server = createHttpServer(signer).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => server.close());
  const health = await fetch(`http://127.0.0.1:${server.address().port}/health`).then(r => r.json());
  assert.equal(health.status, 'ok');
  assert.deepEqual([health.max_retirements_per_day, health.retirements_last_24h, health.retirement_refusals], [2, 2, 2]);
  // A day after the first signing, the window frees its slot.
  clock += 86_400_000;
  await signer.handle('eth_sendTransaction', [retire(11, 6n)]);
  assert.equal(broadcasts(calls).length, 6);
  clock += 86_400_000;
  assert.deepEqual((await signer.handle('zkapi_signerStatus', [])).warnings, []);
});

test('a retirement that is not broadcast takes no budget; zero allows none', async () => {
  const refusedFor = reason => error => error instanceof RpcError && error.data?.reason === reason;
  const spent = { data: { reason: 'retirement_budget_exhausted', max_retirements_per_day: '0x1' } };
  // A failed simulation and the node's fee-cap refusal leave the budget.
  let simulation = new RpcError(-32000, 'reverted', 'upstream_rejected');
  let broadcast = new RpcError(-32000, 'tx fee exceeds the configured cap', 'upstream_tx_fee_cap');
  const { signer, calls } = fixture({
    eth_call: () => { if (simulation) throw simulation; return '0x'; },
    eth_sendRawTransaction: raw => { if (broadcast) throw broadcast; return keccak256(raw); },
  }, { maxRetirementsPerDay: 1n });
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(9)]), refusedFor('simulation_failed'));
  simulation = null;
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(9)]), refusedFor('upstream_tx_fee_cap'));
  assert.equal((await signer.handle('zkapi_signerStatus', [])).retirements_last_24h, 0);
  // An ambiguous broadcast may have been broadcast: it takes the budget.
  broadcast = new RpcError(-32000, 'timeout', 'upstream_unavailable');
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(9)]), refusedFor('broadcast_ambiguous'));
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(10)]), spent);
  broadcast = null;
  await signer.handle('eth_sendTransaction', [retire(9)]);
  assert.equal(broadcasts(calls).length, 3);
  const none = fixture({}, { maxRetirementsPerDay: 0n });
  await assert.rejects(none.signer.handle('eth_sendTransaction', [retire(9)]), { data: { reason: 'retirement_budget_exhausted', max_retirements_per_day: '0x0' } });
  assert.equal(none.calls.length, 0);
  await none.signer.handle('eth_sendTransaction', [validTx]);
  for (const bad of [-1n, 1_001n, 2]) assert.throws(() => fixture({}, { maxRetirementsPerDay: bad }), { message: 'Retirement budget is invalid' });
});

test('a note retires on one nonce at a time: fee replacements are free, a later nonce waits for the earlier one to mine and takes a new unit', async () => {
  // The sender's latest nonce count; retirements on nonces at or above it may still mine.
  let mined = 4n;
  const { signer, calls, logs } = fixture({ eth_getTransactionCount: () => (mined instanceof Error ? (() => { throw mined; })() : wei(mined)) }, { maxRetirementsPerDay: 3n });
  const units = async () => (await signer.handle('zkapi_signerStatus', [])).retirements_last_24h;
  // The upstream methods one send reads, and how it ends.
  const send = async transaction => {
    const before = calls.length;
    const outcome = await signer.handle('eth_sendTransaction', [transaction]).then(() => undefined, error => error);
    const error = outcome && { code: outcome.code, message: outcome.message, data: outcome.data };
    return { methods: calls.slice(before).map(call => call.method), error };
  };
  await signer.handle('eth_sendTransaction', [retire(9, 4n)]);
  // A fee replacement on the counted nonce signs without reading the nonce count or taking a unit.
  const replacement = await send({ ...retire(9, 4n), ...fees(5n * GWEI, 2n * GWEI) });
  assert.equal(replacement.error, undefined);
  assert.ok(!replacement.methods.includes('eth_getTransactionCount'));
  assert.equal(broadcasts(calls).length, 2);
  assert.equal(await units(), 1);
  // While nonce 4 is unmined, the same note on later nonces is refused before any simulation.
  const inFlight = { code: -32003, message: 'A retirement of this note may still mine on an earlier nonce', data: { reason: 'retirement_in_flight', retirement_nonce: '0x4' } };
  for (let nonce = 5n; nonce < 54n; nonce += 1n) {
    const copy = await send(retire(9, nonce));
    assert.deepEqual(copy.error, inFlight);
    assert.deepEqual(copy.methods, ['eth_chainId', 'eth_getTransactionCount']);
  }
  assert.deepEqual(calls.find(call => call.method === 'eth_getTransactionCount').params, [sender.toLowerCase(), 'latest']);
  assert.equal(broadcasts(calls).length, 2);
  assert.equal(await units(), 1);
  assert.deepEqual(logs.find(line => line.event === 'challenge_refused'), {
    event: 'challenge_refused', nonce: 5, code: -32003, reason: 'retirement_in_flight', message: inFlight.message, retirement_nonce: '4',
  });
  // An unreadable nonce count is a transient refusal that takes nothing.
  for (const failure of [new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'), '0x04']) {
    mined = failure;
    await assert.rejects(signer.handle('eth_sendTransaction', [retire(9, 5n)]), { code: -32000, data: { reason: 'upstream_unavailable' } });
  }
  assert.equal(broadcasts(calls).length, 2);
  // Another note takes its own unit.
  mined = 4n;
  await signer.handle('eth_sendTransaction', [retire(10, 5n)]);
  assert.equal(await units(), 2);
  // Once nonce 4 is mined (say it reverted after a root race), the note is
  // re-sent on a new nonce for a new unit; its fee replacements stay free.
  mined = 5n;
  await signer.handle('eth_sendTransaction', [retire(9, 6n)]);
  await signer.handle('eth_sendTransaction', [{ ...retire(9, 6n), ...fees(6n * GWEI, 3n * GWEI) }]);
  assert.equal(await units(), 3);
  assert.equal(broadcasts(calls).length, 5);
  // The budget is spent: a fourth nonce is refused before any upstream call,
  // even once every earlier one is mined, while a counted nonce still signs.
  mined = 7n;
  const spent = { code: -32003, message: 'Leaf retirement budget for the last 24 hours is spent', data: { reason: 'retirement_budget_exhausted', max_retirements_per_day: '0x3' } };
  const fourth = await send(retire(9, 7n));
  assert.deepEqual(fourth.error, spent);
  assert.deepEqual(fourth.methods, []);
  await signer.handle('eth_sendTransaction', [{ ...retire(10, 5n), ...fees(7n * GWEI, 3n * GWEI) }]);
  assert.equal(broadcasts(calls).length, 6);
  // At a budget of one, the same note on fifty successive nonces signs once.
  const one = fixture({ eth_getTransactionCount: '0x4' }, { maxRetirementsPerDay: 1n });
  for (let nonce = 4n; nonce < 54n; nonce += 1n) {
    await one.signer.handle('eth_sendTransaction', [retire(9, nonce)]).catch(error => assert.equal(error.data?.reason, 'retirement_budget_exhausted'));
  }
  assert.deepEqual(broadcasts(one.calls).map(call => Transaction.from(call.params[0]).nonce), [4]);
});

test('a retirement follows the operator policy: retire-on-miss is on and an escape of the note finalized within the lookback', async () => {
  assert.equal(ESCAPE_FINALIZED_TOPIC, keccak256(Buffer.from('EscapeWithdrawalFinalized(uint32,uint256,uint128,address)')));
  const noteTopic = note => `0x${note.toString(16).padStart(64, '0')}`;
  const finalized = (note, extra = {}) => ({ address: vault, topics: [ESCAPE_FINALIZED_TOPIC, noteTopic(note)], data: `0x${'00'.repeat(96)}`, removed: false, ...extra });
  // Logs by block: note 9's escape finalized at block 30,000 of 100,000.
  let found = { 30_000n: [finalized(9)] };
  const ranges = [];
  const getLogs = filter => {
    assert.equal(filter.address, vault);
    assert.deepEqual(filter.topics, [ESCAPE_FINALIZED_TOPIC, noteTopic(BigInt(filter.topics[1]))]);
    const [from, to] = [BigInt(filter.fromBlock), BigInt(filter.toBlock)];
    ranges.push([from, to]);
    return Object.entries(found).filter(([block]) => BigInt(block) >= from && BigInt(block) <= to).flatMap(([, logs]) => logs);
  };
  const { signer, calls, logs } = fixture({ eth_blockNumber: wei(100_000n), eth_getLogs: getLogs, eth_getTransactionCount: '0x4' },
    { maxRetirementsPerDay: 5n, retirementLookbackBlocks: 80_000n });
  assert.deepEqual([signer.policy.retire_on_miss, signer.policy.retirement_lookback_blocks], [true, 80_000]);
  // Found three 10,000-block ranges back, newest first: the retirement signs.
  await signer.handle('eth_sendTransaction', [retire(9, 4n)]);
  assert.deepEqual(ranges, [[90_001n, 100_000n], [80_001n, 90_000n], [70_001n, 80_000n], [60_001n, 70_000n],
    [50_001n, 60_000n], [40_001n, 50_000n], [30_001n, 40_000n], [20_001n, 30_000n]]);
  assert.equal(broadcasts(calls).length, 1);
  // A fee replacement on the counted nonce does not read the logs again.
  ranges.length = 0;
  await signer.handle('eth_sendTransaction', [{ ...retire(9, 4n), ...fees(5n * GWEI, 2n * GWEI) }]);
  assert.deepEqual(ranges, []);
  // No finalization of note 10 within the lookback (one at 20,000 is
  // older; another note's, a removed log and another contract's do not
  // count): refused after the whole lookback, nothing simulated or sent, no budget taken.
  found = { 20_000n: [finalized(10)], 50_000n: [finalized(11), finalized(10, { removed: true }), finalized(10, { address: '0x0000000000000000000000000000000000004321' })] };
  ranges.length = 0;
  const before = calls.length;
  const refused = { code: -32003, message: 'No escape of this note finalized within the retirement lookback',
    data: { reason: 'retirement_not_after_escape', note_id: '0xa', lookback_blocks: wei(80_000n) } };
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(10, 5n)]), refused);
  assert.deepEqual(ranges.at(-1), [20_001n, 30_000n]);
  assert.equal(ranges.length, 8);
  assert.ok(!calls.slice(before).some(call => ['eth_call', 'eth_estimateGas', 'eth_sendRawTransaction'].includes(call.method)));
  assert.equal((await signer.handle('zkapi_signerStatus', [])).retirements_last_24h, 1);
  assert.deepEqual(logs.at(-1), { event: 'challenge_refused', nonce: 5, code: -32003, reason: 'retirement_not_after_escape',
    message: refused.message, note_id: '10', lookback_blocks: '80000' });
  // An unreadable log range is transient and takes nothing.
  const flaky = fixture({ eth_getLogs: () => { throw new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'); } });
  await assert.rejects(flaky.signer.handle('eth_sendTransaction', [retire(9)]), { code: -32000, data: { reason: 'upstream_unavailable' } });
  assert.equal(broadcasts(flaky.calls).length, 0);
  const malformed = fixture({ eth_getLogs: { logs: [] } });
  await assert.rejects(malformed.signer.handle('eth_sendTransaction', [retire(9)]), { code: -32000, data: { reason: 'upstream_unavailable' } });
  // With retire-on-miss off, every retirement is refused before any upstream
  // call; defeats and raises still sign.
  const off = fixture({}, { retireOnMiss: false });
  assert.equal(off.signer.policy.retire_on_miss, false);
  await assert.rejects(off.signer.handle('eth_sendTransaction', [retire(9)]),
    { code: -32003, message: 'Leaf retirements are off (ZKAPI_CHALLENGE_RETIRE_ON_MISS=false)', data: { reason: 'retirement_disabled' } });
  assert.equal(off.calls.length, 0);
  await off.signer.handle('eth_sendTransaction', [validTx]);
  assert.equal(broadcasts(off.calls).length, 1);
  for (const [option, value] of [['retireOnMiss', 'yes'], ['retirementLookbackBlocks', 0n], ['retirementLookbackBlocks', 5_000_001n], ['retirementLookbackBlocks', 10]]) {
    assert.throws(() => fixture({}, { [option]: value }), { message: option === 'retireOnMiss' ? 'Retirement policy is invalid' : 'Retirement lookback is invalid' });
  }
});

test('fee proposals outside 0 < tip <= max fee <= cap and tip <= tip cap are refused before any RPC', async () => {
  const options = { maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 5n * GWEI };
  const bounds = { reason: 'fee_out_of_bounds', max_fee_per_gas: wei(50n * GWEI), max_priority_fee_per_gas: wei(5n * GWEI) };
  for (const [proposal, message] of [
    [fees(10n * GWEI, 0n), 'Requested fees are outside the configured bounds'],
    [fees(0n, 0n), 'Requested fees are outside the configured bounds'],
    [fees(2n * GWEI, 3n * GWEI), 'Requested fees are outside the configured bounds'],
    [fees(50n * GWEI + 1n, GWEI), 'Requested fees are outside the configured bounds'],
    [fees(50n * GWEI, 5n * GWEI + 1n), 'Requested fees are outside the configured bounds'],
    [{ maxFeePerGas: wei(10n * GWEI) }, 'maxFeePerGas and maxPriorityFeePerGas must be supplied together'],
    [{ maxPriorityFeePerGas: wei(GWEI) }, 'maxFeePerGas and maxPriorityFeePerGas must be supplied together'],
  ]) {
    const { signer, calls } = fixture({}, options);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...proposal }]), { code: -32602, message, data: bounds }, JSON.stringify(proposal));
    assert.equal(calls.length, 0);
  }
});

test('gas limit x max fee above the transaction fee cap is refused before any RPC, for default and proposed bids; the cap itself signs', async () => {
  const gas = 8_000_000n;
  const message = 'Gas limit times max fee per gas exceeds the transaction fee cap';
  for (const [transaction, maxFee] of [[validTx, 10n * GWEI], [{ ...validTx, ...fees(3n * GWEI, GWEI) }, 3n * GWEI]]) {
    const exact = fixture({}, { txFeeCap: gas * maxFee });
    const hash = await exact.signer.handle('eth_sendTransaction', [transaction]);
    const [sent] = broadcasts(exact.calls);
    assert.equal(hash, keccak256(sent.params[0]));
    assert.equal(Transaction.from(sent.params[0]).maxFeePerGas, maxFee);
    // One wei above the cap: refused before the chain, simulation or any broadcast.
    const cap = gas * maxFee - 1n;
    const above = fixture({}, { txFeeCap: cap });
    await assert.rejects(above.signer.handle('eth_sendTransaction', [transaction]), {
      code: -32003, message,
      data: { reason: 'tx_fee_above_cap', gas_limit: wei(gas), max_fee_per_gas: wei(maxFee), tx_fee_cap_wei: wei(cap), max_fee_per_gas_allowed: wei(maxFee - 1n) },
    });
    assert.deepEqual(above.calls, []);
    assert.deepEqual(above.logs, [{
      event: 'challenge_refused', nonce: 4, code: -32003, reason: 'tx_fee_above_cap', message, gas_limit: '8000000',
      max_fee_per_gas_wei: String(maxFee), tx_fee_cap_wei: String(cap), max_fee_per_gas_allowed_wei: String(maxFee - 1n),
    }]);
  }
});

test('the default 1 ETH transaction fee cap bounds a measured 7.53M-gas challenge to about 132.7 gwei', async () => {
  const gas = 7_534_341n; // 6,278,618 measured, plus the daemon's 20%
  const challenge = { ...validTx, gas: wei(gas) };
  const allowed = DEFAULT_TX_FEE_CAP / gas;
  assert.equal(allowed, 132_725_609_313n);
  // The default bid (a 300 gwei cap: 2.26 ETH), the reviewed 142 gwei first bid (1.07 ETH) and one wei above the ceiling,
  // from a sender funded for all of them.
  for (const [transaction, maxFee] of [[challenge, 300n * GWEI], [{ ...challenge, ...fees(142n * GWEI, 2n * GWEI) }, 142n * GWEI], [{ ...challenge, ...fees(allowed + 1n, 2n * GWEI) }, allowed + 1n]]) {
    const { signer, calls } = fixture({ eth_getBalance: wei(10n * DEFAULT_TX_FEE_CAP) }, { maxFeePerGas: 300n * GWEI });
    await assert.rejects(signer.handle('eth_sendTransaction', [transaction]), {
      code: -32003,
      data: { reason: 'tx_fee_above_cap', gas_limit: wei(gas), max_fee_per_gas: wei(maxFee), tx_fee_cap_wei: ONE_ETH, max_fee_per_gas_allowed: wei(allowed) },
    });
    assert.equal(broadcasts(calls).length, 0);
  }
  const { signer, calls } = fixture({}, { maxFeePerGas: 300n * GWEI });
  await signer.handle('eth_sendTransaction', [{ ...challenge, ...fees(allowed, 2n * GWEI) }]);
  const signed = Transaction.from(broadcasts(calls)[0].params[0]);
  assert.deepEqual([signed.gasLimit, signed.maxFeePerGas], [gas, allowed]);
  assert.ok(signed.gasLimit * signed.maxFeePerGas <= DEFAULT_TX_FEE_CAP);
});

test('upstream wrong chain, failed simulation, base fee above the max fee, missing base fee, low balance and changed estimate never broadcast', async () => {
  const proposed = { ...validTx, ...fees(3n * GWEI, GWEI) };
  for (const [overrides, transaction, expected] of [
    [{ eth_chainId: '0x1' }, validTx, { code: -32000, message: 'Upstream RPC does not match the configured chain', data: { reason: 'upstream_chain_mismatch' } }],
    [{ eth_chainId: '0x01' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid chain ID', data: { reason: 'upstream_unavailable' } }],
    [{ eth_call: new RpcError(-32000, 'reverted', 'upstream_rejected') }, validTx, { code: -32000, message: 'Challenge simulation failed', data: { reason: 'simulation_failed' } }],
    [{ eth_estimateGas: new RpcError(-32000, 'rate limited', 'upstream_rejected') }, validTx, { code: -32000, message: 'Challenge simulation failed', data: { reason: 'simulation_failed' } }],
    [{ eth_call: new RpcError(-32000, 'down', 'upstream_unavailable') }, validTx, { code: -32000, message: 'down', data: { reason: 'upstream_unavailable' } }],
    [{ eth_estimateGas: '0xffffff' }, validTx, { code: -32602, message: 'Gas limit is below current estimate', data: { reason: 'gas_estimate_exceeds_limit', estimate: '0xffffff' } }],
    [{ eth_estimateGas: '0x' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid gas estimate', data: { reason: 'upstream_unavailable' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be401' } }, validTx, { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: '0x2540be401', max_fee_per_gas: '0x2540be400' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: wei(3n * GWEI + 1n) } }, proposed, { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: wei(3n * GWEI + 1n), max_fee_per_gas: wei(3n * GWEI) } }],
    [{ eth_getBlockByNumber: { number: '0x10' } }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBlockByNumber: null }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x01' } }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBalance: '0x0' }, validTx, { code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas', data: { reason: 'insufficient_balance', balance: '0x0', required_balance: wei(8_000_000n * 10n * GWEI) } }],
    [{ eth_getBalance: wei(8_000_000n * 3n * GWEI - 1n) }, proposed, { code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas', data: { reason: 'insufficient_balance', balance: wei(8_000_000n * 3n * GWEI - 1n), required_balance: wei(8_000_000n * 3n * GWEI) } }],
    [{ eth_getBalance: '1000' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid balance', data: { reason: 'upstream_unavailable' } }],
  ]) {
    const { signer, calls } = fixture(overrides);
    await assert.rejects(signer.handle('eth_sendTransaction', [transaction]), expected, JSON.stringify(overrides));
    assert.equal(broadcasts(calls).length, 0);
  }
});

test('every failure is either a definite non-broadcast or broadcast_ambiguous carrying the candidate hash', async () => {
  const methods = ['eth_chainId', 'eth_call', 'eth_estimateGas', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_sendRawTransaction', 'eth_getTransactionByHash'];
  const faults = [
    new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'),
    new RpcError(-32000, 'Upstream RPC rejected the request', 'upstream_rejected'),
    new Error('unexpected failure'), 'malformed', null, {}, `0x${'cd'.repeat(32)}`,
  ];
  // What createUpstream raises for a node's own fee-cap refusal of a broadcast.
  const feeCapRefusal = new RpcError(-32000, 'Upstream RPC rejected the request', 'upstream_tx_fee_cap');
  for (const method of methods) {
    for (const fault of method === 'eth_sendRawTransaction' ? [...faults, feeCapRefusal] : faults) {
      const overrides = { [method]: fault };
      if (method === 'eth_getTransactionByHash') overrides.eth_sendRawTransaction = new RpcError(-32000, 'already known', 'upstream_rejected');
      const { signer, calls } = fixture(overrides);
      const outcome = await signer.handle('eth_sendTransaction', [validTx]).then(hash => ({ hash }), error => ({ error }));
      const sent = broadcasts(calls);
      const label = `${method} -> ${fault instanceof Error ? `${fault.message}${fault.data ? ` (${fault.data.reason})` : ''}` : JSON.stringify(fault)}`;
      if (fault === feeCapRefusal) assert.equal(outcome.error?.data?.reason, 'upstream_tx_fee_cap', label);
      if (outcome.error?.data?.reason === 'broadcast_ambiguous') {
        assert.equal(outcome.error.code, -32000, label);
        assert.equal(sent.length, 1, label);
        assert.equal(outcome.error.data.transaction_hash, keccak256(sent[0].params[0]), label);
        assert.equal(calls.at(-1).method === 'eth_sendRawTransaction' || calls.at(-1).method === 'eth_getTransactionByHash', true, label);
      } else if (outcome.error?.data?.reason === 'upstream_tx_fee_cap') {
        // The node refused the broadcast before its pool: definite, and no hash to track.
        assert.equal(fault, feeCapRefusal, label);
        assert.equal(outcome.error.code, -32003, label);
        assert.equal(sent.length, 1, label);
        assert.equal(outcome.error.data.transaction_hash, undefined, label);
      } else if (outcome.error) {
        assert.equal(sent.length, 0, label);
      } else {
        assert.equal(sent.length, 1, label);
        assert.equal(outcome.hash, keccak256(sent[0].params[0]), label);
      }
    }
  }
});

test('base fee at the max fee still signs; the effective tip shrinks, the bid does not change', async () => {
  const { signer, calls } = fixture({ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be400' } });
  await signer.handle('eth_sendTransaction', [validTx]);
  const signed = Transaction.from(calls.at(-1).params[0]);
  assert.equal(signed.maxFeePerGas, 10n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 1n * GWEI);
});

test('daemon replacement on the same nonce changes only the proposed fees', async () => {
  const { signer, calls } = fixture({}, { maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 20n * GWEI });
  const first = await signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(4n * GWEI, GWEI) }]);
  const bump = fees(9n * GWEI / 2n, 9n * GWEI / 8n);
  const bumped = await signer.handle('eth_sendTransaction', [{ ...validTx, ...bump }]);
  const raws = broadcasts(calls).map(c => Transaction.from(c.params[0]));
  assert.equal(raws.length, 2);
  assert.notEqual(first, bumped);
  for (const field of ['type', 'nonce', 'to', 'data', 'value', 'chainId', 'gasLimit', 'from', 'accessList']) {
    assert.deepEqual(raws[1][field], raws[0][field], field);
  }
  assert.deepEqual([raws[0].maxFeePerGas, raws[0].maxPriorityFeePerGas], [4n * GWEI, GWEI]);
  assert.deepEqual([raws[1].maxFeePerGas, raws[1].maxPriorityFeePerGas], [9n * GWEI / 2n, 9n * GWEI / 8n]);
  const before = calls.length;
  for (const change of [{ to: sender }, { value: '0x1' }, { data: '0xdeadbeef' }, { gasPrice: '0x1' }, { type: '0x2' }, fees(50n * GWEI + 1n, 2n * GWEI), fees(30n * GWEI, 20n * GWEI + 1n)]) {
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...bump, ...change }]), RpcError, JSON.stringify(change));
  }
  assert.equal(calls.length, before);
});

test('ambiguous sends retain the caller nonce, report the candidate hash, and the retry queue remains usable', async () => {
  const { signer, calls } = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'Unavailable', 'upstream_unavailable') });
  const first = await signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
  const second = await signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
  const sends = broadcasts(calls);
  assert.equal(sends.length, 2);
  assert.equal(sends[0].params[0], sends[1].params[0]);
  const decoded = Transaction.from(sends[1].params[0]);
  assert.equal(decoded.nonce, 4);
  for (const error of [first, second]) {
    assert.ok(error instanceof RpcError);
    assert.equal(error.code, -32000);
    assert.equal(error.message, 'Transaction broadcast outcome is unknown');
    assert.deepEqual(error.data, { reason: 'broadcast_ambiguous', transaction_hash: keccak256(sends[0].params[0]) });
    assert.equal(error.data.transaction_hash, decoded.hash);
  }
  assert.equal(calls.filter(call => call.method === 'eth_getTransactionByHash').length, 2);
});

test('an already-known identical rebroadcast returns the locally computed hash', async () => {
  let known;
  const { signer, calls } = fixture({
    eth_sendRawTransaction: raw => { known = keccak256(raw); throw new RpcError(-32000, 'already known', 'upstream_rejected'); },
    eth_getTransactionByHash: hash => (hash === known ? { hash: known.toUpperCase().replace('0X', '0x'), blockNumber: null } : null),
  });
  assert.equal(await signer.handle('eth_sendTransaction', [validTx]), known);
  assert.equal(calls.at(-1).method, 'eth_getTransactionByHash');
  assert.deepEqual(calls.at(-1).params, [known]);
});

test('an invalid or mismatched upstream transaction hash remains an ambiguous send error', async () => {
  for (const returned of ['0x', `0x${'ab'.repeat(32)}`, null]) {
    const { signer, calls } = fixture({ eth_sendRawTransaction: returned });
    const error = await signer.handle('eth_sendTransaction', [validTx]).catch(failure => failure);
    assert.ok(error instanceof RpcError);
    assert.deepEqual([error.code, error.message, error.data], [-32000, 'Transaction broadcast outcome is unknown',
      { reason: 'broadcast_ambiguous', transaction_hash: keccak256(broadcasts(calls)[0].params[0]) }]);
    assert.equal(calls.at(-1).method, 'eth_sendRawTransaction');
  }
});

test('a node fee-cap refusal of the broadcast is a definite refusal without a hash; other send failures stay ambiguous', async t => {
  const geth = 'tx fee (1.07 ether) exceeds the configured cap (1.00 ether)';
  const reads = {
    eth_chainId: wei(CHAIN_ID), eth_call: '0x', eth_estimateGas: '0x6acfc0', eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x3b9aca00' },
    eth_getBalance: ONE_ETH, eth_getTransactionByHash: null,
  };
  let answer;
  const upstream = createServer(async (request, response) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      const { id, method } = JSON.parse(body);
      const reply = payload => response.end(JSON.stringify({ jsonrpc: '2.0', id, ...payload }));
      if (method !== 'eth_sendRawTransaction') return reply({ result: reads[method] });
      return answer(reply, response);
    } catch { response.destroy(); } // a request its client abandoned part-way
  }).listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => { upstream.closeAllConnections(); upstream.close(); });
  const url = `http://127.0.0.1:${upstream.address().port}`;
  let raw;
  // Every call keeps the default timeout, so a slow answer on a loaded host is never
  // mistaken for another outcome; only a broadcast the node never answers gets a short one.
  const send = async (respond, { broadcastTimeoutMs = UPSTREAM_TIMEOUT_MS } = {}) => {
    answer = respond;
    raw = undefined;
    const logs = [];
    const read = createUpstream(url);
    const broadcast = createUpstream(url, { timeoutMs: broadcastTimeoutMs });
    const rpc = (method, params) => {
      if (method !== 'eth_sendRawTransaction') return read(method, params);
      [raw] = params;
      return broadcast(method, params);
    };
    const signer = createSigner({ privateKey: key, vault, rpc, chainId: CHAIN_ID, log: line => logs.push(line) });
    const error = await signer.handle('eth_sendTransaction', [validTx]).then(() => assert.fail('the send cannot succeed'), failure => failure);
    assert.ok(raw, 'the broadcast was attempted');
    return { error, logs };
  };
  // geth's JSON-RPC error answer, whatever its code, amounts or letter case.
  for (const error of [{ code: -32000, message: geth }, { code: -32000, message: 'tx fee (2.05 ether) exceeds the configured cap (1.00 ether)' }, { code: 3, message: geth.toUpperCase() }]) {
    const { error: refused, logs } = await send(reply => reply({ error }));
    assert.ok(refused instanceof RpcError);
    assert.deepEqual([refused.code, refused.message, refused.data], [-32003, 'Upstream RPC refused the transaction fee',
      { reason: 'upstream_tx_fee_cap', gas_limit: wei(8_000_000n), max_fee_per_gas: wei(10n * GWEI) }]);
    assert.deepEqual(logs, [{ event: 'challenge_refused', nonce: 4, code: -32003, reason: 'upstream_tx_fee_cap', message: 'Upstream RPC refused the transaction fee', gas_limit: '8000000', max_fee_per_gas_wei: '10000000000' }]);
  }
  // Any other answer may follow a broadcast: transport errors, timeouts, malformed
  // replies and every other rejection stay ambiguous with the candidate hash.
  const never = () => {};
  for (const respond of [
    reply => reply({ error: { code: -32000, message: 'nonce too low' } }),
    reply => reply({ error: { code: -32000, message: 'replacement transaction underpriced' } }),
    reply => reply({ error: { code: -32000, message: 'insufficient funds for gas * price + value' } }),
    reply => reply({ error: { code: -32000, message: 'execution reverted', data: geth } }),
    reply => reply({ error: { code: -32000, message: `${geth} ${'x'.repeat(256)}` } }),
    reply => reply({ error: geth }),
    (reply, response) => { response.statusCode = 500; reply({ error: { code: -32000, message: geth } }); },
    (_reply, response) => response.end(geth),
    never,
  ]) {
    const { error } = await send(respond, respond === never ? { broadcastTimeoutMs: 300 } : undefined);
    assert.deepEqual([error.code, error.data], [-32000, { reason: 'broadcast_ambiguous', transaction_hash: keccak256(raw) }], respond.toString());
  }
  // A node that lowered its cap after accepting the identical transaction still has it pending.
  const known = fixture({
    eth_sendRawTransaction: new RpcError(-32000, 'Upstream RPC rejected the request', 'upstream_tx_fee_cap'),
    eth_getTransactionByHash: hash => ({ hash }),
  });
  assert.equal(await known.signer.handle('eth_sendTransaction', [validTx]), keccak256(broadcasts(known.calls)[0].params[0]));
});

test('audit logging can never change the RPC outcome', async () => {
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    for (const log of [() => { throw new Error('log sink failed'); }, async () => { throw new Error('async log sink failed'); }, () => ({ then() { throw new Error('bad thenable'); } })]) {
      const ok = fixture({}, { log });
      assert.equal(await ok.signer.handle('eth_sendTransaction', [validTx]), keccak256(ok.calls.at(-1).params[0]));
      const lost = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'down', 'upstream_unavailable') }, { log });
      const ambiguous = await lost.signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
      assert.deepEqual(ambiguous.data, { reason: 'broadcast_ambiguous', transaction_hash: keccak256(broadcasts(lost.calls)[0].params[0]) });
      const refused = fixture({ eth_getBalance: '0x0' }, { log });
      await assert.rejects(refused.signer.handle('eth_sendTransaction', [validTx]), { code: -32003, data: { reason: 'insufficient_balance', balance: '0x0', required_balance: wei(8_000_000n * 10n * GWEI) } });
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('RPC method allowlist excludes generic signing, account management, fee oracles and raw broadcasts', async () => {
  const feeHistory = { oldestBlock: '0xf', baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], gasUsedRatio: [0.5], reward: [['0x3b9aca00']] };
  const { signer, calls } = fixture({ eth_feeHistory: feeHistory, eth_getCode: '0x6000' });
  for (const method of ['eth_sendRawTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData_v4', 'personal_unlockAccount', 'admin_peers', 'debug_traceCall', 'eth_signTransaction', 'eth_accounts', 'eth_gasPrice', 'eth_maxPriorityFeePerGas']) {
    await assert.rejects(signer.handle(method, []), { code: -32601 });
  }
  assert.equal(calls.length, 0);
  assert.equal(await signer.handle('eth_blockNumber', []), '0x1');
  assert.equal(await signer.handle('eth_getBalance', [sender, 'latest']), ONE_ETH);
  assert.deepEqual(await signer.handle('eth_feeHistory', ['0x1', 'latest', [50]]), feeHistory);
  // The challenger's startup codehash probes read code through the signer.
  assert.equal(await signer.handle('eth_getCode', [vault, 'latest']), '0x6000');
  assert.deepEqual(calls.map(c => [c.method, c.params]), [['eth_blockNumber', []], ['eth_getBalance', [sender, 'latest']],
    ['eth_feeHistory', ['0x1', 'latest', [50]]], ['eth_getCode', [vault, 'latest']]]);
});

test('signer status reports policy, base fee, balance coverage and warnings', async () => {
  const healthy = await fixture().signer.handle('zkapi_signerStatus', []);
  assert.deepEqual(healthy, {
    chain_id: '0xaa36a7', sender: sender.toLowerCase(), vault, transaction_type: '0x2', fee_cap_source: 'default',
    max_fee_per_gas: '0x2540be400', priority_fee_per_gas: '0x3b9aca00', max_priority_fee_per_gas: '0x2540be400',
    fee_ceiling: '0x9184e72a000', tx_fee_cap_wei: ONE_ETH, max_gas: '0xb71b00', required_balance: '0x1aa535d3d0c0000',
    max_retirements_per_day: 2, retire_on_miss: true, retirement_lookback_blocks: 50400,
    retirements_last_24h: 0, retirement_refusals: 0, last_retirement_refusal_at: null,
    block_number: '0x10', base_fee_per_gas: '0x3b9aca00', balance: ONE_ETH, warnings: [],
  });
  const warnings = async (baseFee, balance = ONE_ETH) => (await fixture({
    eth_getBlockByNumber: { number: '0x11', baseFeePerGas: wei(baseFee) }, eth_getBalance: wei(BigInt(balance)),
  }).signer.handle('zkapi_signerStatus', [])).warnings;
  // Near the cap once baseFee x 1.125 + default tip (1 gwei) exceeds the 10 gwei cap.
  assert.deepEqual(await warnings(8n * GWEI), []);
  assert.deepEqual(await warnings(8n * GWEI + 1n), ['base_fee_near_cap']);
  assert.deepEqual(await warnings(10n * GWEI), ['base_fee_near_cap']);
  assert.deepEqual(await warnings(10n * GWEI + 1n), ['base_fee_above_cap', 'base_fee_near_cap']);
  assert.deepEqual(await warnings(GWEI, 12_000_000n * 10n * GWEI), []);
  assert.deepEqual(await warnings(GWEI, 12_000_000n * 10n * GWEI - 1n), ['balance_below_required']);
  assert.deepEqual(await warnings(10n * GWEI + 1n, 1n), ['base_fee_above_cap', 'base_fee_near_cap', 'balance_below_required']);
  await assert.rejects(fixture().signer.handle('zkapi_signerStatus', [1]), { code: -32602, message: 'Expected no parameters' });
  await assert.rejects(fixture({ eth_chainId: '0x1' }).signer.handle('zkapi_signerStatus', []), { code: -32000, message: 'Upstream RPC does not match the configured chain', data: { reason: 'upstream_chain_mismatch' } });
  await assert.rejects(fixture({ eth_getBlockByNumber: { number: '0x11' } }).signer.handle('zkapi_signerStatus', []), { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } });
});

test('status reports the transaction fee cap and warns once MAX_GAS x fee cap exceeds it', async () => {
  const status = options => fixture({ eth_getBalance: wei(10n ** 20n) }, options).signer.handle('zkapi_signerStatus', []);
  const maxGas = 12_000_000n;
  // At the defaults, 12M gas x 10 gwei is 0.12 ETH, well within 1 ETH.
  assert.deepEqual([(await status()).tx_fee_cap_wei, (await status()).warnings], [ONE_ETH, []]);
  assert.deepEqual((await status({ txFeeCap: maxGas * 10n * GWEI })).warnings, []);
  const below = await status({ txFeeCap: maxGas * 10n * GWEI - 1n });
  assert.deepEqual([below.tx_fee_cap_wei, below.warnings], [wei(maxGas * 10n * GWEI - 1n), ['tx_fee_cap_below_fee_cap']]);
  // A 100 gwei cap at the default 12M gas and 1 ETH: only about 83.3 gwei per gas fits.
  assert.deepEqual((await status({ maxFeePerGas: 100n * GWEI })).warnings, ['tx_fee_cap_below_fee_cap']);
  assert.deepEqual((await status({ maxFeePerGas: 100n * GWEI, maxGas: 8_000_000n })).warnings, []);
  assert.deepEqual((await status({ maxFeePerGas: 300n * GWEI, txFeeCap: maxGas * 300n * GWEI })).warnings, []);
});

test('between the MAX_GAS warning and the real gas limit, status warns but a challenge without fee proposals still signs', async () => {
  // At the default 12M MAX_GAS and 1 ETH the warning starts above about 83.3 gwei, while a
  // 7.53M-gas challenge bid at the fee cap (an earlier daemon proposes no fees) fits up to about 132.7 gwei.
  const gas = 7_534_341n;
  const challenge = { ...validTx, gas: wei(gas) };
  const allowed = DEFAULT_TX_FEE_CAP / gas;
  const funded = { eth_getBalance: wei(10n * DEFAULT_TX_FEE_CAP) };
  for (const maxFeePerGas of [DEFAULT_TX_FEE_CAP / 12_000_000n + 1n, 100n * GWEI, allowed]) {
    const { signer, calls } = fixture(funded, { maxFeePerGas });
    assert.deepEqual((await signer.handle('zkapi_signerStatus', [])).warnings, ['tx_fee_cap_below_fee_cap'], String(maxFeePerGas));
    const hash = await signer.handle('eth_sendTransaction', [challenge]);
    const [sent] = broadcasts(calls);
    const signed = Transaction.from(sent.params[0]);
    assert.equal(hash, keccak256(sent.params[0]));
    assert.deepEqual([signed.gasLimit, signed.maxFeePerGas, signed.maxPriorityFeePerGas], [gas, maxFeePerGas, GWEI]);
  }
  // One wei above the ceiling, the same default bid is refused before any upstream call.
  const { signer, calls } = fixture(funded, { maxFeePerGas: allowed + 1n });
  await assert.rejects(signer.handle('eth_sendTransaction', [challenge]), {
    code: -32003,
    data: { reason: 'tx_fee_above_cap', gas_limit: wei(gas), max_fee_per_gas: wei(allowed + 1n), tx_fee_cap_wei: ONE_ETH, max_fee_per_gas_allowed: wei(allowed) },
  });
  assert.deepEqual(calls, []);
  // Lowering MAX_GAS toward the gas limit clears the warning; the same challenge still signs.
  const lowered = fixture(funded, { maxFeePerGas: 100n * GWEI, maxGas: 7_600_000n });
  assert.deepEqual((await lowered.signer.handle('zkapi_signerStatus', [])).warnings, []);
  await lowered.signer.handle('eth_sendTransaction', [challenge]);
  assert.equal(broadcasts(lowered.calls).length, 1);
});

test('base-fee and balance reads run in parallel when signing and in status', async () => {
  // Each read resolves only after both were requested; sequential reads time out.
  const gate = () => {
    let arrived = 0;
    let release;
    const both = new Promise(resolve => { release = resolve; });
    return value => async () => {
      if (++arrived === 2) release();
      await Promise.race([both, sleep(2_000, undefined, { ref: false }).then(() => { throw new Error('reads were sequential'); })]);
      return value;
    };
  };
  for (const run of [signer => signer.handle('eth_sendTransaction', [validTx]), signer => signer.handle('zkapi_signerStatus', [])]) {
    const reads = gate();
    const { signer } = fixture({ eth_getBlockByNumber: reads({ number: '0x10', baseFeePerGas: '0x3b9aca00' }), eth_getBalance: reads(ONE_ETH) });
    await run(signer);
  }
});

test('HTTP errors suppress provider details, carry structured refusal reasons, and health reports the fee policy', async t => {
  const secret = 'https://provider.invalid/private-key-material';
  const { signer } = fixture({ eth_blockNumber: new Error(secret) });
  const server = createHttpServer(signer).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = value => fetch(base, { method: 'POST', body: JSON.stringify(value) }).then(r => r.json());
  const health = await fetch(`${base}/health`).then(r => r.json());
  assert.deepEqual(health, {
    status: 'ok', chain_id: Number(CHAIN_ID), sender: sender.toLowerCase(), vault, transaction_type: '0x2', fee_cap_source: 'default',
    max_fee_per_gas: '0x2540be400', priority_fee_per_gas: '0x3b9aca00', max_priority_fee_per_gas: '0x2540be400',
    fee_ceiling: '0x9184e72a000', tx_fee_cap_wei: ONE_ETH, max_gas: '0xb71b00', required_balance: '0x1aa535d3d0c0000',
    max_retirements_per_day: 2, retire_on_miss: true, retirement_lookback_blocks: 50400,
    retirements_last_24h: 0, retirement_refusals: 0, last_retirement_refusal_at: null,
  });
  const failed = await post({ jsonrpc: '2.0', id: 8, method: 'eth_blockNumber', params: [] });
  assert.deepEqual(failed, { jsonrpc: '2.0', id: 8, error: { code: -32603, message: 'Signer request failed' } });
  assert.ok(!JSON.stringify(failed).includes(secret));
  assert.equal((await post([])).error.code, -32600);
  assert.equal((await post({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: {} })).error.code, -32602);
  const outOfBounds = await post({ jsonrpc: '2.0', id: 3, method: 'eth_sendTransaction', params: [{ ...validTx, ...fees(10n * GWEI + 1n, GWEI) }] });
  assert.deepEqual(outOfBounds, { jsonrpc: '2.0', id: 3, error: { code: -32602, message: 'Requested fees are outside the configured bounds', data: { reason: 'fee_out_of_bounds', max_fee_per_gas: '0x2540be400', max_priority_fee_per_gas: '0x2540be400' } } });
  const spiking = createHttpServer(fixture({ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be401' } }).signer).listen(0, '127.0.0.1');
  await once(spiking, 'listening');
  t.after(() => spiking.close());
  const refused = await fetch(`http://127.0.0.1:${spiking.address().port}`, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'eth_sendTransaction', params: [validTx] }) }).then(r => r.json());
  assert.deepEqual(refused, { jsonrpc: '2.0', id: 2, error: { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: '0x2540be401', max_fee_per_gas: '0x2540be400' } } });
  const capped = createHttpServer(fixture({}, { txFeeCap: 8_000_000n * 10n * GWEI - 1n }).signer).listen(0, '127.0.0.1');
  await once(capped, 'listening');
  t.after(() => capped.close());
  const overCap = await fetch(`http://127.0.0.1:${capped.address().port}`, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'eth_sendTransaction', params: [validTx] }) }).then(r => r.json());
  assert.deepEqual(overCap, { jsonrpc: '2.0', id: 4, error: { code: -32003, message: 'Gas limit times max fee per gas exceeds the transaction fee cap', data: {
    reason: 'tx_fee_above_cap', gas_limit: '0x7a1200', max_fee_per_gas: '0x2540be400', tx_fee_cap_wei: wei(8_000_000n * 10n * GWEI - 1n), max_fee_per_gas_allowed: wei(10n * GWEI - 1n),
  } } });
  const wrong = createHttpServer(fixture({ eth_chainId: '0x1' }).signer).listen(0, '127.0.0.1');
  await once(wrong, 'listening');
  t.after(() => wrong.close());
  const unavailable = await fetch(`http://127.0.0.1:${wrong.address().port}/health`);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { status: 'unavailable' });
});

test('upstream enforces encrypted remote transport, bounds every call by a timeout and sanitizes errors', async t => {
  assert.equal(UPSTREAM_TIMEOUT_MS, 8_000);
  assert.throws(() => createUpstream('http://remote.invalid/private-api-key'), configError('Upstream RPC must use HTTPS or loopback HTTP'));
  for (const invalid of [undefined, '', 'not a url private-api-key']) assert.throws(() => createUpstream(invalid), configError('Upstream RPC URL is invalid'));
  const unavailable = { code: -32000, message: 'Upstream RPC request failed', data: { reason: 'upstream_unavailable' } };
  await assert.rejects(createUpstream('http://127.0.0.1:1/private-api-key')('eth_chainId', []), unavailable);
  const sockets = new Set();
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    const route = {
      '/ok': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xaa36a7' })),
      '/rejected': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: 3, message: 'execution reverted: private-api-key', data: '0xdead' } })),
      '/fee-cap': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'tx fee (1.07 ether) exceeds the configured cap (1.00 ether)' } })),
      '/http-error': () => { response.statusCode = 500; response.end('private-api-key'); },
      '/no-result': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1 })),
      '/not-json': () => response.end('private-api-key'),
      '/hang': () => {},
    }[request.url];
    route();
  }).listen(0, '127.0.0.1');
  upstream.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await once(upstream, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); upstream.close(); });
  const at = (path, options) => createUpstream(`http://127.0.0.1:${upstream.address().port}${path}`, options);
  assert.equal(await at('/ok')('eth_chainId', []), '0xaa36a7');
  for (const path of ['/http-error', '/no-result', '/not-json']) await assert.rejects(at(path)('eth_chainId', []), unavailable, path);
  const rejected = await at('/rejected')('eth_call', []).catch(error => error);
  assert.deepEqual({ code: rejected.code, message: rejected.message, data: rejected.data }, { code: -32000, message: 'Upstream RPC rejected the request', data: { reason: 'upstream_rejected' } });
  // A node's fee-cap refusal is told apart only for a raw broadcast, and its text is still dropped.
  const feeCap = await at('/fee-cap')('eth_sendRawTransaction', ['0x02']).catch(error => error);
  assert.deepEqual({ code: feeCap.code, message: feeCap.message, data: feeCap.data }, { code: -32000, message: 'Upstream RPC rejected the request', data: { reason: 'upstream_tx_fee_cap' } });
  assert.deepEqual((await at('/fee-cap')('eth_call', []).catch(error => error)).data, { reason: 'upstream_rejected' });
  const started = Date.now();
  await assert.rejects(at('/hang', { timeoutMs: 200 })('eth_chainId', []), unavailable);
  assert.ok(Date.now() - started < 5_000, 'a hung upstream call is abandoned at its timeout');
});

test('requires an explicit supported chain without a Sepolia fallback', () => {
  for (const value of [undefined, null, '', '01', '0x1', '11155111 ', '137', 1]) assert.throws(() => parseChainId(value), configError('Explicit challenge chain ID must be 1 or 11155111'));
  assert.equal(parseChainId('1'), 1n);
  assert.equal(parseChainId('11155111'), 11155111n);
  for (const chainId of [undefined, 1, '1', 0n, 137n]) assert.throws(() => fixture({}, { chainId }), RpcError);
});

test('Mainnet refuses to start without an explicit fee cap; Sepolia uses a reported default', () => {
  for (const maxFeePerGas of [undefined, null]) {
    assert.throws(() => fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas }), { message: 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI' });
    const { policy } = fixture({}, { maxFeePerGas }).signer;
    assert.deepEqual([policy.fee_cap_source, policy.max_fee_per_gas], ['default', '0x2540be400']);
  }
  assert.throws(() => fixture({}, { maxGasPrice: 50n * GWEI }), { message: 'Unsupported signer option' });
  assert.equal(fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas: 10n * GWEI }).signer.policy.fee_cap_source, 'explicit');
  const env = { ZKAPI_CHALLENGE_CHAIN_ID: '1', ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault, ZKAPI_CHALLENGE_RPC_URL: 'https://rpc.invalid' };
  const { rpcUrl, listenHost, port, ...options } = parseSignerConfig(env);
  assert.deepEqual([rpcUrl, listenHost, port, options.maxFeePerGas], ['https://rpc.invalid', '127.0.0.1', 8547, undefined]);
  assert.throws(() => createSigner({ ...options, rpc: async () => assert.fail('no RPC expected') }), { message: 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI' });
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '' }).maxFeePerGas, undefined);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '50000000000' }).maxFeePerGas, 50n * GWEI);
  const configured = parseSignerConfig({
    ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '300000000000', ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '2000000000',
    ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: '20000000000', ZKAPI_CHALLENGE_FEE_CEILING_WEI: '1000000000000',
    ZKAPI_CHALLENGE_MAX_GAS: '9000000', ZKAPI_CHALLENGE_PORT: '65535', ZKAPI_CHALLENGE_LISTEN_HOST: '',
    ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '2700000000000000000', ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: '0',
  });
  assert.deepEqual(configured, {
    chainId: 1n, privateKey: key, vault, rpcUrl: 'https://rpc.invalid', listenHost: '127.0.0.1', port: 65535, maxGas: 9_000_000n,
    maxFeePerGas: 300n * GWEI, priorityFeePerGas: 2n * GWEI, maxPriorityFeePerGas: 20n * GWEI, feeCeiling: 1_000n * GWEI,
    txFeeCap: 2_700_000_000_000_000_000n, maxRetirementsPerDay: 0n, retireOnMiss: undefined, retirementLookbackBlocks: undefined,
  });
  assert.equal(parseSignerConfig(env).maxRetirementsPerDay, undefined);
  assert.deepEqual([parseSignerConfig(env).retireOnMiss, parseSignerConfig(env).retirementLookbackBlocks], [undefined, undefined]);
  assert.deepEqual([parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIRE_ON_MISS: '', ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS: '' }).retireOnMiss,
    parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS: '' }).retirementLookbackBlocks], [undefined, undefined]);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIRE_ON_MISS: 'false' }).retireOnMiss, false);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIRE_ON_MISS: 'true' }).retireOnMiss, true);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS: '5000000' }).retirementLookbackBlocks, 5_000_000n);
  for (const bad of ['TRUE', '0', '1', 'no', ' true']) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIRE_ON_MISS: bad }), configError('ZKAPI_CHALLENGE_RETIRE_ON_MISS must be true or false'), bad);
  }
  assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS: '5000001' }),
    configError('ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS must be a decimal integer from 1 to 5000000'));
  for (const bad of ['0', '-1', '0x10', '01']) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS: bad }),
      configError('ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS must be a positive decimal integer'), bad);
  }
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: '' }).maxRetirementsPerDay, undefined);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: '1000' }).maxRetirementsPerDay, 1_000n);
  for (const bad of ['1001', '-1', '0x2', '02', ' 2', '2.0', 'two']) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: bad }),
      configError('ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY must be a decimal integer from 0 to 1000'), bad);
  }
  for (const legacy of ['50000000000', '']) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '50000000000', ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI: legacy }),
      configError('ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported; remove it and set ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI (the EIP-1559 fee cap in wei)'));
  }
  for (const name of ['ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_FEE_CEILING_WEI', 'ZKAPI_CHALLENGE_TX_FEE_CAP_WEI', 'ZKAPI_CHALLENGE_MAX_GAS', 'ZKAPI_CHALLENGE_PORT']) {
    for (const bad of ['0', '0x10', '1e9', ' 5', '5 ', '-1', '10.5', '+5', '05', '1_000', 'REPLACE_WITH_FEE_CAP_WEI', '9'.repeat(32)]) {
      assert.throws(() => parseSignerConfig({ ...env, [name]: bad }), configError(`${name} must be a positive decimal integer`), `${name}=${bad}`);
    }
  }
  assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_PORT: '65536' }), configError('ZKAPI_CHALLENGE_PORT must be between 1 and 65535'));
});

test('fee cap, priority fees and the configurable ceiling are mutually bounded', () => {
  const policy = options => fixture({}, options).signer.policy;
  assert.throws(() => policy({ maxFeePerGas: 10_001n * GWEI }), { message: 'Fee cap is invalid or exceeds the fee ceiling' });
  assert.equal(policy({ maxFeePerGas: 20_000n * GWEI, feeCeiling: 20_000n * GWEI }).max_fee_per_gas, wei(20_000n * GWEI));
  assert.equal(policy({ maxFeePerGas: ABSOLUTE_FEE_CEILING, feeCeiling: ABSOLUTE_FEE_CEILING }).fee_ceiling, wei(ABSOLUTE_FEE_CEILING));
  assert.throws(() => policy({ feeCeiling: ABSOLUTE_FEE_CEILING + 1n }), { message: 'Fee ceiling is invalid' });
  for (const feeCeiling of [0n, 10_000, null]) assert.throws(() => policy({ feeCeiling }), { message: 'Fee ceiling is invalid' });
  for (const maxFeePerGas of [0n, -1n, 10, '10000000000']) assert.throws(() => policy({ maxFeePerGas }), { message: 'Fee cap is invalid or exceeds the fee ceiling' });
  for (const maxGas of [0n, 16_777_217n, 1_000, null]) assert.throws(() => policy({ maxGas }), { message: 'Gas limit cap is invalid' });
  // Defaults: tip = min(1 gwei, tip cap); tip cap = min(fee cap, 10 x default tip).
  const tips = options => { const p = policy(options); return [p.priority_fee_per_gas, p.max_priority_fee_per_gas]; };
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI }), [wei(GWEI), wei(10n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 5n * GWEI }), [wei(GWEI), wei(5n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: GWEI / 2n }), [wei(GWEI / 2n), wei(GWEI / 2n)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, priorityFeePerGas: 2n * GWEI }), [wei(2n * GWEI), wei(20n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: GWEI / 2n }), [wei(GWEI / 2n), wei(GWEI / 2n)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 50n * GWEI }), [wei(GWEI), wei(50n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, priorityFeePerGas: null, maxPriorityFeePerGas: null }), [wei(GWEI), wei(10n * GWEI)]);
  for (const maxPriorityFeePerGas of [10n * GWEI + 1n, 0n, 1]) {
    assert.throws(() => policy({ maxFeePerGas: 10n * GWEI, maxPriorityFeePerGas }), { message: 'Priority fee cap is invalid or exceeds the fee cap' });
  }
  for (const options of [{ maxPriorityFeePerGas: 2n * GWEI, priorityFeePerGas: 3n * GWEI }, { priorityFeePerGas: 11n * GWEI }, { priorityFeePerGas: 0n }, { priorityFeePerGas: 1 }]) {
    assert.throws(() => policy({ maxFeePerGas: 10n * GWEI, ...options }), { message: 'Default priority fee is invalid or exceeds the priority fee cap' });
  }
  assert.throws(() => fixture({}, { privateKey: '0x1234' }), { message: 'Signer private key is invalid' });
});

test('ZKAPI_CHALLENGE_TX_FEE_CAP_WEI defaults to 1 ETH and must be a positive decimal', () => {
  const env = { ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault, ZKAPI_CHALLENGE_RPC_URL: 'https://rpc.invalid' };
  const policyFor = extra => {
    const { rpcUrl, listenHost, port, ...options } = parseSignerConfig({ ...env, ...extra });
    return createSigner({ ...options, rpc: async () => assert.fail('no RPC expected') }).policy;
  };
  assert.equal(DEFAULT_TX_FEE_CAP, 1_000_000_000_000_000_000n);
  for (const unset of [{}, { ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '' }]) {
    assert.equal(parseSignerConfig({ ...env, ...unset }).txFeeCap, undefined);
    assert.equal(policyFor(unset).tx_fee_cap_wei, ONE_ETH);
  }
  assert.equal(policyFor({ ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '2260302300000000000' }).tx_fee_cap_wei, wei(2_260_302_300_000_000_000n));
  assert.equal(policyFor({ ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '1' }).tx_fee_cap_wei, '0x1');
  for (const bad of ['0', '00', '0x0de0b6b3a7640000', '1e18', '1000000000000000000 ', '-1', '1.5', '+1', '01', '1_000', 'REPLACE_WITH_TX_FEE_CAP_WEI', '9'.repeat(32)]) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: bad }), configError('ZKAPI_CHALLENGE_TX_FEE_CAP_WEI must be a positive decimal integer'), bad);
  }
  for (const txFeeCap of [0n, -1n, 1_000_000, '1000000000000000000', null]) {
    assert.throws(() => fixture({}, { txFeeCap }), { message: 'Transaction fee cap is invalid' }, String(txFeeCap));
  }
});

test('Mainnet and Sepolia preserve chain-specific signatures, proof bindings and fee bounds', async () => {
  for (const chainId of [1n, 11155111n]) {
    const other = chainId === 1n ? 11155111n : 1n;
    const chainHex = `0x${chainId.toString(16)}`;
    const selectedData = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, chainId, vault, ...inputs.slice(3)], proof]);
    const transaction = { ...validTx, data: selectedData, chainId: chainHex };
    const options = { chainId, maxFeePerGas: 30n * GWEI };
    const { signer, calls } = fixture({ eth_chainId: chainHex }, options);
    await signer.handle('eth_sendTransaction', [transaction]);
    assert.equal(signer.chainId, chainId);
    const signed = Transaction.from(calls.at(-1).params[0]);
    assert.equal(signed.chainId, chainId);
    assert.equal(signed.type, 2);
    assert.equal(signed.maxFeePerGas, 30n * GWEI);
    const baseline = calls.length;
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, chainId: `0x${other.toString(16)}` }]), RpcError);
    const wrongData = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, other, vault, ...inputs.slice(3)], proof]);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, data: wrongData }]), RpcError);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, ...fees(30n * GWEI + 1n, GWEI) }]), RpcError);
    assert.equal(calls.length, baseline);
    for (const overrides of [{ eth_chainId: `0x${other.toString(16)}` }, { eth_getBlockByNumber: { number: '0x1', baseFeePerGas: wei(30n * GWEI + 1n) } }, { eth_estimateGas: '0xffffff' }]) {
      const denied = fixture({ eth_chainId: chainHex, ...overrides }, options);
      await assert.rejects(denied.signer.handle('eth_sendTransaction', [transaction]), RpcError);
      assert.equal(broadcasts(denied.calls).length, 0);
    }
  }
});

test('Mainnet health advertises only its explicitly configured chain', async t => {
  const { signer } = fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas: 30n * GWEI });
  const server = createHttpServer(signer).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health`).then(r => r.json());
  assert.equal(response.chain_id, 1);
  assert.equal(response.fee_cap_source, 'explicit');
  assert.equal(response.max_fee_per_gas, wei(30n * GWEI));
});

test('server process refuses unsafe fee configuration and prints only the safe reason', () => {
  const base = { PATH: process.env.PATH, ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault, ZKAPI_CHALLENGE_RPC_URL: 'http://127.0.0.1:1/private-api-key' };
  for (const [env, reason] of [
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '1' }, 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '1', ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: 'REPLACE_WITH_FEE_CAP_WEI' }, 'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI must be a positive decimal integer'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI: '50000000000' }, 'ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '0' }, 'ZKAPI_CHALLENGE_TX_FEE_CAP_WEI must be a positive decimal integer'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '11155111' }, 'Upstream RPC request failed (upstream_unavailable)'],
  ]) {
    const result = spawnSync(process.execPath, ['server.mjs'], { cwd: here, encoding: 'utf8', timeout: 30_000, env: { ...base, ...env } });
    assert.equal(result.status, 1, reason);
    assert.ok(result.stderr.startsWith(`Challenge signer startup failed: ${reason}`), result.stderr);
    for (const secret of [key.slice(2), 'private-api-key']) assert.ok(!result.stderr.includes(secret) && !result.stdout.includes(secret));
  }
});

test('server process starts from strict configuration and prints its fee policy without key material', async t => {
  const upstream = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const { id, method } = JSON.parse(body);
    const results = { eth_chainId: '0xaa36a7', eth_getBlockByNumber: { number: '0x10', baseFeePerGas: wei(9n * GWEI) }, eth_getBalance: '0x1' };
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(Object.hasOwn(results, method) ? { jsonrpc: '2.0', id, result: results[method] } : { jsonrpc: '2.0', id, error: { code: -32601, message: 'not found' } }));
  }).listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => upstream.close());
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: here, stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH, ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault,
      ZKAPI_CHALLENGE_RPC_URL: `http://127.0.0.1:${upstream.address().port}/private-api-key`, ZKAPI_CHALLENGE_PORT: String(port),
      ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '10000000000', ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '',
      ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: '100000000000000000',
    },
  });
  t.after(() => child.kill());
  let stdout = '';
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const line = await new Promise((resolve, reject) => {
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.includes('\n')) resolve(JSON.parse(stdout.split('\n')[0])); });
    child.on('exit', code => reject(new Error(`signer exited with ${code}: ${stderr}`)));
  });
  assert.deepEqual(line, {
    status: 'listening', chain_id: 11155111, sender: sender.toLowerCase(), vault, fee_model: 'eip1559', fee_cap_source: 'explicit',
    max_fee_per_gas_wei: '10000000000', priority_fee_per_gas_wei: '1000000000', max_priority_fee_per_gas_wei: '10000000000',
    // 0.1 ETH over 12M gas leaves 8.33 gwei per gas, below the 10 gwei fee cap.
    fee_ceiling_wei: '10000000000000', tx_fee_cap_wei: '100000000000000000', max_fee_per_gas_allowed_at_max_gas_wei: '8333333333',
    max_gas: '12000000', required_balance_wei: '120000000000000000', balance_wei: '1', max_retirements_per_day: 2,
    retire_on_miss: true, retirement_lookback_blocks: 50400,
    base_fee_per_gas_wei: '9000000000', warnings: ['base_fee_near_cap', 'balance_below_required', 'tx_fee_cap_below_fee_cap'],
  });
  const health = await fetch(`http://127.0.0.1:${port}/health`).then(r => r.json());
  assert.equal(health.status, 'ok');
  assert.equal(health.max_fee_per_gas, wei(10n * GWEI));
  assert.equal(health.tx_fee_cap_wei, wei(10n ** 17n));
  for (const secret of [key.slice(2), 'private-api-key']) assert.ok(!stdout.includes(secret) && !stderr.includes(secret));
});

test('refusals and signatures are logged once per transition without provider details', async () => {
  let baseFee = '0x2540be401';
  const { signer, logs } = fixture({ eth_getBlockByNumber: () => ({ number: '0x10', baseFeePerGas: baseFee }) });
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  assert.deepEqual(logs, [{ event: 'challenge_refused', nonce: 4, code: -32003, reason: 'base_fee_above_max_fee', message: 'Base fee exceeds the transaction max fee per gas', base_fee_per_gas_wei: '10000000001', max_fee_per_gas_wei: '10000000000' }]);
  await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(GWEI, 2n * GWEI) }]));
  await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, to: sender }]));
  assert.deepEqual(logs.slice(1), [
    { event: 'challenge_refused', nonce: 4, code: -32602, reason: 'fee_out_of_bounds', message: 'Requested fees are outside the configured bounds', max_fee_per_gas_wei: '10000000000', max_priority_fee_per_gas_wei: '10000000000' },
    { event: 'challenge_refused', nonce: 4, code: -32602, reason: 'invalid_request', message: 'Destination is not authorized' },
  ]);
  baseFee = '0x3b9aca00';
  const hash = await signer.handle('eth_sendTransaction', [validTx]);
  await signer.handle('eth_sendTransaction', [validTx]);
  assert.equal(logs.length, 4);
  assert.deepEqual(logs[3], { event: 'challenge_signed', nonce: 4, transaction_hash: hash, max_fee_per_gas_wei: '10000000000', max_priority_fee_per_gas_wei: '1000000000' });
  baseFee = '0x2540be401';
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  assert.equal(logs.length, 5, 'a refusal after a signature is a new transition');
  const lost = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'https://provider.invalid/private-api-key', 'upstream_unavailable') });
  await assert.rejects(lost.signer.handle('eth_sendTransaction', [validTx]));
  assert.deepEqual(lost.logs, [{ event: 'challenge_refused', nonce: 4, code: -32000, reason: 'broadcast_ambiguous', message: 'Transaction broadcast outcome is unknown', transaction_hash: keccak256(broadcasts(lost.calls)[0].params[0]) }]);
  const text = JSON.stringify([...logs, ...lost.logs]);
  for (const secret of [key.slice(2), 'private-api-key', broadcasts(lost.calls)[0].params[0].slice(2, 66), data.slice(2, 10)]) assert.ok(!text.includes(secret));
});
