// Real-node checks of the type-2 signer against a disposable anvil. Skipped when
// anvil is not installed unless ZKAPI_REQUIRE_ANVIL=1, which makes that a failure.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';
import { Transaction, Wallet } from 'ethers';
import { ESCAPE_FINALIZED_TOPIC, GWEI, createSigner, createUpstream, vaultInterface } from './signer.mjs';

const CHAIN_ID = 11155111n;
const haveAnvil = spawnSync('anvil', ['--version'], { stdio: 'ignore' }).status === 0;
const skip = !haveAnvil && process.env.ZKAPI_REQUIRE_ANVIL !== '1' && 'anvil is not installed (ZKAPI_REQUIRE_ANVIL=1 makes this a failure)';
// Anvil's first default account: a public test key, only ever funded on a disposable anvil.
const key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const sender = new Wallet(key).address;
const vault = '0x0000000000000000000000000000000000001234';
const data = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, CHAIN_ID, vault, 0, 1, 2, 0, 1, 0, 0, 0, 0], `0x${'00'.repeat(256)}`]);
const GAS = 200_000n;
const wei = value => `0x${value.toString(16)}`;
const fees = (maxFee, tip) => ({ maxFeePerGas: wei(maxFee), maxPriorityFeePerGas: wei(tip) });
const tx = (nonce, extra = {}) => ({ from: sender, to: vault, data, gas: wei(GAS), nonce: wei(BigInt(nonce)), ...extra });

// Port 0 lets the OS choose a free port, which anvil reports on stdout, so
// parallel runs cannot collide; startup is still retried. Automine is off and
// every test mines explicitly, so no receipt is read before its block exists.
async function launchAnvil(t) {
  assert.ok(haveAnvil, 'ZKAPI_REQUIRE_ANVIL=1 but anvil is not on PATH');
  for (let attempt = 1; attempt <= 3; attempt++) {
    const child = spawn('anvil', ['--port', '0', '--chain-id', String(CHAIN_ID), '--no-mining'], { stdio: ['ignore', 'pipe', 'ignore'] });
    t.after(() => child.kill());
    const port = await new Promise(resolve => {
      let output = '';
      const timer = setTimeout(() => resolve(null), 20_000);
      const onData = chunk => {
        output += chunk;
        const match = output.match(/Listening on \S+:(\d+)/);
        if (!match) return;
        clearTimeout(timer);
        child.stdout.off('data', onData);
        child.stdout.resume(); // Keep draining anvil's request log.
        resolve(Number(match[1]));
      };
      child.stdout.on('data', onData);
      child.on('exit', () => { clearTimeout(timer); resolve(null); });
    });
    if (port) {
      const url = `http://127.0.0.1:${port}`;
      // A STOP contract: every challenge call simulates successfully.
      await createUpstream(url)('anvil_setCode', [vault, '0x00']);
      return url;
    }
    child.kill();
  }
  assert.fail('anvil did not start');
}
const startAnvil = async t => createUpstream(await launchAnvil(t));
// Anvil does not enforce a node's RPC fee cap. This proxy answers
// eth_sendRawTransaction above geth's default --rpc.txfeecap (1 ether of gas
// limit x maxFeePerGas) with geth's exact error and forwards all else to anvil.
const NODE_TX_FEE_CAP = 10n ** 18n;
async function feeCapProxy(t, anvilUrl) {
  const refused = [];
  const proxy = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    response.setHeader('content-type', 'application/json');
    try {
      const { id, method, params } = JSON.parse(body);
      if (method === 'eth_sendRawTransaction') {
        const { hash, gasLimit, maxFeePerGas } = Transaction.from(params[0]);
        const fee = gasLimit * maxFeePerGas;
        if (fee > NODE_TX_FEE_CAP) {
          refused.push(hash);
          const message = `tx fee (${(Number(fee) / 1e18).toFixed(2)} ether) exceeds the configured cap (1.00 ether)`;
          response.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message } }));
          return;
        }
      }
      const forwarded = await fetch(anvilUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
      response.end(await forwarded.text());
    } catch {
      response.statusCode = 502;
      response.end();
    }
  }).listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  t.after(() => { proxy.closeAllConnections(); proxy.close(); });
  return { url: `http://127.0.0.1:${proxy.address().port}`, refused };
}
const signerFor = (rpc, options) => createSigner({ privateKey: key, vault, rpc, chainId: CHAIN_ID, log: () => {}, ...options });
const nonceOf = async (rpc, tag) => Number(BigInt(await rpc('eth_getTransactionCount', [sender, tag])));
const poolSize = async rpc => Number(BigInt((await rpc('txpool_status', [])).pending));
async function receipt(rpc, hash) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const value = await rpc('eth_getTransactionReceipt', [hash]);
    if (value) return value;
    await sleep(50);
  }
  return assert.fail(`no receipt for ${hash}`);
}
async function mine(rpc, nextBaseFee) {
  if (nextBaseFee !== undefined) await rpc('anvil_setNextBlockBaseFeePerGas', [wei(nextBaseFee)]);
  await rpc('evm_mine', []);
}
const balanceOf = async (rpc, block = 'latest') => BigInt(await rpc('eth_getBalance', [sender, block]));
// Wei per gas actually charged for a mined zero-value transaction. Anvil 1.5.1
// reports receipt.effectiveGasPrice as baseFee + tip even when maxFeePerGas
// binds, so the sender's balance change is the reliable measure.
async function chargedPerGas(rpc, hash, balanceBefore) {
  const mined = await receipt(rpc, hash);
  assert.deepEqual([mined.type, mined.status], ['0x2', '0x1']);
  const charged = balanceBefore - await balanceOf(rpc, mined.blockNumber);
  assert.equal(charged % BigInt(mined.gasUsed), 0n);
  return { perGas: charged / BigInt(mined.gasUsed), block: await rpc('eth_getBlockByNumber', [mined.blockNumber, false]) };
}

test('type-2 challenges are charged min(maxFee, baseFee + tip) per gas, never above the bid', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 10n * GWEI });
  // No fee fields (a daemon that predates fee proposals): bid the cap with the default tip.
  let before = await balanceOf(rpc);
  const defaultBid = await signer.handle('eth_sendTransaction', [tx(0)]);
  await mine(rpc, 2n * GWEI);
  const first = await chargedPerGas(rpc, defaultBid, before);
  assert.deepEqual([BigInt(first.block.baseFeePerGas), first.perGas], [2n * GWEI, 3n * GWEI]);
  // A proposed bid whose max fee binds pays exactly the max fee, not baseFee + tip.
  before = await balanceOf(rpc);
  const proposed = await signer.handle('eth_sendTransaction', [tx(1, fees(4n * GWEI, 2n * GWEI))]);
  await mine(rpc, 3n * GWEI);
  const second = await chargedPerGas(rpc, proposed, before);
  assert.deepEqual([BigInt(second.block.baseFeePerGas), second.perGas], [3n * GWEI, 4n * GWEI]);
  const mined = await rpc('eth_getTransactionByHash', [proposed]);
  assert.deepEqual([BigInt(mined.maxFeePerGas), BigInt(mined.maxPriorityFeePerGas)], [4n * GWEI, 2n * GWEI]);
  assert.equal(await nonceOf(rpc, 'latest'), 2);
});

test('a base fee above the transaction max fee refuses with exact data and broadcasts nothing', { skip }, async t => {
  const rpc = await startAnvil(t);
  await mine(rpc, 12n * GWEI);
  const capped = signerFor(rpc, { maxFeePerGas: 10n * GWEI });
  const raised = signerFor(rpc, { maxFeePerGas: 30n * GWEI });
  const refusal = maxFee => ({
    code: -32003, message: 'Base fee exceeds the transaction max fee per gas',
    data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: wei(12n * GWEI), max_fee_per_gas: wei(maxFee) },
  });
  await assert.rejects(capped.handle('eth_sendTransaction', [tx(0)]), refusal(10n * GWEI));
  await assert.rejects(raised.handle('eth_sendTransaction', [tx(0, fees(11n * GWEI, GWEI))]), refusal(11n * GWEI));
  assert.equal(await nonceOf(rpc, 'pending'), 0);
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  assert.deepEqual((await capped.handle('zkapi_signerStatus', [])).warnings, ['base_fee_above_cap', 'base_fee_near_cap']);
  // A bid above the base fee lands, paying baseFee + tip and never more than its max fee.
  const before = await balanceOf(rpc);
  const landed = await raised.handle('eth_sendTransaction', [tx(0, fees(15n * GWEI, GWEI))]);
  await mine(rpc);
  const { perGas, block } = await chargedPerGas(rpc, landed, before);
  assert.equal(perGas, BigInt(block.baseFeePerGas) + GWEI);
  assert.ok(perGas > 10n * GWEI && perGas <= 15n * GWEI, 'paid more than the old cap, never more than the bid');
});

test('identical rebroadcast is idempotent; a tip-only bump is rejected; raising both fees replaces on the same nonce', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 20n * GWEI, maxPriorityFeePerGas: 5n * GWEI });
  const original = await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, GWEI))]);
  assert.equal(await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, GWEI))]), original, 'an identical rebroadcast returns the same hash');
  assert.equal(await poolSize(rpc), 1);
  const tipOnly = await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, 9n * GWEI / 8n))]).catch(error => error);
  assert.equal(tipOnly.code, -32000);
  assert.equal(tipOnly.data.reason, 'broadcast_ambiguous');
  assert.match(tipOnly.data.transaction_hash, /^0x[0-9a-f]{64}$/);
  assert.notEqual(tipOnly.data.transaction_hash, original);
  assert.equal(await rpc('eth_getTransactionByHash', [tipOnly.data.transaction_hash]), null, 'the pool rejected the tip-only replacement');
  assert.ok(await rpc('eth_getTransactionByHash', [original]), 'the original is still pending');
  // Both fees +12.5%: above geth/reth's 10% bump on each field (anvil only requires a higher max fee).
  const replacement = await signer.handle('eth_sendTransaction', [tx(0, fees(9n * GWEI / 2n, 9n * GWEI / 8n))]);
  assert.equal(await poolSize(rpc), 1);
  assert.equal(await rpc('eth_getTransactionByHash', [original]), null, 'the replacement evicted the original');
  await mine(rpc);
  assert.equal((await receipt(rpc, replacement)).status, '0x1');
  assert.equal(await rpc('eth_getTransactionReceipt', [original]), null, 'the original never mines');
  const mined = Transaction.from(await rpc('eth_getRawTransactionByHash', [replacement]));
  assert.deepEqual([mined.to.toLowerCase(), mined.data, mined.value, mined.nonce], [vault, data, 0n, 0]);
  assert.deepEqual([mined.maxFeePerGas, mined.maxPriorityFeePerGas], [9n * GWEI / 2n, 9n * GWEI / 8n]);
  assert.equal(await nonceOf(rpc, 'latest'), 1);
});

test('a balance below gas limit x max fee refuses before broadcast; the check uses the bid, not the cap', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 50n * GWEI });
  const balance = GAS * 10n * GWEI - 1n;
  await rpc('anvil_setBalance', [sender, wei(balance)]);
  const refusal = maxFee => ({
    code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas',
    data: { reason: 'insufficient_balance', balance: wei(balance), required_balance: wei(GAS * maxFee) },
  });
  await assert.rejects(signer.handle('eth_sendTransaction', [tx(0, fees(10n * GWEI, GWEI))]), refusal(10n * GWEI));
  await assert.rejects(signer.handle('eth_sendTransaction', [tx(0)]), refusal(50n * GWEI));
  assert.equal(await nonceOf(rpc, 'pending'), 0);
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  assert.ok((await signer.handle('zkapi_signerStatus', [])).warnings.includes('balance_below_required'));
  // A lower bid that the balance covers is signed and mines.
  const fits = await signer.handle('eth_sendTransaction', [tx(0, fees(9n * GWEI, GWEI))]);
  await mine(rpc);
  assert.equal((await receipt(rpc, fits)).status, '0x1');
});

test('bids above a node\'s 1 ETH fee cap are refused as never broadcast; a bid within it then mines on the same nonce', { skip }, async t => {
  const node = await feeCapProxy(t, await launchAnvil(t));
  const rpc = createUpstream(node.url);
  // The measured challenge gas limit: at 1 ETH, about 132.7 gwei per gas.
  const gas = 7_534_341n;
  const challenge = extra => tx(0, { gas: wei(gas), ...extra });
  // At the default transaction fee cap, which matches the node's, the signer
  // refuses the reviewed 142 gwei bid and the default (fee cap) bid itself.
  const matched = signerFor(rpc, { maxFeePerGas: 300n * GWEI });
  const allowed = NODE_TX_FEE_CAP / gas;
  for (const [request, maxFee] of [[challenge(fees(142n * GWEI, 2n * GWEI)), 142n * GWEI], [challenge(), 300n * GWEI]]) {
    await assert.rejects(matched.handle('eth_sendTransaction', [request]), {
      code: -32003, message: 'Gas limit times max fee per gas exceeds the transaction fee cap',
      data: { reason: 'tx_fee_above_cap', gas_limit: wei(gas), max_fee_per_gas: wei(maxFee), tx_fee_cap_wei: wei(NODE_TX_FEE_CAP), max_fee_per_gas_allowed: wei(allowed) },
    });
  }
  assert.deepEqual(node.refused, [], 'nothing reached the node');
  // A signer configured above the node's cap passes the bid on; the node
  // refuses it before its pool, which is a definite refusal, not ambiguous.
  const unmatched = signerFor(rpc, { maxFeePerGas: 300n * GWEI, txFeeCap: 3n * NODE_TX_FEE_CAP });
  await assert.rejects(unmatched.handle('eth_sendTransaction', [challenge(fees(142n * GWEI, 2n * GWEI))]), {
    code: -32003, message: 'Upstream RPC refused the transaction fee',
    data: { reason: 'upstream_tx_fee_cap', gas_limit: wei(gas), max_fee_per_gas: wei(142n * GWEI) },
  });
  assert.equal(node.refused.length, 1);
  assert.equal(await rpc('eth_getTransactionByHash', [node.refused[0]]), null);
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  assert.equal(await nonceOf(rpc, 'pending'), 0);
  // The same nonce at the reported ceiling (0.99 ETH) is accepted and mines.
  const landed = await matched.handle('eth_sendTransaction', [challenge(fees(allowed, 2n * GWEI))]);
  await mine(rpc);
  const mined = await receipt(rpc, landed);
  assert.deepEqual([mined.type, mined.status], ['0x2', '0x1']);
  const signed = Transaction.from(await rpc('eth_getRawTransactionByHash', [landed]));
  assert.deepEqual([signed.nonce, signed.gasLimit, signed.maxFeePerGas], [0, gas, allowed]);
  assert.equal(await nonceOf(rpc, 'latest'), 1);
  assert.equal(node.refused.length, 1);
});

test('a leaf retirement is signed only for a note whose EscapeWithdrawalFinalized log the node returns', { skip }, async t => {
  const rpc = await startAnvil(t);
  // A vault stand-in that emits EscapeWithdrawalFinalized(9) (LOG2: topic0,
  // then note 9) on every call, so the retirement of note 9 also simulates.
  const topic = ESCAPE_FINALIZED_TOPIC.slice(2);
  const note9 = (9).toString(16).padStart(64, '0');
  await rpc('anvil_setCode', [vault, `0x7f${note9}7f${topic}60006000a200`]);
  // Another funded account emits it: the signer's sender keeps nonce 0.
  const [, funded] = await rpc('eth_accounts', []);
  await rpc('eth_sendTransaction', [{ from: funded, to: vault, gas: '0x30000' }]);
  await mine(rpc);
  const logs = await rpc('eth_getLogs', [{ address: vault, fromBlock: '0x0', toBlock: 'latest', topics: [ESCAPE_FINALIZED_TOPIC] }]);
  assert.equal(logs.length, 1);
  const signer = signerFor(rpc, { maxFeePerGas: 10n * GWEI });
  const retire = (note, nonce) => ({ from: sender, to: vault, gas: wei(GAS), nonce: wei(BigInt(nonce)),
    data: vaultInterface.encodeFunctionData('retireClosedLeaf', [note, Array(32).fill(0)]) });
  await assert.rejects(signer.handle('eth_sendTransaction', [retire(10, 0)]),
    { code: -32003, data: { reason: 'retirement_not_after_escape', note_id: '0xa', lookback_blocks: wei(50_400n) } });
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  const hash = await signer.handle('eth_sendTransaction', [retire(9, 0)]);
  await mine(rpc);
  assert.equal((await receipt(rpc, hash)).status, '0x1');
  assert.equal((await signer.handle('zkapi_signerStatus', [])).retirements_last_24h, 1);
});
