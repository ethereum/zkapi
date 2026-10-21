#!/usr/bin/env node
// The shared withdrawal golden vector (design §11 WP-F) on a real chain.
//
// protocol/contracts/test/fixtures/withdrawal-golden.json holds a real kind-0
// escape and kind-1 close proof (vault-challenge.json's escape_a2_concede and
// close_b0), their exact calldata, and the deployment and deposits they land
// on. Forge's WithdrawalGoldenTest pins it to abi.encodeCall against the real
// vault. This script runs every encoder on it and submits each one's output
// to a vault deployed on a fresh Anvil:
//
//   rust-serverd    zkapi-serverd watcher::withdrawal_calldata (Rust challenger/server)
//   rust-companion  zkapi-companion chain::withdrawal_calldata (Rust wallet companion)
//   js-sdk          sdk/wallet.js encodeWithdrawal (in this process)
//   go-clientd      zkapi-clientd escapeCalldata and withdrawalCalldata
//
// The Rust and Go golden tests assert byte equality themselves and, with
// ZKAPI_WITHDRAWAL_GOLDEN_OUT set, write what their encoder produced; this
// script reads those files, so each submission is that encoder's own output.
// Every escape and close must succeed (receipt status 1, note PendingWithdrawal
// and Closed); the chain is reverted between encoders.
//
//   node scripts/check-withdrawal-golden.mjs [--encoders rust-serverd,rust-companion,js-sdk,go-clientd]
//   node scripts/check-withdrawal-golden.mjs --update   # rewrite the JSON (Forge prints it)
//
// Needs node 24, forge and anvil, and cargo and go for their encoders.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACTS = path.join(ROOT, 'protocol/contracts');
const GOLDEN = path.join(CONTRACTS, 'test/fixtures/withdrawal-golden.json');
const FIXTURES = path.join(CONTRACTS, 'test/fixtures/vault-challenge.json');
const ENCODERS = ['rust-serverd', 'rust-companion', 'js-sdk', 'go-clientd'];
// WithdrawalGoldenTest's deployment (keep them equal).
const DEPLOYMENT = Object.freeze({
  deployer: '0x000000000000000000000000000000000000f00d', deployer_nonce: 0,
  treasury: '0x000000000000000000000000000000000000beef', owner: '0x0000000000000000000000000000000000000d0d',
  note_ttl: 30 * 86_400, challenge_period: 86_400, request_charge_cap: 100_000, max_pause_duration: 7 * 86_400,
});
const DEPOSITOR = '0x1111111111111111111111111111111111111111';
const DEPOSIT_WEI = 1_000_000n * 1_000_000_000n;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 << 20, ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.status}):\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const addressWord = value => String(value).toLowerCase().replace(/^0x/, '').padStart(64, '0');

function update() {
  const fixtures = JSON.parse(fs.readFileSync(FIXTURES, 'utf8'));
  const log = run('forge', ['test', '--match-contract', 'WithdrawalGoldenTest', '-vv'], {
    cwd: CONTRACTS, env: { ...process.env, ZKAPI_PRINT_WITHDRAWAL_GOLDEN: 'true' },
  });
  const printed = Object.fromEntries(log.split('\n').map(line => /^\s*([a-z_]+)=(0x[0-9a-f]+)\s*$/.exec(line))
    .filter(Boolean).map(([, key, value]) => [key, value]));
  for (const key of ['deposit_a', 'deposit_b', 'escape', 'close', 'active_root']) assert.ok(printed[key], `forge printed no ${key}`);
  const statement = name => ({
    public_inputs: fixtures[name].public_inputs,
    proof: Buffer.from(fixtures[name].proof_hex.slice(2), 'hex').toString('base64'),
    proof_hex: fixtures[name].proof_hex,
    inputs_abi: fixtures[name].inputs_abi,
  });
  const golden = {
    description: 'Shared withdrawal golden vector (design §11 WP-F): a real kind-0 escape (conceding 100,000) and a real kind-1 close of circuit zkapi-v2-concession-v1, setup dev, with their calldata as Solidity abi.encodeCall encodes them against the real vault (WithdrawalGoldenTest), and the deployment and deposits they land on. The Rust (zkapi-serverd, zkapi-companion), JS (sdk/wallet.js) and Go (zkapi-clientd) encoders must produce exactly `calldata`; scripts/check-withdrawal-golden.mjs submits each encoder\'s output to this deployment on Anvil. Regenerate: node scripts/check-withdrawal-golden.mjs --update.',
    source: { fixture: 'protocol/contracts/test/fixtures/vault-challenge.json', escape: 'escape_a2_concede', close: 'close_b0' },
    circuit_id: fixtures.circuit_id,
    setup_id: fixtures.setup_id,
    chain_id: fixtures.chain_id,
    timestamp: fixtures.timestamp,
    deployment: {
      vault: fixtures.vault, ...DEPLOYMENT,
      state_signing_key: fixtures.state_signing_key, clearance_signing_key: fixtures.clearance_signing_key,
    },
    depositor: DEPOSITOR,
    deposits: [
      { note_id: 0, value_wei: DEPOSIT_WEI.toString(), calldata: printed.deposit_a },
      { note_id: 1, value_wei: DEPOSIT_WEI.toString(), calldata: printed.deposit_b },
    ],
    active_root: printed.active_root,
    escape: { ...statement('escape_a2_concede'), state_balance: '790000', calldata: printed.escape },
    close: { ...statement('close_b0'), calldata: printed.close },
  };
  fs.writeFileSync(GOLDEN, `${JSON.stringify(golden, null, 2)}\n`);
  console.log(`updated ${path.relative(ROOT, GOLDEN)}`);
}

// ---- encoders ----

async function jsEncoder(golden) {
  const { default: wallet } = await import(pathToFileURL(path.join(ROOT, 'sdk/wallet.js')).href);
  const destination = statement => `0x${Buffer.from(statement.public_inputs.destination).toString('hex')}`;
  const encode = (mode, statement) => wallet.encodeWithdrawal(
    { mode, public_inputs: statement.public_inputs, proof: { backend: 'groth16_bn254', proof: statement.proof } },
    mode, destination(statement), golden.deployment.vault, { conceded: statement.public_inputs.conceded });
  return { escape: encode('escape', golden.escape), close: encode('mutual', golden.close) };
}

function testedEncoder(name, outDir) {
  const env = { ...process.env, ZKAPI_WITHDRAWAL_GOLDEN_OUT: outDir };
  if (name === 'rust-serverd') {
    run('cargo', ['test', '--release', '--locked', '-p', 'zkapi-serverd', '--lib',
      'watcher::tests::real_proofs_encode_to_the_shared_withdrawal_golden_vector', '--', '--exact'], { env });
  } else if (name === 'rust-companion') {
    run('cargo', ['test', '--release', '--locked', '-p', 'zkapi-companion', '--lib',
      'chain::tests::real_proofs_encode_to_the_shared_withdrawal_golden_vector', '--', '--exact'], { env });
  } else if (name === 'go-clientd') {
    run('go', ['test', '-count=1', '-run', '^TestRealProofsEncodeToTheSharedWithdrawalGoldenVector$', './internal/zkapi'],
      { env, cwd: path.join(ROOT, 'zkapi-clientd') });
  } else {
    throw new Error(`unknown encoder ${name}`);
  }
  const file = path.join(outDir, `${name}.json`);
  assert.ok(fs.existsSync(file), `${name} wrote no output (${file})`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// ---- Anvil ----

async function startAnvil(chainId) {
  const child = spawn('anvil', ['--port', '0', '--chain-id', String(chainId)], { stdio: ['ignore', 'pipe', 'pipe'] });
  const port = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('anvil did not start')); }, 30_000);
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/Listening on \S+:(\d+)/);
      if (match) { clearTimeout(timer); resolve(Number(match[1])); }
    });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`anvil exited (${code})`)); });
  });
  child.stdout.resume();
  child.stderr.resume();
  let id = 0;
  const rpc = async (method, params = []) => {
    const response = await fetch(`http://127.0.0.1:${port}`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
  };
  return { child, rpc };
}

function linked(artifact, libraries) {
  let bytecode = artifact.bytecode.object;
  for (const [source, names] of Object.entries(artifact.bytecode.linkReferences ?? {})) {
    for (const [name, references] of Object.entries(names)) {
      const address = libraries[`${source}:${name}`];
      assert.match(address ?? '', /^0x[0-9a-fA-F]{40}$/, `no address for library ${name}`);
      for (const { start, length } of references) {
        assert.equal(length, 20);
        const offset = 2 + start * 2;
        bytecode = bytecode.slice(0, offset) + address.slice(2).toLowerCase() + bytecode.slice(offset + 40);
      }
    }
  }
  assert.match(bytecode, /^0x[0-9a-fA-F]+$/, 'unlinked library');
  return bytecode;
}

async function mined(rpc, hash) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (receipt) return receipt;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`no receipt for ${hash}`);
}

async function send(rpc, transaction) {
  return mined(rpc, await rpc('eth_sendTransaction', [{ gas: hex(15_000_000), ...transaction }]));
}

async function deploy(rpc, golden) {
  const artifact = name => JSON.parse(fs.readFileSync(path.join(CONTRACTS, `out/${name}.sol/${name}.json`), 'utf8'));
  const [funder] = await rpc('eth_accounts');
  const poseidon = await send(rpc, { from: funder, data: linked(artifact('Bn254Poseidon'), {}) });
  const adapter = await send(rpc, { from: funder, data: linked(artifact('Groth16ProofAdapter'), {}) });
  assert.equal(poseidon.status, '0x1');
  assert.equal(adapter.status, '0x1');
  const d = golden.deployment;
  // The proofs bind the vault address: CREATE by the deployer at its nonce.
  await rpc('anvil_impersonateAccount', [d.deployer]);
  await rpc('anvil_setBalance', [d.deployer, hex(10n ** 20n)]);
  assert.equal(BigInt(await rpc('eth_getTransactionCount', [d.deployer, 'latest'])), BigInt(d.deployer_nonce));
  const args = [addressWord(d.treasury), word(d.note_ttl), word(d.challenge_period), word(d.request_charge_cap),
    addressWord(adapter.contractAddress), word(d.state_signing_key.x), word(d.state_signing_key.y),
    word(d.clearance_signing_key.x), word(d.clearance_signing_key.y), addressWord(d.owner), word(d.max_pause_duration)];
  const vault = await send(rpc, { from: d.deployer,
    data: linked(artifact('ZkApiVault'), { 'src/libraries/Bn254Poseidon.sol:Bn254Poseidon': poseidon.contractAddress }) + args.join('') });
  assert.equal(vault.status, '0x1');
  assert.equal(vault.contractAddress.toLowerCase(), d.vault.toLowerCase(), 'the vault is at the address the proofs bind');
  // The deposits, at the fixture's time (the leaves hold the bucketed expiry).
  await rpc('anvil_impersonateAccount', [golden.depositor]);
  await rpc('anvil_setBalance', [golden.depositor, hex(10n ** 20n)]);
  await rpc('evm_setNextBlockTimestamp', [hex(golden.timestamp)]);
  for (const deposit of golden.deposits) {
    const receipt = await send(rpc, { from: golden.depositor, to: d.vault, value: hex(deposit.value_wei), data: deposit.calldata });
    assert.equal(receipt.status, '0x1', `deposit of note ${deposit.note_id}`);
  }
  const root = await rpc('eth_call', [{ to: d.vault, data: '0xfdab463d' }, 'latest']);
  assert.equal(BigInt(root), BigInt(golden.active_root), 'the deposits rebuild the proofs\' root');
}

async function noteStatus(rpc, vault, noteId) {
  const words = await rpc('eth_call', [{ to: vault, data: `0x9f18e4ed${word(noteId)}` }, 'latest']);
  return Number(BigInt(`0x${words.slice(2 + 3 * 64, 2 + 4 * 64)}`));
}

async function submit(rpc, golden, name, output) {
  const vault = golden.deployment.vault;
  for (const call of ['escape', 'close']) {
    assert.equal(output[call], golden[call].calldata, `${name}: ${call} calldata differs from the golden vector`);
  }
  const escape = await send(rpc, { from: golden.depositor, to: vault, data: output.escape });
  assert.equal(escape.status, '0x1', `${name}: the escape reverted`);
  assert.equal(await noteStatus(rpc, vault, golden.escape.public_inputs.note_id), 2, `${name}: the note is not PendingWithdrawal`);
  const concession = await rpc('eth_call', [{ to: vault, data: `0xf8ffe6e0${word(golden.escape.public_inputs.note_id)}` }, 'latest']);
  assert.equal(BigInt(`0x${concession.slice(2 + 2 * 64)}`), BigInt(golden.escape.public_inputs.conceded), `${name}: concession`);
  const close = await send(rpc, { from: golden.depositor, to: vault, data: output.close });
  assert.equal(close.status, '0x1', `${name}: the close reverted`);
  assert.equal(await noteStatus(rpc, vault, golden.close.public_inputs.note_id), 3, `${name}: the note is not Closed`);
  return { escapeGas: Number(BigInt(escape.gasUsed)), closeGas: Number(BigInt(close.gasUsed)) };
}

async function check(encoders) {
  const golden = JSON.parse(fs.readFileSync(GOLDEN, 'utf8'));
  run('forge', ['build'], { cwd: CONTRACTS });
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkapi-withdrawal-golden-'));
  const outputs = {};
  try {
    for (const name of encoders) {
      outputs[name] = name === 'js-sdk' ? await jsEncoder(golden) : testedEncoder(name, outDir);
      console.log(`${name}: encoded the golden escape and close`);
    }
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
  const { child, rpc } = await startAnvil(golden.chain_id);
  try {
    await deploy(rpc, golden);
    // Control: the vault verifies the proof, so one changed proof byte reverts.
    const tampered = `${golden.escape.calldata.slice(0, -2)}${golden.escape.calldata.endsWith('00') ? '01' : '00'}`;
    const control = await send(rpc, { from: golden.depositor, to: golden.deployment.vault, data: tampered });
    assert.equal(control.status, '0x0', 'a tampered escape proof must revert');
    for (const name of encoders) {
      const snapshot = await rpc('evm_snapshot');
      const gas = await submit(rpc, golden, name, outputs[name]);
      assert.equal(await rpc('evm_revert', [snapshot]), true);
      console.log(`${name}: escape (gas ${gas.escapeGas}) and close (gas ${gas.closeGas}) landed on the Anvil vault`);
    }
  } finally {
    child.kill();
  }
  console.log(`withdrawal golden vector: ${encoders.length} encoders produced the golden calldata and every call landed`);
}

const args = process.argv.slice(2);
if (args.includes('--update')) {
  update();
} else {
  const index = args.indexOf('--encoders');
  const encoders = index >= 0 ? args[index + 1].split(',') : ENCODERS;
  for (const name of encoders) assert.ok(ENCODERS.includes(name), `unknown encoder ${name}`);
  await check(encoders);
}
