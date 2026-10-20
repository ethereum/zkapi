import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  identity, gitIdentity, git, initLedger, commitFiles, advance, head, tree,
  bytesJson, validateConfig, openForContributions, assertExtension,
  validateSubmissionTree, stageOutput, contributionRecords,
} from '../lib.mjs';

async function temporary(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-ceremony-unit-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

test('identity fields are individually optional and never use Git environment defaults', () => {
  assert.deepEqual(identity('', '  '), { name: null, email: null });
  assert.deepEqual(identity('Alice', ''), { name: 'Alice', email: null });
  assert.deepEqual(identity('', 'a@example.org'), { name: null, email: 'a@example.org' });
  assert.deepEqual(gitIdentity(identity()), { name: 'Anonymous', email: 'anonymous@participants.invalid' });
  assert.throws(() => identity('Alice\nBob', ''), /Invalid name/);
  assert.throws(() => identity('<Alice>', ''), /Invalid name/);
  assert.throws(() => identity(12, ''), /Invalid name/);
  assert.throws(() => identity('', 'not an email'), /Invalid email/);
  assert.throws(() => identity('😀'.repeat(17), ''), /Invalid name/);
});

test('anonymous commit overrides inherited author/committer, signing and dates', async t => {
  const dir = await temporary(t);
  const repo = path.join(dir, 'ledger.git');
  initLedger(repo);
  git(repo, ['config', 'user.name', 'Leaked Global Name']);
  git(repo, ['config', 'user.email', 'private@real.example']);
  git(repo, ['config', 'commit.gpgSign', 'true']);
  const env = ['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_AUTHOR_DATE'];
  const old = Object.fromEntries(env.map(key => [key, process.env[key]]));
  for (const key of env) process.env[key] = 'DO NOT LEAK';
  try {
    const commit = commitFiles(repo, null, { 'receipt.json': bytesJson(identity()) }, identity(), 'Anonymous contribution');
    advance(repo, commit);
    const raw = git(repo, ['cat-file', 'commit', commit]);
    assert.match(raw, /author Anonymous <anonymous@participants.invalid> 946684800 \+0000/);
    assert.match(raw, /committer Anonymous <anonymous@participants.invalid> 946684800 \+0000/);
    assert.doesNotMatch(raw, /DO NOT LEAK|Leaked|private@/);
  } finally {
    for (const key of env) {
      if (old[key] === undefined) delete process.env[key]; else process.env[key] = old[key];
    }
  }
});

test('a valid-looking alternative contribution prefix cannot replace an accepted one', () => {
  const record = (value, type = 0) => ({ type, bytes: Buffer.from(value), params: new Map() });
  const prefix = { circuitHash: Buffer.alloc(64, 1), records: [record('accepted')] };
  const good = { ...prefix, records: [...prefix.records, record('new')] };
  assert.equal(assertExtension(prefix, good).bytes.toString(), 'new');
  assert.throws(() => assertExtension(prefix, { ...good, records: [record('replacement'), record('new')] }), /preserve/);
  assert.throws(() => assertExtension(prefix, prefix), /exactly one/);
  assert.throws(() => assertExtension(prefix, { ...good, circuitHash: Buffer.alloc(64, 2) }), /Circuit/);
  assert.throws(() => assertExtension(prefix, { ...good, records: [...prefix.records, record('beacon', 1)] }), /type/);
  assert.equal(assertExtension(prefix, { ...good, records: [...prefix.records, record('beacon', 1)] }, 1).type, 1);
});

test('submission cannot add executable files, delete history or change the circuit', () => {
  const base = new Map([['manifest.json', 'm'], ['state.json', 's'], ['request.r1cs', 'r'],
    ['request.zkey', 'a'], ['withdrawal.zkey', 'b']]);
  const next = new Map([...base, ['state.json', 'n'], ['request.zkey', 'c'], ['withdrawal.zkey', 'd'], ['receipt-0001.json', 'e']]);
  validateSubmissionTree(base, next, 1);
  assert.throws(() => validateSubmissionTree(base, new Map([...next, ['run.sh', 'x']]), 1), /unexpected/);
  assert.throws(() => validateSubmissionTree(base, new Map([...next, ['request.r1cs', 'x']]), 1), /changed/);
  const deleted = new Map(next); deleted.delete('manifest.json');
  assert.throws(() => validateSubmissionTree(base, deleted, 1), /unexpected/);
});

test('production planning requires three contributors and a future beacon after closure', () => {
  const config = { id: 'test', setupId: 'mpc-1', sourceCommit: 'a'.repeat(40), ptauSha256: 'b'.repeat(64),
    expectedContributions: 10, contributionsCloseAt: new Date(Date.now() + 60000).toISOString(),
    beacon: { source: 'Public event exact round 1234', notBefore: new Date(Date.now() + 120000).toISOString(), iterationsExp: 10 } };
  validateConfig(config, { initializing: true });
  assert.throws(() => validateConfig({ ...config, expectedContributions: 2 }), /3\.\.1000/);
  assert.throws(() => validateConfig({ ...config, sourceCommit: 'main' }), /full Git commit/);
  assert.throws(() => validateConfig({ ...config, beacon: { ...config.beacon, notBefore: config.contributionsCloseAt } }), /close before/);
  assert.throws(() => openForContributions({ config }, { round: 10, finalized: false }), /All planned/);
  assert.throws(() => openForContributions({ config }, { round: 1, finalized: true }), /finalized/);
  assert.throws(() => openForContributions({ config: { ...config, contributionsCloseAt: '2000-01-01T00:00:00Z' } },
    { round: 1, finalized: false }), /deadline/);
});

test('failed output preparation cleans up and never overwrites an existing artifact', async t => {
  const dir = await temporary(t);
  const output = path.join(dir, 'submission');
  await assert.rejects(stageOutput(output, async staging => {
    await fs.writeFile(path.join(staging, 'partial'), 'incomplete');
    throw new Error('Interrupted');
  }), /Interrupted/);
  assert.deepEqual(await fs.readdir(dir), []);
  await stageOutput(output, async staging => fs.writeFile(path.join(staging, 'receipt'), 'complete'));
  await assert.rejects(stageOutput(output, async () => {}), /overwrite/);
  assert.equal(await fs.readFile(path.join(output, 'receipt'), 'utf8'), 'complete');
});

test('Git compare-and-swap refuses a racing update and rejects symlink trees', async t => {
  const dir = await temporary(t);
  const repo = path.join(dir, 'ledger.git');
  initLedger(repo);
  const first = commitFiles(repo, null, { 'state.json': bytesJson({ round: 0 }) }, identity(), 'Init');
  advance(repo, first);
  const second = commitFiles(repo, first, { 'state.json': bytesJson({ round: 1 }) }, identity(), 'Next');
  advance(repo, second, first);
  assert.throws(() => advance(repo, first, first));
  assert.equal(head(repo), second);
  const oid = git(repo, ['hash-object', '-w', '--stdin'], { input: '/etc/passwd' }).trim();
  const root = git(repo, ['mktree'], { input: `120000 blob ${oid}\tstate.json\n` }).trim();
  const malicious = git(repo, ['commit-tree', root, '-p', first, '-m', 'Link']).trim();
  assert.throws(() => tree(repo, malicious), /ordinary/);
});

test('malformed zkey inputs fail before allocating attacker-supplied section sizes', async t => {
  const dir = await temporary(t);
  const file = path.join(dir, 'malformed.zkey');
  const bytes = Buffer.alloc(24);
  bytes.write('zkey'); bytes.writeUInt32LE(1, 4); bytes.writeUInt32LE(10, 8);
  bytes.writeUInt32LE(10, 12); bytes.writeBigUInt64LE(2n ** 63n, 16);
  await fs.writeFile(file, bytes);
  await assert.rejects(contributionRecords(file), /section table/);
});
