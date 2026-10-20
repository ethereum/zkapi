// EXPLICIT OPT-IN ONLY: npm run rehearse generates toy keys/contributions.
// Never imported by the ordinary unit-test command. Not run during preparation.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { initialize, pack, contribute, accept, finalize, exportFinal } from '../ceremony.mjs';
import { HERE, REF, git, hash, writeJson, bytesJson, initLedger, importBundle, advance, head,
  tree, ledgerJson, extract, commitFiles, cleanEnvironment } from '../lib.mjs';

function u32(value) { const b = Buffer.alloc(4); b.writeUInt32LE(value); return b; }
function le(value, size) {
  const b = Buffer.alloc(size); let n = BigInt(value);
  for (let i = 0; i < size; i++) { b[i] = Number(n & 255n); n >>= 8n; }
  return b;
}
function toyR1cs() {
  // One public output c and two private inputs a,b, constrained by a*b=c.
  const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const header = Buffer.concat([u32(32), le(field, 32), u32(4), u32(1), u32(0), u32(2), le(4, 8), u32(1)]);
  const lc = wire => Buffer.concat([u32(1), u32(wire), le(1, 32)]);
  const constraints = Buffer.concat([lc(2), lc(3), lc(1)]);
  const wires = Buffer.concat([0, 1, 2, 3].map(n => le(n, 8)));
  const section = (id, b) => Buffer.concat([u32(id), le(b.length, 8), b]);
  return Buffer.concat([Buffer.from('r1cs'), u32(1), u32(3), section(1, header), section(2, constraints), section(3, wires)]);
}

test('toy rehearsal: named, anonymous, tampered, stale, final beacon and transcript export', { timeout: 600000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-ceremony-rehearsal-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'); await fs.mkdir(source);
  git(null, ['init', '--template=', source]);
  await fs.writeFile(path.join(source, 'README'), 'Disposable rehearsal source pin\n');
  git(null, ['-C', source, 'add', 'README']);
  git(null, ['-C', source, 'commit', '-m', 'Rehearsal fixture']);
  const revision = git(null, ['-C', source, 'rev-parse', 'HEAD']).trim();
  const fixtures = path.join(root, 'r1cs'); await fs.mkdir(fixtures);
  const r1csFiles = {};
  for (const kind of ['request', 'withdrawal']) {
    await fs.writeFile(path.join(fixtures, `${kind}.r1cs`), toyR1cs());
    r1csFiles[`${kind}.r1cs`] = await hash(path.join(fixtures, `${kind}.r1cs`));
  }
  await writeJson(path.join(fixtures, 'r1cs-manifest.json'), { circuit_id: 'toy-rehearsal-only', files: r1csFiles });
  const snark = args => execFileSync(process.execPath, [path.join(HERE, 'node_modules/snarkjs/build/cli.cjs'), ...args],
    { env: cleanEnvironment(), stdio: 'pipe', timeout: 120000 });
  const raw = path.join(root, 'raw.ptau');
  const contributed = path.join(root, 'contributed.ptau');
  const ptau = path.join(root, 'pot.ptau');
  snark(['powersoftau', 'new', 'bn128', '4', raw]);
  snark(['powersoftau', 'contribute', raw, contributed, '--name=PUBLIC REHEARSAL ONLY', '-e=public rehearsal entropy']);
  snark(['powersoftau', 'prepare', 'phase2', contributed, ptau]);
  const config = { id: 'toy-rehearsal', setupId: 'rehearsal', sourceCommit: revision,
    ptauSha256: await hash(ptau), expectedContributions: 2,
    contributionsCloseAt: new Date(Date.now() + 3600000).toISOString(),
    beacon: { source: 'Disposable rehearsal beacon, never production',
      notBefore: new Date(Date.now() + 7200000).toISOString(), iterationsExp: 10 } };
  const configFile = path.join(root, 'config.json'); await writeJson(configFile, config);
  const state = path.join(root, 'state');
  await initialize({ config: configFile, source, ptau, out: state, 'r1cs-dir': fixtures });
  const repo = path.join(state, 'ledger.git');
  const firstPackage = path.join(root, 'participant-01');
  await pack({ state, out: firstPackage });
  const named = path.join(root, 'named');
  const stale = path.join(root, 'stale');
  await contribute({ package: firstPackage, out: named, name: 'Alice', email: 'alice@example.org',
    'assignment-sha256': await hash(path.join(firstPackage, 'assignment.json')) });
  await contribute({ package: firstPackage, out: stale, anonymous: true });
  await accept({ state, bundle: path.join(named, 'contribution.bundle') });
  const afterFirst = head(repo);
  await assert.rejects(accept({ state, bundle: path.join(stale, 'contribution.bundle') }), /Stale/);
  assert.equal(head(repo), afterFirst);

  const secondPackage = path.join(root, 'participant-02');
  await pack({ state, out: secondPackage });
  const anonymous = path.join(root, 'anonymous');
  // Explicit empty strings exercise the same identity normalization as Enter.
  await contribute({ package: secondPackage, out: anonymous, name: '', email: '' });
  const originalReceipt = JSON.parse(await fs.readFile(path.join(anonymous, 'receipt.json')));
  assert.deepEqual(originalReceipt.participant, { name: null, email: null });

  // Forge a correctly parented commit with consistent receipt/file hashes but
  // corrupted curve points. A checksum-only acceptor would incorrectly accept.
  const maliciousRepo = path.join(root, 'malicious.git'); initLedger(maliciousRepo);
  const base = importBundle(maliciousRepo, path.join(secondPackage, 'input.bundle')); advance(maliciousRepo, base);
  const valid = importBundle(maliciousRepo, path.join(anonymous, 'contribution.bundle'));
  const entries = tree(maliciousRepo, valid);
  const corrupted = path.join(root, 'corrupt.zkey');
  const validWithdrawal = path.join(root, 'withdrawal.zkey');
  await extract(maliciousRepo, entries, 'request.zkey', corrupted);
  await extract(maliciousRepo, entries, 'withdrawal.zkey', validWithdrawal);
  const data = await fs.readFile(corrupted);
  let offset = 12;
  for (let i = 0; i < data.readUInt32LE(8); i++) {
    const id = data.readUInt32LE(offset);
    const length = Number(data.readBigUInt64LE(offset + 4));
    if (id === 8) { data[offset + 12] ^= 1; break; }
    offset += 12 + length;
  }
  await fs.writeFile(corrupted, data);
  const forgedState = ledgerJson(maliciousRepo, entries, 'state.json');
  const forgedReceipt = structuredClone(originalReceipt);
  forgedState.zkeys.request = await hash(corrupted);
  forgedReceipt.outputs.request = forgedState.zkeys.request;
  const forged = commitFiles(maliciousRepo, base, {
    'request.zkey': corrupted, 'withdrawal.zkey': validWithdrawal,
    'state.json': bytesJson(forgedState), 'receipt-0002.json': bytesJson(forgedReceipt),
  }, { name: null, email: null }, 'Forged contribution');
  advance(maliciousRepo, forged, base);
  const maliciousBundle = path.join(root, 'malicious.bundle');
  git(maliciousRepo, ['bundle', 'create', maliciousBundle, `${base}..${REF}`]);
  await assert.rejects(accept({ state, bundle: maliciousBundle }), /verify failed/);
  assert.equal(head(repo), afterFirst);

  await accept({ state, bundle: path.join(anonymous, 'contribution.bundle') });
  const acceptedTree = tree(repo, head(repo));
  const acceptance = ledgerJson(repo, acceptedTree, 'acceptance-0002.json');
  const rawCommit = git(repo, ['cat-file', 'commit', acceptance.submissionCommit]);
  assert.match(rawCommit, /author Anonymous <anonymous@participants.invalid>/);
  const beaconFile = path.join(root, 'beacon.json');
  await writeJson(beaconFile, { source: config.beacon.source, value: 'ab'.repeat(32),
    evidence: 'Public deterministic toy beacon; not a production beacon' });
  await assert.rejects(finalize({ state, beacon: beaconFile }), /still in the future/);
  const realNow = Date.now;
  Date.now = () => Date.parse(config.beacon.notBefore) + 1000;
  try { await finalize({ state, beacon: beaconFile }); } finally { Date.now = realNow; }
  const output = path.join(root, 'final');
  await exportFinal({ state, out: output });
  const transcript = JSON.parse(await fs.readFile(path.join(output, 'transcript.json')));
  assert.equal(transcript.contributions.length, 2);
  assert.equal(transcript.finalCommit, head(repo));
  assert.equal(transcript.files['request_final.zkey'], await hash(path.join(output, 'request_final.zkey')));
  assert.equal(transcript.files['transcript.bundle'], await hash(path.join(output, 'transcript.bundle')));
  const reviewRepo = path.join(root, 'review.git'); initLedger(reviewRepo);
  assert.equal(importBundle(reviewRepo, path.join(output, 'transcript.bundle')), head(repo));
  await assert.rejects(pack({ state, out: path.join(root, 'after-final') }), /finalized/);
});
