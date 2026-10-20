import { createHash } from 'node:crypto';
import { createReadStream, constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { devNull } from 'node:os';
import { execFileSync, fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const KINDS = ['request', 'withdrawal'];
export const REF = 'refs/heads/ceremony';
export const TOOL_FILES = ['package.json', 'package-lock.json', 'ceremony.mjs', 'lib.mjs',
  'crypto-worker.mjs', 'contribute.sh', 'contribute.cmd'];
export const CIRCUIT_ID = 'zkapi-v2-concession-v1';
export const PUBLIC_PTAU_16 = '6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125';
const HASH = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const ANON = { name: 'Anonymous', email: 'anonymous@participants.invalid' };
const DATE = '946684800 +0000'; // Fixed UTC dates avoid leaking participant timezone/time.

export function check(condition, message) { if (!condition) throw new Error(message); }
export function json(value) { return `${JSON.stringify(value, null, 2)}\n`; }
export function equal(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
export function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
export async function hash(file, algorithm = 'sha256') {
  const h = createHash(algorithm);
  for await (const chunk of createReadStream(file)) h.update(chunk);
  return h.digest('hex');
}
export async function readJson(file) { return JSON.parse(await fs.readFile(file, 'utf8')); }
export async function writeJson(file, value) { await fs.writeFile(file, json(value), { flag: 'wx' }); }
export async function copy(from, to) { await fs.copyFile(from, to, constants.COPYFILE_EXCL); }
export async function absent(file) {
  try { await fs.lstat(file); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
  throw new Error(`Refusing to overwrite ${file}`);
}
export async function stageOutput(destination, action) {
  const dest = path.resolve(destination);
  await absent(dest);
  await fs.mkdir(path.dirname(dest), { recursive: true });
  const temporary = await fs.mkdtemp(`${dest}.partial-`);
  try {
    const result = await action(temporary);
    await absent(dest);
    await fs.rename(temporary, dest);
    return result;
  } catch (e) {
    await fs.rm(temporary, { recursive: true, force: true });
    throw e;
  }
}
export async function locked(state, action) {
  const lock = path.join(state, '.ceremony-lock');
  await fs.mkdir(lock).catch(e => {
    if (e.code === 'EEXIST') throw new Error('Ceremony is locked. Do not run concurrent coordinator commands.');
    throw e;
  });
  try { return await action(); } finally { await fs.rmdir(lock); }
}

export function identity(name, email) {
  const clean = (value, field, max) => {
    if (value == null) return null;
    check(typeof value === 'string', `Invalid ${field}`);
    if (value.trim() === '') return null;
    const text = value.trim();
    check(!/[\x00-\x1f\x7f<>]/.test(text) && Buffer.byteLength(text) <= max, `Invalid ${field}`);
    if (field === 'email') check(/^[^\s@]+@[^\s@]+$/.test(text), 'Invalid email');
    return text;
  };
  return { name: clean(name, 'name', 64), email: clean(email, 'email', 254) };
}
export function gitIdentity(person) {
  return { name: person.name || ANON.name, email: person.email || ANON.email };
}
export function cleanEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(GIT_|EMAIL$|NODE_OPTIONS$|NODE_PATH$|NODE_V8_COVERAGE$)/i.test(key)));
}
export function git(repo, args, { input, person = ANON, binary = false } = {}) {
  const id = gitIdentity(person);
  return execFileSync('git', ['-c', 'core.hooksPath=' + devNull,
    '-c', 'commit.gpgSign=false', '-c', 'tag.gpgSign=false', '-c', 'core.autocrlf=false',
    '-c', 'core.attributesFile=' + devNull, '-c', 'core.quotePath=false',
    ...(repo ? ['--git-dir', repo] : []), ...args], {
    input, encoding: binary ? undefined : 'utf8', maxBuffer: 16 * 1024 * 1024,
    env: { ...cleanEnvironment(), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: devNull,
      GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0',
      GIT_AUTHOR_NAME: id.name, GIT_AUTHOR_EMAIL: id.email,
      GIT_COMMITTER_NAME: id.name, GIT_COMMITTER_EMAIL: id.email,
      GIT_AUTHOR_DATE: DATE, GIT_COMMITTER_DATE: DATE },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}
export function initLedger(repo) {
  git(null, ['init', '--bare', '--object-format=sha1', '--template=', repo]);
  git(repo, ['symbolic-ref', 'HEAD', REF]);
}
export function head(repo) { return git(repo, ['rev-parse', '--verify', REF]).trim(); }
export function tree(repo, commit) {
  check(COMMIT.test(commit), 'Invalid commit ID');
  const result = new Map();
  for (const entry of git(repo, ['ls-tree', '-z', commit]).split('\0').filter(Boolean)) {
    const match = /^(100644) blob ([a-f0-9]{40})\t([a-zA-Z0-9_.-]+)$/.exec(entry);
    check(match && !result.has(match[3]), 'Ceremony tree must contain only ordinary, flat files');
    result.set(match[3], match[2]);
  }
  return result;
}
export function blob(repo, entries, name) {
  check(entries.has(name), `Missing ledger file ${name}`);
  return git(repo, ['cat-file', 'blob', entries.get(name)], { binary: true });
}
export function ledgerJson(repo, entries, name) { return JSON.parse(blob(repo, entries, name)); }
export async function extract(repo, entries, name, output) {
  check(entries.has(name), `Missing ledger file ${name}`);
  // Stream large zkeys directly to a new file, without a text conversion.
  const fd = await fs.open(output, 'wx');
  try {
    execFileSync('git', ['--git-dir', repo, 'cat-file', 'blob', entries.get(name)], {
      env: { ...cleanEnvironment(), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: devNull,
        GIT_NO_REPLACE_OBJECTS: '1' }, stdio: ['ignore', fd.fd, 'pipe'],
    });
  } finally { await fd.close(); }
}
export function commitFiles(repo, previous, files, person, message) {
  const entries = previous ? tree(repo, previous) : new Map();
  for (const [name, value] of Object.entries(files)) {
    check(/^[a-zA-Z0-9_.-]+$/.test(name), 'Invalid ledger path');
    const oid = typeof value === 'string'
      ? git(repo, ['hash-object', '-w', '--no-filters', '--', value]).trim()
      : git(repo, ['hash-object', '-w', '--stdin'], { input: value }).trim();
    entries.set(name, oid);
  }
  const listing = [...entries].sort(([a], [b]) => a.localeCompare(b, 'en'))
    .map(([name, oid]) => `100644 blob ${oid}\t${name}\0`).join('');
  const root = git(repo, ['mktree', '-z'], { input: listing }).trim();
  return git(repo, ['commit-tree', root, ...(previous ? ['-p', previous] : []), '-m', message], { person }).trim();
}
export function advance(repo, next, previous = '0'.repeat(40)) {
  git(repo, ['update-ref', REF, next, previous]);
}
export function importBundle(repo, file) {
  const refs = git(repo, ['bundle', 'list-heads', file]).trim().split('\n');
  check(refs.length === 1 && /^[a-f0-9]{40} refs\/heads\/ceremony$/.test(refs[0]),
    'Bundle must contain exactly the ceremony branch');
  git(repo, ['bundle', 'verify', file]);
  git(repo, ['bundle', 'unbundle', file]); // Objects only; never check out or execute submission files.
  const revision = refs[0].split(' ')[0];
  check(git(repo, ['cat-file', '-t', revision]).trim() === 'commit', 'Bundle branch must point directly to a commit');
  return revision;
}
export function bytesJson(value) { return Buffer.from(json(value)); }
export function roundName(prefix, round) { return `${prefix}-${String(round).padStart(4, '0')}.json`; }

export function validateConfig(config, { initializing = false } = {}) {
  check(config && /^[a-z0-9][a-z0-9-]{0,79}$/.test(config.id), 'Invalid ceremony ID');
  check(['mpc-1', 'rehearsal'].includes(config.setupId), 'setupId must be mpc-1 or rehearsal');
  check(COMMIT.test(config.sourceCommit), 'Set sourceCommit to the reviewed full Git commit');
  check(HASH.test(config.ptauSha256), 'Invalid ptau SHA-256');
  const minimum = config.setupId === 'mpc-1' ? 3 : 1;
  check(Number.isSafeInteger(config.expectedContributions) && config.expectedContributions >= minimum
    && config.expectedContributions <= 1000, `expectedContributions must be ${minimum}..1000`);
  const deadline = Date.parse(config.contributionsCloseAt);
  const beaconTime = Date.parse(config.beacon?.notBefore);
  check(Number.isFinite(deadline) && Number.isFinite(beaconTime) && deadline < beaconTime,
    'Contributions must close before the beacon becomes available');
  check(typeof config.beacon?.source === 'string' && config.beacon.source.length >= 12
    && !config.beacon.source.includes('REPLACE_'), 'Specify the exact future public beacon event');
  check(config.beacon.iterationsExp === 10, 'This tool pins the beacon iteration exponent to 10');
  if (initializing) check(Date.now() < deadline, 'Contribution deadline must be in the future');
}
export function openForContributions(manifest, state) {
  check(!state.finalized, 'Ceremony is finalized');
  check(Date.now() < Date.parse(manifest.config.contributionsCloseAt), 'Contribution deadline has passed');
  check(state.round < manifest.config.expectedContributions, 'All planned contributions have been accepted');
}
export async function softwareHashes() {
  return Object.fromEntries(await Promise.all(TOOL_FILES.map(async f => [f, await hash(path.join(HERE, f))])));
}
export async function checkSoftware(manifest) {
  check(equal(manifest.software, await softwareHashes()), 'Tooling differs from the version frozen for this ceremony');
}
export async function checkPtau(file, config) {
  check(await hash(file) === config.ptauSha256, 'Powers-of-tau SHA-256 mismatch');
  if (config.setupId === 'mpc-1') {
    check(await hash(file, 'blake2b512') === PUBLIC_PTAU_16,
      'Production tooling accepts the public Hermez power-16 transcript only');
  }
}
export function cryptoOperation(operation, args) {
  console.log(`  ${operation} ${operation === 'contribute' ? '(fresh local randomness)' : ''}`.trimEnd());
  return new Promise((resolve, reject) => {
    let ok = false;
    const child = fork(path.join(HERE, 'crypto-worker.mjs'), [], {
      execArgv: [], env: cleanEnvironment(), stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    });
    child.on('message', message => { ok = message?.ok === true; });
    child.once('error', reject);
    child.once('exit', code => code === 0 && ok ? resolve() : reject(new Error(`${operation} failed`)));
    child.send({ operation, args });
  });
}

// Read only section 10, not the large proving queries. Comparing entire
// serialized records prevents replacing a valid prefix with a different valid
// chain. snarkjs verification alone does NOT enforce this prefix relationship.
export async function contributionRecords(file) {
  const fd = await fs.open(file, 'r');
  try {
    const size = (await fd.stat()).size;
    const read = async (position, length) => {
      check(Number.isSafeInteger(position + length) && position + length <= size, 'Truncated zkey');
      const data = Buffer.alloc(length);
      const { bytesRead } = await fd.read(data, 0, length, position);
      check(bytesRead === length, 'Truncated zkey');
      return data;
    };
    const header = await read(0, 12);
    check(header.subarray(0, 4).toString() === 'zkey' && header.readUInt32LE(4) === 1,
      'Unsupported zkey format');
    const sections = new Map();
    const count = header.readUInt32LE(8);
    check(count === 10, 'Expected a Groth16 zkey with ten sections');
    let position = 12;
    for (let i = 0; i < count; i++) {
      const record = await read(position, 12);
      const id = record.readUInt32LE(0);
      const length = Number(record.readBigUInt64LE(4));
      position += 12;
      check(!sections.has(id) && Number.isSafeInteger(length) && position + length <= size,
        'Invalid zkey section table');
      sections.set(id, { position, length });
      position += length;
    }
    check(position === size && [...Array(10)].every((_, i) => sections.has(i + 1)), 'Invalid zkey sections');
    const protocol = sections.get(1);
    check(protocol.length === 4 && (await read(protocol.position, 4)).readUInt32LE(0) === 1, 'Not Groth16');
    const curve = await read(sections.get(2).position, 40);
    check(curve.readUInt32LE(0) === 32 && curve.readUInt32LE(36) === 32, 'Expected BN254 field widths');
    const section = sections.get(10);
    check(section.length >= 68 && section.length <= 2 * 1024 * 1024, 'Invalid contribution section size');
    const bytes = await read(section.position, section.length);
    const n = bytes.readUInt32LE(64);
    check(n <= 1001, 'Too many contributions');
    const records = [];
    let offset = 68;
    for (let i = 0; i < n; i++) {
      check(offset + 392 <= bytes.length, 'Truncated contribution record');
      const type = bytes.readUInt32LE(offset + 384);
      const end = offset + 392 + bytes.readUInt32LE(offset + 388);
      check(end <= bytes.length && (type === 0 || type === 1), 'Invalid contribution record');
      const params = new Map();
      let p = offset + 392;
      let previous = 0;
      while (p < end) {
        const id = bytes[p++];
        check(id > previous && id <= 3 && p < end, 'Invalid contribution parameters');
        previous = id;
        const length = id === 2 ? 1 : bytes[p++];
        check(p + length <= end, 'Truncated contribution parameter');
        params.set(id, bytes.subarray(p, p + length));
        p += length;
      }
      records.push({ type, bytes: bytes.subarray(offset, end), params });
      offset = end;
    }
    check(offset === bytes.length, 'Trailing contribution bytes');
    return { circuitHash: bytes.subarray(0, 64), records };
  } finally { await fd.close(); }
}
export function assertExtension(before, after, type = 0) {
  check(before.circuitHash.equals(after.circuitHash), 'Circuit transcript hash changed');
  check(after.records.length === before.records.length + 1, 'Expected exactly one new contribution');
  check(before.records.every((r, i) => r.type === 0 && r.bytes.equals(after.records[i].bytes)),
    'Contribution does not preserve the accepted transcript');
  const added = after.records.at(-1);
  check(added.type === type, 'Unexpected contribution type');
  return added;
}
export function validateSubmissionTree(before, after, round) {
  const changed = new Set(['state.json', 'request.zkey', 'withdrawal.zkey', roundName('receipt', round)]);
  check(!before.has(roundName('receipt', round)), 'Round already has a receipt');
  check(after.size === before.size + 1, 'Submission added or removed unexpected files');
  for (const [name, oid] of before) {
    check(after.has(name) && (changed.has(name) || after.get(name) === oid), `Submission changed ${name}`);
  }
  for (const name of after.keys()) check(before.has(name) || changed.has(name), `Unexpected file ${name}`);
}
