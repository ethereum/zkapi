#!/usr/bin/env node
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';
import {
  HERE, KINDS, REF, TOOL_FILES, CIRCUIT_ID, check, json, equal, digest, hash,
  readJson, writeJson, copy, stageOutput, locked, identity, gitIdentity, cleanEnvironment,
  git, initLedger, head, tree, ledgerJson, extract, commitFiles, advance, importBundle,
  bytesJson, roundName, validateConfig, openForContributions, softwareHashes, checkSoftware,
  checkPtau, cryptoOperation, contributionRecords, assertExtension, validateSubmissionTree,
} from './lib.mjs';

const COORDINATOR = { name: 'Ceremony coordinator', email: 'coordinator@participants.invalid' };
const ledgerPath = directory => path.join(directory, 'ledger.git');

function load(repo, revision = head(repo)) {
  const entries = tree(repo, revision);
  const manifest = ledgerJson(repo, entries, 'manifest.json');
  const state = ledgerJson(repo, entries, 'state.json');
  check(manifest.version === 1 && manifest.snarkjs === '0.7.6', 'Unsupported ceremony manifest');
  validateConfig(manifest.config);
  check(state.id === manifest.config.id && Number.isSafeInteger(state.round) && state.round >= 0
    && state.round <= manifest.config.expectedContributions && typeof state.finalized === 'boolean',
  'Invalid ceremony state');
  return { repo, revision, entries, manifest, state };
}

async function materialize(snapshot, directory) {
  const { repo, entries, manifest, state } = snapshot;
  for (const file of ['r1cs-manifest.json', ...KINDS.flatMap(k => [`${k}.r1cs`, `${k}.zkey`])]) {
    await extract(repo, entries, file, path.join(directory, file));
  }
  check(await hash(path.join(directory, 'r1cs-manifest.json')) === manifest.r1csManifestSha256,
    'R1CS manifest hash mismatch');
  for (const kind of KINDS) {
    check(await hash(path.join(directory, `${kind}.r1cs`)) === manifest.r1cs[kind], `${kind} R1CS hash mismatch`);
    check(await hash(path.join(directory, `${kind}.zkey`)) === state.zkeys[kind], `${kind} zkey hash mismatch`);
    const transcript = await contributionRecords(path.join(directory, `${kind}.zkey`));
    check(transcript.records.length === state.round + Number(state.finalized), 'Contribution count mismatch');
    check(transcript.records.every((r, i) => r.type === (state.finalized && i === state.round ? 1 : 0)),
      'Unexpected beacon in contribution chain');
  }
}

async function scratch(state, action) {
  const temp = await fs.mkdtemp(path.join(state, '.operation-'));
  try { return await action(temp); } finally { await fs.rm(temp, { recursive: true, force: true }); }
}

export async function initialize(options) {
  const config = await readJson(options.config);
  validateConfig(config, { initializing: true });
  const source = path.resolve(options.source);
  check(git(null, ['-C', source, 'rev-parse', 'HEAD']).trim() === config.sourceCommit,
    'Source checkout is not the frozen commit');
  check(git(null, ['-C', source, 'status', '--porcelain']).trim() === '', 'Freeze a clean source checkout first');
  check(!options['r1cs-dir'] || config.setupId === 'rehearsal', 'Production initialization exports its own frozen circuits');
  await checkPtau(path.resolve(options.ptau), config);
  await stageOutput(options.out, async directory => {
    await copy(path.resolve(options.ptau), path.join(directory, 'pot.ptau'));
    await checkPtau(path.join(directory, 'pot.ptau'), config);
    await cryptoOperation('verify-ptau', [path.join(directory, 'pot.ptau')]);
    const work = path.join(directory, 'initial');
    await fs.mkdir(work);
    if (options['r1cs-dir']) {
      for (const file of ['request.r1cs', 'withdrawal.r1cs', 'r1cs-manifest.json']) {
        await copy(path.join(path.resolve(options['r1cs-dir']), file), path.join(work, file));
      }
    } else {
      execFileSync('cargo', ['run', '--locked', '--release', '--manifest-path',
        path.join(source, 'protocol/rust/Cargo.toml'), '-p', 'zkapi-proof', '--example',
        'export_r1cs', '--', work], { env: cleanEnvironment(), stdio: 'inherit' });
    }
    const r1csManifest = await readJson(path.join(work, 'r1cs-manifest.json'));
    check(config.setupId === 'rehearsal' || r1csManifest.circuit_id === CIRCUIT_ID, 'Wrong circuit ID');
    const manifest = {
      version: 1, config, circuitId: r1csManifest.circuit_id, snarkjs: '0.7.6',
      software: await softwareHashes(), r1cs: {},
      r1csManifestSha256: await hash(path.join(work, 'r1cs-manifest.json')),
    };
    const state = { id: config.id, round: 0, finalized: false, zkeys: {} };
    const files = { 'r1cs-manifest.json': path.join(work, 'r1cs-manifest.json') };
    for (const kind of KINDS) {
      const r1cs = path.join(work, `${kind}.r1cs`);
      const zkey = path.join(work, `${kind}.zkey`);
      manifest.r1cs[kind] = await hash(r1cs);
      check(manifest.r1cs[kind] === r1csManifest.files[`${kind}.r1cs`], 'Export does not match its R1CS manifest');
      await cryptoOperation('new', [r1cs, path.join(directory, 'pot.ptau'), zkey]);
      await cryptoOperation('verify', [r1cs, path.join(directory, 'pot.ptau'), zkey]);
      check((await contributionRecords(zkey)).records.length === 0, 'Initial key contains contributions');
      state.zkeys[kind] = await hash(zkey);
      files[`${kind}.r1cs`] = r1cs;
      files[`${kind}.zkey`] = zkey;
    }
    files['manifest.json'] = bytesJson(manifest);
    files['state.json'] = bytesJson(state);
    check(git(null, ['-C', source, 'rev-parse', 'HEAD']).trim() === config.sourceCommit
      && git(null, ['-C', source, 'status', '--porcelain']).trim() === '',
    'Source changed during initialization; freeze it again');
    const repo = ledgerPath(directory);
    initLedger(repo);
    advance(repo, commitFiles(repo, null, files, COORDINATOR, `Initialize ${config.id}`));
    await fs.rm(work, { recursive: true });
  });
  console.log(`Initialized ${config.id} at ${path.resolve(options.out)}. No participant contributions yet.`);
}

export async function pack(options) {
  const directory = path.resolve(options.state);
  return locked(directory, async () => {
    const snapshot = load(ledgerPath(directory));
    openForContributions(snapshot.manifest, snapshot.state);
    await checkSoftware(snapshot.manifest);
    await checkPtau(path.join(directory, 'pot.ptau'), snapshot.manifest.config);
    await stageOutput(options.out, async output => {
      for (const file of TOOL_FILES) await copy(path.join(HERE, file), path.join(output, file));
      await copy(path.join(HERE, 'PARTICIPANT.md'), path.join(output, 'README.md'));
      await fs.chmod(path.join(output, 'contribute.sh'), 0o755);
      await copy(path.join(directory, 'pot.ptau'), path.join(output, 'pot.ptau'));
      git(snapshot.repo, ['bundle', 'create', path.join(output, 'input.bundle'), REF]);
      await writeJson(path.join(output, 'assignment.json'), {
        version: 1, id: snapshot.manifest.config.id, round: snapshot.state.round + 1,
        baseCommit: snapshot.revision, manifestSha256: digest(bytesJson(snapshot.manifest)),
        inputBundleSha256: await hash(path.join(output, 'input.bundle')),
      });
      const hashes = {};
      for (const file of [...TOOL_FILES, 'README.md', 'pot.ptau', 'input.bundle', 'assignment.json']) {
        hashes[file] = await hash(path.join(output, file));
      }
      await writeJson(path.join(output, 'checksums.json'), hashes);
    });
    console.log(`Participant ${snapshot.state.round + 1}: ${path.resolve(options.out)}`);
    console.log(`Assignment SHA-256 (send separately): ${await hash(path.join(path.resolve(options.out), 'assignment.json'))}`);
    console.log('Archive this whole directory for the participant. Do not issue the next turn until acceptance.');
  });
}

async function askIdentity(options) {
  check(!(options.anonymous && (options.name !== undefined || options.email !== undefined)),
    'Use either --anonymous or name/email');
  if (options.anonymous) return identity();
  if (options.name !== undefined || options.email !== undefined) return identity(options.name, options.email);
  check(process.stdin.isTTY, 'For noninteractive use, choose --anonymous or pass --name / --email');
  console.log('Name and email are optional and will be published if supplied. Enter skips either field.');
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return identity(await prompt.question('Name (optional): '), await prompt.question('Email (optional): '));
  } finally { prompt.close(); }
}

export async function contribute(options) {
  const packageDir = path.resolve(options.package);
  if (options['assignment-sha256']) {
    check(await hash(path.join(packageDir, 'assignment.json')) === options['assignment-sha256'], 'Assignment pin mismatch');
  }
  const assignment = await readJson(path.join(packageDir, 'assignment.json'));
  check(assignment.version === 1, 'Unsupported assignment');
  check(await hash(path.join(packageDir, 'input.bundle')) === assignment.inputBundleSha256, 'Input bundle hash mismatch');
  const person = await askIdentity(options);
  await stageOutput(options.out, async output => {
    const repo = ledgerPath(output);
    initLedger(repo);
    const base = importBundle(repo, path.join(packageDir, 'input.bundle'));
    check(base === assignment.baseCommit, 'Input bundle is not the assigned base');
    advance(repo, base);
    const snapshot = load(repo);
    const { manifest, state } = snapshot;
    check(assignment.id === manifest.config.id && assignment.round === state.round + 1, 'Wrong assignment');
    check(digest(bytesJson(manifest)) === assignment.manifestSha256, 'Manifest pin mismatch');
    await checkSoftware(manifest);
    openForContributions(manifest, state);
    const ptau = path.join(packageDir, 'pot.ptau');
    await checkPtau(ptau, manifest.config);
    const work = path.join(output, 'work');
    await fs.mkdir(work);
    await materialize(snapshot, work);
    const receipt = {
      version: 1, id: manifest.config.id, round: assignment.round, baseCommit: base,
      participant: person, inputs: state.zkeys, outputs: {}, contributionRecordSha256: {},
    };
    const files = {};
    for (const kind of KINDS) {
      const input = path.join(work, `${kind}.zkey`);
      const result = path.join(work, `${kind}-next.zkey`);
      const r1cs = path.join(work, `${kind}.r1cs`);
      if (options['r1cs-dir']) {
        check(await hash(path.join(path.resolve(options['r1cs-dir']), `${kind}.r1cs`)) === manifest.r1cs[kind],
          `Your independent ${kind} export differs from the frozen circuit`);
      }
      console.log(`Checking and contributing to ${kind}…`);
      await cryptoOperation('verify', [r1cs, ptau, input]);
      await cryptoOperation('contribute', [input, result, person.name || 'Anonymous']);
      const added = assertExtension(await contributionRecords(input), await contributionRecords(result));
      await cryptoOperation('verify', [r1cs, ptau, result]);
      receipt.outputs[kind] = await hash(result);
      receipt.contributionRecordSha256[kind] = digest(added.bytes);
      files[`${kind}.zkey`] = result;
    }
    openForContributions(manifest, state); // Work finishing after the deadline must be rerun in a new ceremony.
    const nextState = { ...state, round: assignment.round, zkeys: receipt.outputs };
    files['state.json'] = bytesJson(nextState);
    files[roundName('receipt', assignment.round)] = bytesJson(receipt);
    const next = commitFiles(repo, base, files, person, `Contribute round ${assignment.round}`);
    advance(repo, next, base);
    git(repo, ['bundle', 'create', path.join(output, 'contribution.bundle'), `${base}..${REF}`]);
    await writeJson(path.join(output, 'receipt.json'), receipt);
    await fs.writeFile(path.join(output, 'contribution.bundle.sha256'), `${await hash(path.join(output, 'contribution.bundle'))}  contribution.bundle\n`);
    await fs.rm(work, { recursive: true });
    await fs.rm(repo, { recursive: true });
  });
  console.log(`Send ${path.resolve(options.out, 'contribution.bundle')} and its .sha256 file to the coordinator.`);
}

export async function accept(options) {
  const directory = path.resolve(options.state);
  return locked(directory, () => scratch(directory, async work => {
    const snapshot = load(ledgerPath(directory));
    const { repo, revision, manifest, state } = snapshot;
    openForContributions(manifest, state);
    await checkSoftware(manifest);
    await checkPtau(path.join(directory, 'pot.ptau'), manifest.config);
    const candidate = importBundle(repo, path.resolve(options.bundle));
    const ancestry = git(repo, ['rev-list', '--parents', '-n', '1', candidate]).trim().split(' ');
    check(ancestry.length === 2 && ancestry[1] === revision, 'Stale or unrelated submission: rerun from the current assignment');
    const proposed = load(repo, candidate);
    const round = state.round + 1;
    validateSubmissionTree(snapshot.entries, proposed.entries, round);
    const receipt = ledgerJson(repo, proposed.entries, roundName('receipt', round));
    const person = identity(receipt.participant?.name, receipt.participant?.email);
    check(receipt.version === 1 && receipt.id === manifest.config.id && receipt.round === round
      && receipt.baseCommit === revision && equal(receipt.participant, person)
      && equal(receipt.inputs, state.zkeys), 'Invalid contribution receipt');
    check(equal(proposed.state, { ...state, round, zkeys: receipt.outputs }), 'Invalid proposed state');
    const id = gitIdentity(person);
    const authors = git(repo, ['show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce', candidate]).trimEnd().split('\0');
    check(equal(authors, [id.name, id.email, id.name, id.email]), 'Git identity does not match the receipt');
    const before = path.join(work, 'before');
    const after = path.join(work, 'after');
    await fs.mkdir(before); await fs.mkdir(after);
    await materialize(snapshot, before);
    await materialize(proposed, after);
    for (const kind of KINDS) {
      const added = assertExtension(await contributionRecords(path.join(before, `${kind}.zkey`)),
        await contributionRecords(path.join(after, `${kind}.zkey`)));
      check(digest(added.bytes) === receipt.contributionRecordSha256[kind], 'Contribution receipt hash mismatch');
      check(added.params.get(1)?.toString('utf8') === (person.name || 'Anonymous'), 'Contribution name differs from receipt');
      await cryptoOperation('verify', [path.join(before, `${kind}.r1cs`),
        path.join(directory, 'pot.ptau'), path.join(after, `${kind}.zkey`)]);
    }
    const nomination = options.nomination ? await readJson(options.nomination) : null;
    if (nomination) {
      for (const field of ['nominatedBy', 'participantRef', 'evidence']) {
        check(typeof nomination[field] === 'string' && nomination[field].trim().length > 0
          && nomination[field].length <= 2048, `Nomination needs ${field}`);
      }
      for (let i = 1; i <= state.round; i++) {
        const prior = ledgerJson(repo, snapshot.entries, roundName('acceptance', i));
        check(prior.nomination?.participantRef !== nomination.participantRef, 'Externally nominated participant was already counted');
      }
    }
    const acceptance = { round, submissionCommit: candidate, nomination };
    const accepted = commitFiles(repo, candidate, {
      [roundName('acceptance', round)]: bytesJson(acceptance),
    }, COORDINATOR, `Accept round ${round}`);
    openForContributions(manifest, state);
    advance(repo, accepted, revision); // Both keys and evidence become current together.
    console.log(`Accepted round ${round}: ${accepted}`);
  }));
}

export async function finalize(options) {
  const directory = path.resolve(options.state);
  return locked(directory, () => scratch(directory, async work => {
    const snapshot = load(ledgerPath(directory));
    const { repo, revision, entries, manifest, state } = snapshot;
    check(!state.finalized, 'Already finalized');
    check(state.round === manifest.config.expectedContributions, 'Collect all planned contributions first');
    check(Date.now() >= Date.parse(manifest.config.beacon.notBefore), 'The precommitted beacon event is still in the future');
    let nominated = 0;
    for (let i = 1; i <= state.round; i++) {
      if (ledgerJson(repo, entries, roundName('acceptance', i)).nomination) nominated++;
    }
    check(manifest.config.setupId === 'rehearsal' || nominated >= 2, 'Two externally nominated contributions are required');
    const beacon = await readJson(options.beacon);
    check(beacon.source === manifest.config.beacon.source, 'Beacon source differs from the precommitted plan');
    check(/^[a-f0-9]{64}$/.test(beacon.value), 'Beacon value must be 32 bytes of lowercase hex');
    check(typeof beacon.evidence === 'string' && beacon.evidence.length >= 12, 'Record independently checkable beacon evidence');
    await checkSoftware(manifest);
    await checkPtau(path.join(directory, 'pot.ptau'), manifest.config);
    await materialize(snapshot, work);
    const files = {};
    const zkeys = {};
    for (const kind of KINDS) {
      const input = path.join(work, `${kind}.zkey`);
      const result = path.join(work, `${kind}-final.zkey`);
      await cryptoOperation('verify', [path.join(work, `${kind}.r1cs`), path.join(directory, 'pot.ptau'), input]);
      await cryptoOperation('beacon', [input, result, 'Final public beacon', beacon.value, manifest.config.beacon.iterationsExp]);
      const added = assertExtension(await contributionRecords(input), await contributionRecords(result), 1);
      check(added.params.get(3)?.toString('hex') === beacon.value
        && added.params.get(2)?.[0] === manifest.config.beacon.iterationsExp, 'Beacon parameters do not match');
      await cryptoOperation('verify', [path.join(work, `${kind}.r1cs`), path.join(directory, 'pot.ptau'), result]);
      zkeys[kind] = await hash(result);
      files[`${kind}.zkey`] = result;
    }
    files['state.json'] = bytesJson({ ...state, finalized: true, zkeys });
    files['finalization.json'] = bytesJson({ baseCommit: revision, beacon,
      iterationsExp: manifest.config.beacon.iterationsExp, externallyNominatedContributions: nominated });
    const next = commitFiles(repo, revision, files, COORDINATOR, 'Apply final public beacon');
    advance(repo, next, revision);
    console.log(`Finalized ${next}. Export and independently review before importing production keys.`);
  }));
}

export async function exportFinal(options) {
  const directory = path.resolve(options.state);
  return locked(directory, async () => {
    const snapshot = load(ledgerPath(directory));
    check(snapshot.state.finalized, 'Finalize first');
    await checkSoftware(snapshot.manifest);
    await checkPtau(path.join(directory, 'pot.ptau'), snapshot.manifest.config);
    await stageOutput(options.out, async output => {
      await materialize(snapshot, output);
      for (const kind of KINDS) await fs.rename(path.join(output, `${kind}.zkey`), path.join(output, `${kind}_final.zkey`));
      await copy(path.join(directory, 'pot.ptau'), path.join(output, 'pot.ptau'));
      git(snapshot.repo, ['bundle', 'create', path.join(output, 'transcript.bundle'), REF]);
      const files = {};
      for (const file of await fs.readdir(output)) files[file] = await hash(path.join(output, file));
      const contributions = [];
      for (let i = 1; i <= snapshot.state.round; i++) {
        contributions.push({ receipt: ledgerJson(snapshot.repo, snapshot.entries, roundName('receipt', i)),
          acceptance: ledgerJson(snapshot.repo, snapshot.entries, roundName('acceptance', i)) });
      }
      await writeJson(path.join(output, 'transcript.json'), {
        version: 1, finalCommit: snapshot.revision, manifest: snapshot.manifest,
        contributions, finalization: ledgerJson(snapshot.repo, snapshot.entries, 'finalization.json'), files,
      });
      const transcriptHash = await hash(path.join(output, 'transcript.json'));
      const args = ['cargo', 'run', '--locked', '--release', '-p', 'zkapi-proof', '--example', 'import_zkey', '--',
        '--setup-id', snapshot.manifest.config.setupId, '--ptau', 'pot.ptau', '--ptau-sha256', snapshot.manifest.config.ptauSha256,
        '--request-r1cs', 'request.r1cs', '--withdrawal-r1cs', 'withdrawal.r1cs',
        '--request', 'request_final.zkey', '--withdrawal', 'withdrawal_final.zkey',
        '--transcript-sha256', transcriptHash, 'REPLACE_WITH_NEW_SETUP_OUTPUT_DIRECTORY'];
      await writeJson(path.join(output, 'import-arguments.json'), args);
      await fs.writeFile(path.join(output, 'transcript.json.sha256'), `${transcriptHash}  transcript.json\n`);
    });
    console.log(`Exported ${path.resolve(options.out)}. Import was NOT run. See tools/ceremony/README.md for review and import.`);
  });
}

const HELP = `ZK API ceremony tools (Node.js 24+, Git; snarkjs 0.7.6)

No ceremony runs without an explicit command:
  init --source REPO --config CONFIG --ptau FILE --out NEW_STATE
       [--r1cs-dir DIR]  (fixture override for rehearsal only)
  pack --state STATE --out NEW_PARTICIPANT_DIRECTORY
  contribute --package DIRECTORY --out NEW_SUBMISSION_DIRECTORY
       [--anonymous | --name NAME --email EMAIL]
       [--assignment-sha256 HASH] [--r1cs-dir INDEPENDENT_EXPORT]
  accept --state STATE --bundle FILE [--nomination EVIDENCE_JSON]
  finalize --state STATE --beacon BEACON_JSON
  export-final --state STATE --out NEW_EXPORT_DIRECTORY
  status --state STATE

Preparation and launch instructions: tools/ceremony/README.md
`;

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length || ['help', '--help', '-h'].includes(argv[0])) { console.log(HELP); return; }
  check(Number(process.versions.node.split('.')[0]) >= 24, 'Node.js 24 or newer is required');
  const command = argv[0];
  const specifications = {
    init: { required: ['source', 'config', 'ptau', 'out'], optional: ['r1cs-dir'] },
    pack: { required: ['state', 'out'] },
    contribute: { required: ['package', 'out'], optional: ['name', 'email', 'r1cs-dir', 'assignment-sha256'], flags: ['anonymous'] },
    accept: { required: ['state', 'bundle'], optional: ['nomination'] },
    finalize: { required: ['state', 'beacon'] },
    'export-final': { required: ['state', 'out'] },
    status: { required: ['state'] },
  };
  const spec = specifications[command];
  check(spec, `Unknown command ${command}`);
  const options = Object.fromEntries([...spec.required, ...(spec.optional || [])].map(key => [key, { type: 'string' }]));
  for (const key of spec.flags || []) options[key] = { type: 'boolean', default: false };
  const { values } = parseArgs({ args: argv.slice(1), options, allowPositionals: false, strict: true });
  for (const key of spec.required) check(values[key], `Missing --${key}`);
  const handlers = { init: initialize, pack, contribute, accept, finalize, 'export-final': exportFinal,
    status: async args => {
      const s = load(ledgerPath(path.resolve(args.state)));
      console.log(json({ id: s.manifest.config.id, setupId: s.manifest.config.setupId,
        commit: s.revision, accepted: s.state.round, expected: s.manifest.config.expectedContributions,
        finalized: s.state.finalized, contributionsCloseAt: s.manifest.config.contributionsCloseAt,
        beacon: s.manifest.config.beacon }));
    } };
  await handlers[command](values);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`Ceremony stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
