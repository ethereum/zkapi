import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

// Exercise the real launcher with the documented environment and harmless
// executables. This catches shell startup failures without RPCs or credentials.
// Each fake binary prints its arguments, one per line, on stdout and reports
// on stderr the settings it received through its environment.
const REPORTED_ENV = [
    'ZKAPI_STATE_SEED',
    'ZKAPI_CLEAR_SEED',
    'ZKAPI_ALLOW_LEGACY_CLEARANCE',
    'ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS',
    'ZKAPI_ROOT_MAX_STALENESS_SECONDS',
    'ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS',
    'ZKAPI_CHALLENGE_RPC_URL',
    'ZKAPI_CHALLENGE_SENDER',
    'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI',
    'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI',
    'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI',
    'ZKAPI_CHALLENGE_TX_FEE_CAP_WEI',
    'ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS',
    'ZKAPI_CHALLENGE_RAISE_MIN_UNITS',
    'ZKAPI_CHALLENGE_RETIRE_ON_MISS',
];

const BASE_ENV = {
    CHAIN_ID: '11155111',
    VAULT_ADDRESS: '0x0000000000000000000000000000000000000001',
    DEPLOY_BLOCK: '1',
    CIRCUIT_ID: 'zkapi-v2-concession-v1',
    REQUEST_CHARGE_CAP: '50000',
    ZKAPI_NATIVE_BILLING_RPC_URL: 'https://rpc.example',
    ZKAPI_NATIVE_PRICE_FEED_ADDRESS: '0x0000000000000000000000000000000000000003',
    ZKAPI_STATE_SEED: 'test-state-seed',
    ZKAPI_CLEAR_SEED: 'test-clear-seed',
    RPC_URL: 'https://indexer-rpc.example',
    ZKAPI_CHALLENGE_RPC_URL: 'http://signer:8547',
    ZKAPI_CHALLENGE_SENDER: '0x0000000000000000000000000000000000000002',
    ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '100000000000',
    ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: '10000000000',
};

async function launch(role, { set = {}, unset = [], exitCode = 0, refusal = '' } = {}) {
    const bin = await mkdtemp(join(tmpdir(), 'zkapi-launcher-'));
    try {
        const fake = [
            '#!/bin/sh',
            `printf '%s\\n' "$@"`,
            `for name in ${REPORTED_ENV.join(' ')}; do`,
            `    if value=$(printenv "$name"); then printf 'env %s=%s\\n' "$name" "$value" >&2; fi`,
            'done',
            refusal ? `printf '%s\\n' '${refusal}' >&2` : '',
            `exit ${exitCode}`,
            '',
        ].join('\n');
        for (const name of ['zkapi', 'zkapi-indexerd', 'zkapi-challenged']) {
            await writeFile(join(bin, name), fake, { mode: 0o755 });
        }
        const env = { PATH: `${bin}:/usr/bin:/bin`, ...BASE_ENV, ...set };
        for (const name of unset) delete env[name];
        const result = spawnSync('/bin/sh', [resolve('docker/aws/run-daemon.sh'), role], {
            env, encoding: 'utf8', timeout: 5000,
        });
        const args = result.stdout ? result.stdout.trimEnd().split('\n') : [];
        const received = {};
        for (const line of result.stderr.split('\n')) {
            const match = /^env ([A-Z0-9_]+)=(.*)$/.exec(line);
            if (match) received[match[1]] = match[2];
        }
        return { ...result, args, received };
    } finally {
        await rm(bin, { recursive: true, force: true });
    }
}

function flag(args, name) {
    const index = args.indexOf(name);
    assert.ok(index >= 0, `missing ${name} in ${args.join(' ')}`);
    return args[index + 1];
}

for (const role of ['server', 'challenger']) {
    for (const override of [null, '/custom/proofs']) {
        test(`${role} launches with ${override ? 'explicit' : 'default'} proof artifacts`, async () => {
            const result = await launch(role, { set: override ? { ZKAPI_PROOF_SETUP_DIR: override } : {} });
            assert.equal(result.status, 0, result.stderr);
            assert.equal(flag(result.args, '--proof-setup-dir'), override || '/srv/zkapi/protocol/setup/v2-concession');
            if (role === 'server') {
                assert.equal(flag(result.args, '--native-billing-rpc-url'), BASE_ENV.ZKAPI_NATIVE_BILLING_RPC_URL);
                assert.equal(flag(result.args, '--native-price-feed-address'), BASE_ENV.ZKAPI_NATIVE_PRICE_FEED_ADDRESS);
            }
            assert.ok(!result.stdout.includes('test-state-seed'));
            assert.ok(!result.stdout.includes('test-clear-seed'));
        });
    }
}

test('server forwards the settlement deadline and native price policy defaults', async () => {
    const result = await launch('server');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--openrouter-settlement-deadline-seconds'), '21600');
    assert.equal(flag(result.args, '--native-price-max-age-seconds'), '4500');
    assert.equal(flag(result.args, '--native-price-feed-decimals'), '8');
    assert.equal(flag(result.args, '--openrouter-lease-ttl-seconds'), '300');
    assert.equal(flag(result.args, '--openrouter-settlement-grace-seconds'), '5');
    assert.equal(flag(result.args, '--indexer-url'), 'http://indexer:3001');
    assert.equal(flag(result.args, '--db-path'), '/data/server.db');
    assert.equal(flag(result.args, '--chain-id'), BASE_ENV.CHAIN_ID);
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.ok(!result.args.includes('--oa-org-url'));
});

test('server forwards explicit settlement and native price overrides', async () => {
    const result = await launch('server', {
        set: {
            ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS: '7200',
            ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS: '3600',
            ZKAPI_NATIVE_PRICE_FEED_DECIMALS: '18',
            LEASE_TTL_SECONDS: '600',
            SETTLEMENT_GRACE_SECONDS: '10',
            OA_ORG_URL: 'https://org.example',
        },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--openrouter-settlement-deadline-seconds'), '7200');
    assert.equal(flag(result.args, '--native-price-max-age-seconds'), '3600');
    assert.equal(flag(result.args, '--native-price-feed-decimals'), '18');
    assert.equal(flag(result.args, '--openrouter-lease-ttl-seconds'), '600');
    assert.equal(flag(result.args, '--openrouter-settlement-grace-seconds'), '10');
    assert.equal(flag(result.args, '--oa-org-url'), 'https://org.example');
});

test('server leaves seed validation to zkapi serverd and keeps seeds out of argv', async () => {
    // The removed shell guard compared strings and missed 0X1, 0x0002 and every
    // other spelling. serverd now refuses development keys by derived public key.
    for (const [state, clear] of [['0x1', '0x2'], ['0X1', '0x0002'], ['0x5eed01', '0x5eed02']]) {
        const result = await launch('server', { set: { ZKAPI_STATE_SEED: state, ZKAPI_CLEAR_SEED: clear } });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.received.ZKAPI_STATE_SEED, state);
        assert.equal(result.received.ZKAPI_CLEAR_SEED, clear);
        assert.ok(!result.args.includes('--state-seed'));
        assert.ok(!result.args.includes('--clear-seed'));
        assert.ok(!result.args.includes(state) && !result.args.includes(clear));
        assert.ok(!result.stderr.includes('Refusing the development signing seeds'));
    }
});

test('a refusal by zkapi serverd propagates its exit status and message', async () => {
    const refusal = 'refusing to start: invalid signing seeds (ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED)';
    const result = await launch('server', { exitCode: 3, refusal });
    assert.equal(result.status, 3);
    assert.ok(result.stderr.includes(refusal));
    assert.ok(!result.stderr.includes('Missing required environment variable'));
});

test('server requires both signing seeds and starts nothing without them', async () => {
    for (const name of ['ZKAPI_STATE_SEED', 'ZKAPI_CLEAR_SEED']) {
        for (const options of [{ unset: [name] }, { set: { [name]: '' } }]) {
            const result = await launch('server', options);
            assert.equal(result.status, 1);
            assert.equal(result.stderr.trim(), `Missing required environment variable: ${name}`);
            assert.deepEqual(result.args, []);
        }
    }
});

test('server passes clearance, root and lease-ceiling settings only through the environment', async () => {
    const flags = ['--allow-legacy-clearance', '--clearance-root-window-seconds',
        '--root-max-staleness-seconds', '--request-limit-max-usd-micros'];
    const defaults = await launch('server');
    assert.equal(defaults.status, 0, defaults.stderr);
    for (const name of flags) assert.ok(!defaults.args.includes(name), name);
    assert.equal(defaults.received.ZKAPI_ALLOW_LEGACY_CLEARANCE, undefined);

    const settings = {
        // serverd refuses this one on the concession circuit; the launcher
        // still leaves the decision to it.
        ZKAPI_ALLOW_LEGACY_CLEARANCE: 'true',
        ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS: '600',
        ZKAPI_ROOT_MAX_STALENESS_SECONDS: '30',
        ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS: '6000000',
    };
    const configured = await launch('server', { set: settings });
    assert.equal(configured.status, 0, configured.stderr);
    for (const name of flags) assert.ok(!configured.args.includes(name), name);
    for (const [name, value] of Object.entries(settings)) assert.equal(configured.received[name], value);
});

test('the deployment env example sets the canary lease ceiling and no legacy clearance', async () => {
    const example = await readFile(resolve('docker/aws/deployment.env.example'), 'utf8');
    assert.match(example, /^CIRCUIT_ID=zkapi-v2-concession-v1$/m);
    assert.match(example, /^ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS=6000000$/m);
    assert.doesNotMatch(example, /^ZKAPI_ALLOW_LEGACY_CLEARANCE=/m);
    assert.doesNotMatch(example, /LEGACY_CLEARANCE_MAX_PER_MINUTE/);
});

for (const role of ['server', 'challenger']) {
    test(`${role} reads the mounted deployment manifest, or an explicit one`, async () => {
        const defaults = await launch(role);
        assert.equal(defaults.status, 0, defaults.stderr);
        assert.equal(flag(defaults.args, '--deployment'), '/srv/zkapi/deployment.json');
        const explicit = await launch(role, { set: { ZKAPI_DEPLOYMENT_MANIFEST: '/custom/deployment.json' } });
        assert.equal(flag(explicit.args, '--deployment'), '/custom/deployment.json');
    });
}

// The documented parameter sets (concession-exit spec, section 10.4).
const PARAMETER_SETS = [
    { name: 'Mainnet', challengePeriod: 172_800, deadline: 21_600, raiseLead: 21_600, window: 21_905 },
    { name: 'Sepolia', challengePeriod: 43_200, deadline: 14_400, raiseLead: 21_600, window: 14_705 },
    { name: 'drill', challengePeriod: 7_200, deadline: 1_800, raiseLead: 1_800, window: 2_105 },
];

test('challenger passes the server settlement window for its startup timing checks', async () => {
    const defaults = await launch('challenger');
    assert.equal(defaults.status, 0, defaults.stderr);
    assert.equal(flag(defaults.args, '--settlement-window-seconds'), '21905');
    for (const set of PARAMETER_SETS) {
        const result = await launch('challenger', { set: { ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS: String(set.deadline) } });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(flag(result.args, '--settlement-window-seconds'), String(set.window), set.name);
    }
    const explicit = await launch('challenger', { set: { LEASE_TTL_SECONDS: '600', SETTLEMENT_GRACE_SECONDS: '10', ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS: '1800' } });
    assert.equal(flag(explicit.args, '--settlement-window-seconds'), '2410');
    // An empty value means the default, as for the server.
    const empty = await launch('challenger', { set: { LEASE_TTL_SECONDS: '', SETTLEMENT_GRACE_SECONDS: '' } });
    assert.equal(flag(empty.args, '--settlement-window-seconds'), '21905');
});

test('challenger refuses a settlement setting that is not a number of seconds', async () => {
    for (const [name, value] of [
        ['LEASE_TTL_SECONDS', '5m'],
        ['SETTLEMENT_GRACE_SECONDS', '-5'],
        ['ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS', '021600'],
        ['ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS', '1e4'],
        ['ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS', '9999999999'],
    ]) {
        const result = await launch('challenger', { set: { [name]: value } });
        assert.equal(result.status, 1, `${name}=${value}`);
        assert.equal(result.stderr.trim(), `${name} must be a decimal number of seconds`);
        assert.deepEqual(result.args, []);
    }
});

test('challenger takes its raise and retirement settings from the environment', async () => {
    const set = { ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS: '1800', ZKAPI_CHALLENGE_RAISE_MIN_UNITS: '1000', ZKAPI_CHALLENGE_RETIRE_ON_MISS: 'false' };
    const result = await launch('challenger', { set });
    assert.equal(result.status, 0, result.stderr);
    for (const name of ['--raise-lead-seconds', '--raise-min-units', '--retire-on-miss']) {
        assert.ok(!result.args.includes(name), name);
    }
    assert.deepEqual(
        Object.fromEntries(Object.keys(set).map((name) => [name, result.received[name]])),
        set,
    );
});

test('the deployment env example passes the Sepolia startup timing checks', async () => {
    // Sepolia (its CHAIN_ID) with challengePeriod 43,200: the server's G5 check
    // and the challenger's raise check, with the 2-second settlement poll.
    const example = await readFile(resolve('docker/aws/deployment.env.example'), 'utf8');
    const value = (name) => Number(new RegExp(`^${name}=([0-9]+)$`, 'm').exec(example)?.[1]);
    assert.equal(value('CHAIN_ID'), 11155111);
    const sepolia = PARAMETER_SETS[1];
    const window = value('LEASE_TTL_SECONDS') + value('SETTLEMENT_GRACE_SECONDS') + value('ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS');
    assert.equal(window, sepolia.window);
    assert.equal(value('ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS'), sepolia.raiseLead);
    for (const set of PARAMETER_SETS) {
        const window = 300 + 5 + set.deadline;
        assert.equal(window, set.window, set.name);
        assert.ok(window + 2 * 2 + 600 <= set.challengePeriod / 2, `${set.name} G5`);
        assert.ok(window + set.raiseLead + 4 * 2 + 1200 <= set.challengePeriod, `${set.name} raise`);
    }
    // The Mainnet settlement deadline does not fit Sepolia's period.
    assert.ok(300 + 5 + 21_600 + 2 * 2 + 600 > sepolia.challengePeriod / 2);
});

test('db-init binds the server database to the manifest and the proof setup', async () => {
    for (const override of [null, '/custom/proofs']) {
        const result = await launch('db-init', { set: override ? { ZKAPI_PROOF_SETUP_DIR: override } : {} });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(flag(result.args, '--proof-setup-dir'), override || '/srv/zkapi/protocol/setup/v2-concession');
        const db = result.args.indexOf('db');
        assert.deepEqual(result.args.slice(db, db + 2), ['db', 'init']);
        assert.equal(flag(result.args, '--deployment'), '/srv/zkapi/deployment.json');
        assert.equal(flag(result.args, '--db'), '/data/server.db');
        // No seeds, keys or RPC are needed or passed.
        assert.ok(!result.args.some(arg => arg.includes('seed')));
        assert.equal(result.received.ZKAPI_STATE_SEED, 'test-state-seed');
    }
});

test('every role refuses another circuit before starting anything', async () => {
    for (const role of ['server', 'db-init', 'indexer', 'challenger']) {
        const result = await launch(role, { set: { CIRCUIT_ID: 'zkapi-v2-note-bound-v1' } });
        assert.equal(result.status, 1, role);
        assert.equal(result.stderr.trim(), 'This image requires the zkapi-v2-concession-v1 circuit and a fresh vault');
        assert.deepEqual(result.args, []);
    }
});

test('indexer launches with the deployment chain, confirmations and head-age limit', async () => {
    const result = await launch('indexer');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--listen'), '0.0.0.0:3001');
    assert.equal(flag(result.args, '--rpc-url'), BASE_ENV.RPC_URL);
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.equal(flag(result.args, '--from-block'), '1');
    assert.equal(flag(result.args, '--chain-id'), '11155111');
    assert.equal(flag(result.args, '--confirmations'), '12');
    assert.equal(flag(result.args, '--max-head-age-secs'), '180');
    assert.equal(flag(result.args, '--cursor-path'), '/data/indexer.cursor');
    assert.ok(!result.args.includes('--resync'));
});

test('indexer forwards explicit confirmation and head-age overrides', async () => {
    const result = await launch('indexer', { set: { INDEXER_CONFIRMATIONS: '3', INDEXER_MAX_HEAD_AGE_SECS: '0' } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--confirmations'), '3');
    assert.equal(flag(result.args, '--max-head-age-secs'), '0');
});

test('indexer requires its RPC endpoint', async () => {
    for (const options of [{ unset: ['RPC_URL'] }, { set: { RPC_URL: '' } }]) {
        const result = await launch('indexer', options);
        assert.equal(result.status, 1);
        assert.equal(result.stderr.trim(), 'Missing required environment variable: RPC_URL');
        assert.deepEqual(result.args, []);
    }
});

test('challenger requires its signer RPC, sender and both fee caps', async () => {
    for (const name of [
        'ZKAPI_CHALLENGE_RPC_URL',
        'ZKAPI_CHALLENGE_SENDER',
        'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI',
        'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI',
    ]) {
        for (const options of [{ unset: [name] }, { set: { [name]: '' } }]) {
            const result = await launch('challenger', options);
            assert.equal(result.status, 1);
            assert.equal(result.stderr.trim(), `Missing required environment variable: ${name}`);
            assert.deepEqual(result.args, []);
        }
    }
});

test('challenger serves status on loopback and takes its fees from the environment', async () => {
    const result = await launch('challenger', { set: { ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '2000000000' } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--status-listen'), '127.0.0.1:3002');
    assert.equal(flag(result.args, '--indexer-url'), 'http://indexer:3001');
    assert.equal(flag(result.args, '--chain-id'), '11155111');
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.equal(flag(result.args, '--from-block'), '1');
    assert.equal(flag(result.args, '--confirmations'), '2');
    assert.equal(flag(result.args, '--db-path'), '/data/server.db');
    assert.equal(flag(result.args, '--checkpoint'), '/data/challenges.json');
    assert.equal(flag(result.args, '--deployment'), '/srv/zkapi/deployment.json');
    for (const name of ['--max-fee-per-gas-wei', '--max-priority-fee-per-gas-wei', '--priority-fee-per-gas-wei', '--rpc-url', '--sender']) {
        assert.ok(!result.args.includes(name), name);
    }
    assert.equal(result.received.ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI, '100000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI, '10000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI, '2000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_RPC_URL, 'http://signer:8547');
});

test('challenger receives the shared transaction fee cap from deployment.env through its environment', async () => {
    // The signer reads its own copy from signer.env; unset means the daemon's 1 ETH default.
    const example = await readFile(resolve('docker/aws/deployment.env.example'), 'utf8');
    const cap = /^ZKAPI_CHALLENGE_TX_FEE_CAP_WEI=([1-9][0-9]*)$/m.exec(example)?.[1];
    assert.equal(cap, '1000000000000000000');
    for (const value of [undefined, cap, '2300000000000000000']) {
        const result = await launch('challenger', { set: value === undefined ? {} : { ZKAPI_CHALLENGE_TX_FEE_CAP_WEI: value } });
        assert.equal(result.status, 0, result.stderr);
        assert.ok(!result.args.includes('--tx-fee-cap-wei'));
        assert.equal(result.received.ZKAPI_CHALLENGE_TX_FEE_CAP_WEI, value);
    }
});

test('unknown roles print the usage and exit 2', async () => {
    const result = await launch('indexer-resync');
    assert.equal(result.status, 2);
    assert.equal(result.stderr.trim(), 'Usage: zkapi-run server|db-init|indexer|challenger');
    assert.deepEqual(result.args, []);
});
