// The exit kit (E7), the deployment pins checked through a wallet provider
// before deposits (§6.5), the canary caps, and the SDK's Keccak-256.
import assert from 'node:assert/strict';
import test from 'node:test';
import { keccak256Hex } from './helpers/request-archive-harness.mjs';
import {
    EXIT_KIT_FORMAT, EXIT_KIT_PBKDF2_ITERATIONS, buildExitKitPayload, openExitKit, sealExitKit
} from '../services/zkapiExitKit.mjs';
import {
    CONCESSION_CIRCUIT_ID_HASH, canaryLimits, canaryRefusal, deploymentMismatchError, deploymentPins, verifyDeployment
} from '../services/zkapiDeploymentCheck.mjs';
import { codehash, hexBytes, keccak256 } from '../services/zkapiKeccak.mjs';
import { ABI } from '../wallet.js';

const STATE = {
    protocol_version: 2, chain_id: 11155111, contract_address: `0x${'22'.repeat(20)}`, note_id: 7,
    secret_s: '0x1234', deposit_amount: 5_000_000, expiry_ts: 2_000_000_000, current_balance: 4_900_000,
    balance_blinding: '0xabc', current_commitment_x: '0x1', current_commitment_y: '0x2', current_anchor: '0x99',
    prev_anchor: '0x1', is_genesis: false, state_signature: { r_x: '0x3', r_y: '0x4', s: '0x5' }, bound_at_state: 300
};

test('Keccak-256 matches the independent test implementation and known vectors', () => {
    assert.equal(keccak256(''), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    assert.equal(keccak256('zkapi-v2-concession-v1'), CONCESSION_CIRCUIT_ID_HASH);
    for (const text of ['a', 'NoteDeposited(uint32,bytes32,uint128,uint64,uint256)', 'x'.repeat(135), 'y'.repeat(136), 'z'.repeat(300)]) {
        assert.equal(keccak256(text), keccak256Hex(text), `${text.length} bytes`);
    }
    assert.equal(codehash('0x6001'), keccak256(Uint8Array.from([0x60, 0x01])));
    assert.throws(() => hexBytes('0x123'), /Invalid hex/);
});

test('an exit kit round-trips under its passphrase and nothing else', async () => {
    // Hosts and the companion's parity tests open kits through the package's
    // ./exit-kit export.
    const { readFile } = await import('node:fs/promises');
    const packageJson = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
    const exported = await import(new URL(`../.${packageJson.exports['./exit-kit']}`, import.meta.url).href);
    assert.equal(exported.openExitKit, openExitKit);
    const trusted = { deployment_id: 'v2c', contract_address: STATE.contract_address, vault_runtime_codehash: `0x${'aa'.repeat(32)}` };
    const merklePath = { active_root: '0x77', siblings: Array.from({ length: 32 }, (_, index) => `0x${index.toString(16)}`) };
    const payload = buildExitKitPayload({ trustedDeployment: trusted, state: { ...STATE, extra: 'not copied' }, stateSeq: 4,
        exportedAt: 1_800_000_000, merklePath });
    assert.equal(payload.format, EXIT_KIT_FORMAT);
    assert.deepEqual(payload.trusted_deployment, trusted);
    // s, note_id, D, expiry, B, r, τ, τ_prev and σ, plus the commitment.
    for (const field of ['secret_s', 'note_id', 'deposit_amount', 'expiry_ts', 'current_balance', 'balance_blinding',
        'current_anchor', 'prev_anchor', 'state_signature', 'current_commitment_x']) {
        assert.deepEqual(payload.note[field], STATE[field], field);
    }
    assert.equal(payload.note.extra, undefined);
    assert.equal(payload.bound_at_state, '300');
    assert.equal(payload.state_seq, 4);
    assert.deepEqual(payload.merkle_path, merklePath);

    const sealed = await sealExitKit(payload, 'correct horse battery');
    assert.equal(sealed.format, EXIT_KIT_FORMAT);
    assert.deepEqual(sealed.kdf.name, 'PBKDF2');
    assert.equal(sealed.kdf.hash, 'SHA-256');
    assert.equal(sealed.kdf.iterations, EXIT_KIT_PBKDF2_ITERATIONS);
    assert.equal(EXIT_KIT_PBKDF2_ITERATIONS, 600_000);
    assert.equal(Buffer.from(sealed.kdf.salt, 'base64').length, 16);
    assert.equal(Buffer.from(sealed.cipher.iv, 'base64').length, 12);
    assert.equal(sealed.cipher.name, 'AES-256-GCM');
    // Nothing of the note is readable in the envelope.
    assert.ok(!JSON.stringify(sealed).includes('0x1234'));
    assert.deepEqual(await openExitKit(JSON.stringify(sealed), 'correct horse battery'), payload);
    await assert.rejects(openExitKit(sealed, 'wrong horse battery'), { code: 'exit_kit_passphrase' });
    const ciphertext = Buffer.from(sealed.ciphertext, 'base64');
    ciphertext[0] ^= 1;
    await assert.rejects(openExitKit({ ...sealed, ciphertext: ciphertext.toString('base64') }, 'correct horse battery'),
        { code: 'exit_kit_passphrase' });
    await assert.rejects(openExitKit({ ...sealed, format: 'other' }, 'correct horse battery'), { code: 'exit_kit_invalid' });
    await assert.rejects(openExitKit({ ...sealed, kdf: { ...sealed.kdf, iterations: 1_000 } }, 'correct horse battery'),
        { code: 'exit_kit_invalid' });
    await assert.rejects(sealExitKit(payload, 'short'), { code: 'exit_kit_passphrase_weak' });
    assert.throws(() => buildExitKitPayload({ trustedDeployment: trusted, state: null }), { code: 'exit_kit_invalid' });
    // Two kits of the same payload use fresh salts and nonces.
    const again = await sealExitKit(payload, 'correct horse battery', { iterations: 100_000 });
    assert.notEqual(again.kdf.salt, sealed.kdf.salt);
    assert.notEqual(again.cipher.iv, sealed.cipher.iv);
});

const VAULT = `0x${'22'.repeat(20)}`;
const ADAPTER = `0x${'33'.repeat(20)}`;
const POSEIDON = `0x${'44'.repeat(20)}`;
const CODE = { [VAULT]: '0x6080604052', [ADAPTER]: '0x60806040', [POSEIDON]: '0x6001600201' };
const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;

function trusted(overrides = {}) {
    return {
        deployment_status: 'deployed', contract_address: VAULT, proof_adapter_address: ADAPTER, poseidon_library_address: POSEIDON,
        vault_runtime_codehash: codehash(CODE[VAULT]),
        adapter_runtime_codehash: codehash(CODE[ADAPTER]), poseidon_runtime_codehash: codehash(CODE[POSEIDON]),
        request_vk_keccak256: `0x${'4d'.repeat(32)}`, withdrawal_vk_keccak256: `0x${'29'.repeat(32)}`,
        challenge_period: 172_800, note_ttl: 2_592_000, max_pause_duration: 3_888_000,
        state_signing_key: { x: '0x111', y: '0x112' }, clearance_signing_key: { x: '0x113', y: '0x114' },
        ...overrides
    };
}

/** A chain whose vault and adapter answer the pinned getters, with overrides. */
function chain({ code = CODE, getters = {}, chainId = 1 } = {}) {
    const values = {
        [`${VAULT}:${ABI.proofAdapter}`]: BigInt(ADAPTER), [`${VAULT}:${ABI.stateSigningKeyX}`]: 0x111n,
        [`${VAULT}:${ABI.stateSigningKeyY}`]: 0x112n, [`${VAULT}:${ABI.clearanceSigningKeyX}`]: 0x113n,
        [`${VAULT}:${ABI.clearanceSigningKeyY}`]: 0x114n, [`${VAULT}:${ABI.challengePeriod}`]: 172_800n,
        [`${VAULT}:${ABI.noteTtl}`]: 2_592_000n, [`${VAULT}:${ABI.maxPauseDuration}`]: 3_888_000n,
        [`${VAULT}:${ABI.CONCESSION_ESCAPE_VERSION}`]: 1n, [`${VAULT}:${ABI.ROOT_HISTORY_WINDOW}`]: 86_400n,
        [`${ADAPTER}:${ABI.CIRCUIT_ID_HASH}`]: BigInt(CONCESSION_CIRCUIT_ID_HASH),
        [`${ADAPTER}:${ABI.REQUEST_VK_HASH}`]: BigInt(`0x${'4d'.repeat(32)}`),
        [`${ADAPTER}:${ABI.WITHDRAWAL_VK_HASH}`]: BigInt(`0x${'29'.repeat(32)}`),
        ...getters
    };
    const calls = [];
    const request = async ({ method, params }) => {
        calls.push(method);
        if (method === 'eth_chainId') return `0x${chainId.toString(16)}`;
        if (method === 'eth_getCode') return code[params[0]] ?? '0x';
        if (method === 'eth_call') {
            const key = `${params[0].to}:${params[0].data.slice(2)}`;
            if (!(key in values)) throw Object.assign(new Error('execution reverted'), { code: 3 });
            return values[key] === null ? '0x' : word(values[key]);
        }
        throw new Error(`unexpected ${method}`);
    };
    return { request, calls };
}

test('the deployment pins are checked through a provider: codehashes, adapter, keys, periods and VK hashes', async () => {
    const ok = await verifyDeployment({ request: chain().request, trusted: trusted(), chainId: 1, source: 'wallet' });
    assert.deepEqual(ok, { ok: true, source: 'wallet', mismatches: [] });
    // Each pin is checked on its own.
    const cases = [
        [{ code: { ...CODE, [VAULT]: '0x6080604053' } }, 'vault_runtime_codehash'],
        [{ code: { ...CODE, [ADAPTER]: '0x' } }, 'adapter_runtime_codehash'],
        [{ code: { ...CODE, [POSEIDON]: '0x00' } }, 'poseidon_runtime_codehash'],
        [{ getters: { [`${VAULT}:${ABI.proofAdapter}`]: 0x1n } }, 'proofAdapter'],
        [{ getters: { [`${VAULT}:${ABI.stateSigningKeyY}`]: 0x1n } }, 'stateSigningKeyY'],
        [{ getters: { [`${VAULT}:${ABI.clearanceSigningKeyX}`]: 0x1n } }, 'clearanceSigningKeyX'],
        [{ getters: { [`${VAULT}:${ABI.challengePeriod}`]: 7_200n } }, 'challengePeriod'],
        [{ getters: { [`${VAULT}:${ABI.noteTtl}`]: 1n } }, 'noteTtl'],
        [{ getters: { [`${VAULT}:${ABI.maxPauseDuration}`]: 1n } }, 'maxPauseDuration'],
        [{ getters: { [`${VAULT}:${ABI.CONCESSION_ESCAPE_VERSION}`]: 0n } }, 'CONCESSION_ESCAPE_VERSION'],
        [{ getters: { [`${VAULT}:${ABI.ROOT_HISTORY_WINDOW}`]: 3_600n } }, 'ROOT_HISTORY_WINDOW'],
        [{ getters: { [`${ADAPTER}:${ABI.CIRCUIT_ID_HASH}`]: 1n } }, 'CIRCUIT_ID_HASH'],
        [{ getters: { [`${ADAPTER}:${ABI.REQUEST_VK_HASH}`]: 1n } }, 'REQUEST_VK_HASH'],
        [{ getters: { [`${ADAPTER}:${ABI.WITHDRAWAL_VK_HASH}`]: null } }, 'WITHDRAWAL_VK_HASH']
    ];
    for (const [overrides, field] of cases) {
        const result = await verifyDeployment({ request: chain(overrides).request, trusted: trusted(), chainId: 1 });
        assert.equal(result.ok, false, field);
        assert.deepEqual(result.mismatches.map(entry => entry.field), [field], field);
    }
    // A getter the vault lacks (a revert) is a mismatch, never a pass.
    const legacy = chain();
    const reverting = async args => args.params?.[0]?.data === `0x${ABI.CONCESSION_ESCAPE_VERSION}`
        ? Promise.reject(Object.assign(new Error('execution reverted'), { code: 3 })) : legacy.request(args);
    assert.deepEqual((await verifyDeployment({ request: reverting, trusted: trusted(), chainId: 1 })).mismatches
        .map(entry => entry.field), ['CONCESSION_ESCAPE_VERSION']);
    // Another chain stops the check at once.
    const wrong = await verifyDeployment({ request: chain({ chainId: 5 }).request, trusted: trusted(), chainId: 1 });
    assert.deepEqual(wrong.mismatches.map(entry => entry.field), ['chain_id']);
    const error = deploymentMismatchError([wrong, ok]);
    assert.equal(error.code, 'deployment_mismatch');
    assert.match(error.message, /rpc: chain_id/);
    // A placeholder or incomplete profile cannot be verified, so it takes no deposit.
    assert.throws(() => deploymentPins(trusted({ deployment_status: 'not_deployed' })), { code: 'deployment_unverifiable' });
    assert.throws(() => deploymentPins(trusted({ vault_runtime_codehash: null })), error =>
        error.code === 'deployment_unverifiable' && error.data.missing.includes('vault_runtime_codehash'));
});

test('canary caps bound each deposit and the vault total while they apply', () => {
    const profile = { canary: { per_note_max_wei: '250000000000000000', aggregate_max_wei: '25000000000000000000', until: 2_000 } };
    const limits = canaryLimits(profile, 1_000);
    assert.deepEqual(limits, { perNoteMaxWei: 250_000_000_000_000_000n, aggregateMaxWei: 25_000_000_000_000_000_000n, until: 2_000 });
    assert.equal(canaryLimits(profile, 2_000), null, 'the canary ends at until');
    assert.equal(canaryLimits({ canary: { ...profile.canary, until: null } }, 9_999_999_999).until, null);
    assert.equal(canaryLimits({}, 1), null);
    assert.equal(canaryRefusal({ limits, depositWei: 250_000_000_000_000_000n, vaultBalanceWei: 0n }), null);
    assert.equal(canaryRefusal({ limits, depositWei: 250_000_000_000_000_001n, vaultBalanceWei: 0n }).data.cap, 'per_note');
    assert.equal(canaryRefusal({ limits, depositWei: 1n, vaultBalanceWei: 25_000_000_000_000_000_000n }).data.cap, 'aggregate');
    assert.equal(canaryRefusal({ limits, depositWei: 1n, vaultBalanceWei: null }).code, 'canary_cap_unverified');
    assert.throws(() => canaryLimits({ canary: { per_note_max_wei: '1.5' } }, 1), { code: 'canary_invalid' });
});

// ---- gasless withdrawals: the pins of design §4.3 and the checks of §4.4 ----

test('the gasless pins and the deployment check of the EntryPoint, SenderCreator, paymaster and factory', async () => {
    const { ENTRY_POINT_RUNTIME, FAKE_CODE, SENDER_CREATOR_RUNTIME, VECTORS, create2TransitAccount, gaslessProfileFromVectors } =
        await import('./helpers/fake-bundler.mjs');
    const { GASLESS_SAMPLE_OWNER, GASLESS_SAMPLE_PAYEE, gaslessDeploymentError, gaslessPins, verifyGaslessDeployment } =
        await import('../services/zkapiDeploymentCheck.mjs');
    const { GASLESS_ABI } = await import('../wallet.js');
    const gasless = gaslessProfileFromVectors({ spelling: 'profile' });
    const profile = trusted({ gasless, native_asset_wei_per_unit: '1000000000' });
    const pins = gaslessPins(profile);
    assert.equal(pins.paymaster, VECTORS.paymaster);
    assert.equal(gaslessPins(trusted()), null, 'a profile without the object');
    assert.equal(gaslessPins(trusted({ gasless: null })), null);
    const policyWords = (() => {
        const gp = gasless.gas_policy;
        return [...gp.call_floor, ...gp.call_cap, gp.postop_floor, gp.postop_cap, gp.verification_floor, gp.verification_floor_init,
            gp.verification_cap, gp.pvg_floor, gp.pvg_cap, gp.pm_verification_floor, gp.pm_verification_cap, gp.postop_base_gas,
            gp.postop_escape_gas, gp.postop_finalize_extra_gas, gp.postop_escape_forward_gas, gp.eoa_push_gas, gp.new_account_gas,
            gp.payout_push_gas, gp.credit_gas, gp.account_call_overhead_gas, gp.account_call_overhead_escape_gas, gp.margin_gas,
            gp.finalize_reserve_gas, gp.max_attempts].map(value => BigInt(value).toString(16).padStart(64, '0')).join('');
    })();
    const sample = create2TransitAccount({ factory: VECTORS.factory, creationCode: VECTORS.account_creation_code, entryPoint: VECTORS.entry_point,
        vault: VAULT, paymaster: VECTORS.paymaster, owner: GASLESS_SAMPLE_OWNER, payee: GASLESS_SAMPLE_PAYEE });
    const low = value => String(value).toLowerCase();
    const addressWord = value => word(BigInt(value));
    /** The gasless contracts answering their pinned getters, with overrides. */
    function gaslessChain({ code = {}, getters = {}, chainId = 1 } = {}) {
        const codes = {
            [low(VECTORS.entry_point)]: ENTRY_POINT_RUNTIME, [low(VECTORS.sender_creator)]: SENDER_CREATOR_RUNTIME,
            [low(VECTORS.paymaster)]: FAKE_CODE.paymaster, [low(VECTORS.factory)]: FAKE_CODE.factory,
            [low(VECTORS.implementation)]: FAKE_CODE.implementation, ...code
        };
        const values = {
            [`${low(VECTORS.paymaster)}:${GASLESS_ABI.vault}`]: addressWord(VAULT),
            [`${low(VECTORS.paymaster)}:${GASLESS_ABI.factory}`]: addressWord(VECTORS.factory),
            [`${low(VECTORS.paymaster)}:${GASLESS_ABI.entryPoint}`]: addressWord(VECTORS.entry_point),
            [`${low(VECTORS.paymaster)}:${GASLESS_ABI.WEI_PER_UNIT}`]: word(1_000_000_000n),
            [`${low(VECTORS.paymaster)}:${GASLESS_ABI.gasPolicy}`]: `0x${policyWords}`,
            [`${low(VECTORS.factory)}:${GASLESS_ABI.paymaster}`]: addressWord(VECTORS.paymaster),
            [`${low(VECTORS.factory)}:${GASLESS_ABI.accountCreationCodeHash}`]: low(VECTORS.account_creation_code_keccak256),
            [`${low(VECTORS.factory)}:${GASLESS_ABI.getAddress}`]: addressWord(sample),
            ...getters
        };
        const calls = [];
        const request = async ({ method, params }) => {
            calls.push(method);
            if (method === 'eth_chainId') return `0x${chainId.toString(16)}`;
            if (method === 'eth_getCode') return codes[low(params[0])] ?? '0x';
            if (method === 'eth_call') {
                const key = `${low(params[0].to)}:${params[0].data.slice(2, 10)}`;
                if (!(key in values)) throw Object.assign(new Error('execution reverted'), { code: 3 });
                return values[key];
            }
            throw new Error(`unexpected ${method}`);
        };
        return { request, calls };
    }
    const ok = await verifyGaslessDeployment({ request: gaslessChain().request, trusted: profile, chainId: 1, source: 'read_rpc' });
    assert.deepEqual(ok, { ok: true, source: 'read_rpc', mismatches: [] });
    // The vendored canonical runtimes hash to the pins (identical on every chain).
    assert.equal(codehash(ENTRY_POINT_RUNTIME), VECTORS.entry_point_codehash);
    assert.equal(codehash(SENDER_CREATOR_RUNTIME), VECTORS.sender_creator_codehash);
    const cases = [
        [{ code: { [low(VECTORS.entry_point)]: '0x6002' } }, ['entry_point_runtime_codehash']],
        [{ code: { [low(VECTORS.sender_creator)]: '0x' } }, ['sender_creator_runtime_codehash']],
        [{ code: { [low(VECTORS.paymaster)]: '0x6003' } }, ['withdrawal_paymaster_runtime_codehash']],
        [{ code: { [low(VECTORS.factory)]: '0x6004' } }, ['withdrawal_account_factory_runtime_codehash']],
        [{ code: { [low(VECTORS.implementation)]: '0x6005' } }, ['withdrawal_account_implementation_runtime_codehash']],
        [{ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.vault}`]: addressWord(ADAPTER) } }, ['paymaster.vault']],
        [{ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.factory}`]: addressWord(ADAPTER) } }, ['paymaster.factory']],
        [{ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.entryPoint}`]: addressWord(ADAPTER) } }, ['paymaster.entryPoint']],
        [{ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.WEI_PER_UNIT}`]: word(1n) } }, ['paymaster.WEI_PER_UNIT']],
        [{ getters: { [`${low(VECTORS.factory)}:${GASLESS_ABI.paymaster}`]: addressWord(ADAPTER) } }, ['factory.paymaster']],
        [{ getters: { [`${low(VECTORS.factory)}:${GASLESS_ABI.accountCreationCodeHash}`]: `0x${'11'.repeat(32)}` } }, ['factory.accountCreationCodeHash']],
        [{ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.gasPolicy}`]: `0x${policyWords.slice(0, -1)}2` } }, ['paymaster.gasPolicy']],
        [{ getters: { [`${low(VECTORS.factory)}:${GASLESS_ABI.getAddress}`]: addressWord(ADAPTER) } }, ['factory.getAddress']]
    ];
    for (const [overrides, fields] of cases) {
        const result = await verifyGaslessDeployment({ request: gaslessChain(overrides).request, trusted: profile, chainId: 1 });
        assert.equal(result.ok, false, fields.join());
        assert.deepEqual(result.mismatches.map(entry => entry.field), fields, fields.join());
    }
    // A getter the paymaster lacks is a mismatch; another chain stops the check; no pins cannot pass.
    const missing = gaslessChain({ getters: { [`${low(VECTORS.paymaster)}:${GASLESS_ABI.WEI_PER_UNIT}`]: undefined } });
    const lacking = await verifyGaslessDeployment({ request: async args => (args.params?.[0]?.data === `0x${GASLESS_ABI.WEI_PER_UNIT}`
        ? Promise.reject(Object.assign(new Error('execution reverted'), { code: 3 })) : missing.request(args)), trusted: profile, chainId: 1 });
    assert.deepEqual(lacking.mismatches.map(entry => entry.field), ['paymaster.WEI_PER_UNIT']);
    const wrong = await verifyGaslessDeployment({ request: gaslessChain({ chainId: 5 }).request, trusted: profile, chainId: 1 });
    assert.deepEqual(wrong.mismatches.map(entry => entry.field), ['chain_id']);
    const none = await verifyGaslessDeployment({ request: gaslessChain().request, trusted: trusted(), chainId: 1 });
    assert.deepEqual(none.mismatches.map(entry => entry.field), ['gasless']);
    const error = gaslessDeploymentError([wrong]);
    assert.equal(error.code, 'gasless_unavailable');
    assert.equal(error.data.reason, 'gasless_deployment_mismatch');
    assert.match(error.message, /rpc: chain_id/);
    assert.match(error.message, /only be paid from a wallet/);
});
