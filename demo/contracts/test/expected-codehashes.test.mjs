// scripts/expected-codehashes.mjs reads deployment manifests exactly: forge's serializeUint writes
// values up to 2^64 - 1 as bare JSON numbers, which JSON.parse would round above 2^53 - 1. It also
// finalizes Deploy.s.sol's provisional manifest against the chain (here a fake JSON-RPC), with or
// without the gasless-withdrawal paymaster, whose runtime code (and the factory's and the account
// logic's) it derives from the artifacts the same way as the vault's.
// Run with: node --test demo/contracts/test/*.test.mjs (after forge build in protocol/contracts
// for the codehash cases).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    CANONICAL_ENTRY_POINT,
    ENTRY_POINT_V070_CODEHASH,
    GAS_POLICY_SCALARS,
    SENDER_CREATOR,
    SENDER_CREATOR_V070_CODEHASH,
    accountCreationCode,
    auditDeployment,
    createAddress,
    deploymentInputs,
    expectedCodehashes,
    expectedRuntimeCode,
    finalizeDeployment,
    gasPolicyWords,
    gaslessImmutables,
    hexToBytes,
    keccak256,
    parseDeployment,
    vaultImmutables,
} from '../../../scripts/expected-codehashes.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const ARTIFACTS = join(ROOT, 'protocol/contracts/out');
const FIXTURES = join(ROOT, 'protocol/contracts/test/fixtures');

// A Baby-JubJub subgroup point whose y lies between 2^63 and 2^64 and is odd, so no double holds it.
const WIDE_Y_X = '0x05503c73ffee28fcacc324d533595173a637420b99492265bf57c2c286f59cd7';
const WIDE_Y_Y = '9223372036854775867';

function manifest(keyY) {
    return `{
  "poseidonLibrary": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "proofAdapter": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
  "noteTtl": 2592000,
  "challengePeriod": 86400,
  "maxPauseDuration": 604800,
  "requestChargeCap": 1000000,
  "stateSigningKeyX": "${BigInt(WIDE_Y_X)}",
  "stateSigningKeyY": ${keyY},
  "clearanceSigningKeyX": "13",
  "clearanceSigningKeyY": "14"
}`;
}

test('parseDeployment reads integers above 2^53 - 1 exactly', () => {
    const parsed = parseDeployment('{"a": 18446744073709551615, "b": 9007199254740993, "c": 7, "d": "123", "e": [9223372036854775867]}');
    assert.equal(parsed.a, 18446744073709551615n);
    assert.equal(parsed.b, 9007199254740993n);
    assert.equal(parsed.c, 7);
    assert.equal(parsed.d, '123');
    assert.equal(parsed.e[0], 9223372036854775867n);
    assert.equal(parseDeployment(manifest(WIDE_Y_Y)).stateSigningKeyY, BigInt(WIDE_Y_Y));
});

test('parseDeployment refuses numbers that are not exact integers', () => {
    for (const text of ['{"a": 1.5}', '{"a": 1e300}', '{"a": 9007199254740993.0}', '{"a": -9007199254740993}']) {
        assert.throws(() => parseDeployment(text), /is not an exact integer/, text);
    }
});

test('immutables refuse a JavaScript number that was already rounded', () => {
    const inputs = parseDeployment(manifest(`"${WIDE_Y_Y}"`));
    const words = vaultImmutables(inputs);
    assert.equal(words.stateSigningKeyY, BigInt(WIDE_Y_Y).toString(16).padStart(64, '0'));
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: BigInt(WIDE_Y_Y) }), words);
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: `0x${BigInt(WIDE_Y_Y).toString(16)}` }), words);
    // eslint-disable-next-line no-loss-of-precision
    assert.throws(() => vaultImmutables({ ...inputs, stateSigningKeyY: 9223372036854775867 }), /not a safe integer/);
    assert.throws(() => vaultImmutables({ ...inputs, noteTtl: 2 ** 60 }), /not a safe integer/);
});

test('a bare wide key and its decimal string give the same codehashes', { skip: !existsSync(ARTIFACTS) && 'run forge build in protocol/contracts first' }, () => {
    const bare = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(WIDE_Y_Y)));
    const quoted = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(`"${WIDE_Y_Y}"`)));
    assert.deepEqual(bare, quoted);
    // What a rounding parser would have computed differs.
    const rounded = expectedCodehashes(ARTIFACTS, { ...parseDeployment(manifest(`"${WIDE_Y_Y}"`)), stateSigningKeyY: String(Number(WIDE_Y_Y)) });
    assert.notEqual(rounded.vault_runtime_codehash, bare.vault_runtime_codehash);
});

// ------------------------------------------------------------------ finalizing a broadcast

const NO_ARTIFACTS = !existsSync(ARTIFACTS) && 'run forge build in protocol/contracts first';
const POSEIDON = '0x5fbdb2315678afecb367f032d93f642f64180aa3';
const ADAPTER = '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512';
const VAULT = '0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0';
const OWNER = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const TREASURY = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
const TX = { poseidon: `0x${'a1'.repeat(32)}`, adapter: `0x${'a2'.repeat(32)}`, vault: `0x${'a3'.repeat(32)}`, paymaster: `0x${'a4'.repeat(32)}` };
const selector = signature => keccak256(new TextEncoder().encode(signature)).slice(0, 10);
const word = addr => `0x${addr.slice(2).padStart(64, '0')}`;
const words = values => `0x${values.map(value => BigInt(value).toString(16).padStart(64, '0')).join('')}`;

/// Deploy.s.sol's provisional manifest of a broadcast run whose simulation saw head block 5.
function pendingManifest() {
    const inputs = parseDeployment(manifest(`"${WIDE_Y_Y}"`));
    inputs.poseidonLibrary = POSEIDON;
    inputs.proofAdapter = ADAPTER;
    const hashes = expectedCodehashes(ARTIFACTS, inputs);
    return {
        deploymentStatus: 'pending',
        chainId: 31337,
        deployBlockLowerBound: 5,
        vault: VAULT,
        owner: OWNER,
        treasury: TREASURY,
        poseidonLibraryReused: false,
        ...inputs,
        vaultRuntimeCodehash: hashes.vault_runtime_codehash,
        adapterRuntimeCodehash: hashes.adapter_runtime_codehash,
        poseidonRuntimeCodehash: hashes.poseidon_runtime_codehash,
        withdrawalPaymaster: null,
    };
}

/// A chain on which the broadcast of `deployment` landed: the library and adapter in block 6 and
/// the vault in block 7, with head `latest`. forge's log pairs the first two hashes with each
/// other's addresses in `transactions`, as it does for creations mined in one block; its receipts
/// are right.
function chain(deployment, latest = 7) {
    const code = expectedRuntimeCode(ARTIFACTS, deploymentInputs(deployment));
    const state = {
        code: { [POSEIDON]: code.poseidon, [ADAPTER]: code.adapter, [VAULT]: code.vault },
        receipts: {
            [TX.poseidon]: { transactionHash: TX.poseidon, status: '0x1', blockNumber: '0x6', contractAddress: POSEIDON },
            [TX.adapter]: { transactionHash: TX.adapter, status: '0x1', blockNumber: '0x6', contractAddress: ADAPTER },
            [TX.vault]: { transactionHash: TX.vault, status: '0x1', blockNumber: '0x7', contractAddress: VAULT },
        },
        storage: { [selector('owner()')]: word(OWNER), [selector('treasury()')]: word(TREASURY) },
        chainId: '0x7a69',
        latest,
    };
    const log = {
        chain: 31337,
        transactions: [
            { hash: TX.poseidon, transactionType: 'CREATE', contractAddress: ADAPTER },
            { hash: TX.adapter, transactionType: 'CREATE', contractAddress: POSEIDON },
            { hash: TX.vault, transactionType: 'CREATE', contractAddress: VAULT },
        ],
        receipts: Object.values(state.receipts).map(receipt => ({ ...receipt })),
    };
    const rpc = async (method, params) => {
        if (method === 'eth_chainId') return state.chainId;
        if (method === 'eth_blockNumber') return `0x${state.latest.toString(16)}`;
        if (method === 'eth_getCode') return state.code[params[0].toLowerCase()] ?? '0x';
        if (method === 'eth_getTransactionReceipt') return state.receipts[params[0]] ?? null;
        if (method === 'eth_call' && params[0].to === VAULT) return state.storage[params[0].data];
        if (method === 'eth_call' && state.calls) return state.calls(params[0].to.toLowerCase(), params[0].data);
        throw new Error(`unexpected ${method}`);
    };
    return { state, log, rpc };
}

const finalize = (deployment, { log, rpc }, confirmations = 1) =>
    finalizeDeployment({ artifacts: ARTIFACTS, deployment, broadcastLog: log, rpc, confirmations });

test('finalize records the block that created the vault, not the simulated head', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    const { manifest: final, mismatches } = await finalize(deployment, chain(deployment));
    assert.deepEqual(mismatches, []);
    assert.equal(final.deploymentStatus, 'deployed');
    assert.equal(final.deployBlock, 7);
    assert.equal(final.deployBlockLowerBound, 5);
    // Matched through the receipts, not the log's transactions entries.
    assert.deepEqual(final.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter, poseidonLibrary: TX.poseidon });
    assert.equal(final.vaultRuntimeCodehash, deployment.vaultRuntimeCodehash);
    // A reused library has no creation to look for.
    const reused = { ...pendingManifest(), poseidonLibraryReused: true };
    const fake = chain(reused);
    delete fake.state.receipts[TX.poseidon];
    fake.log.receipts = fake.log.receipts.filter(receipt => receipt.transactionHash !== TX.poseidon);
    const { manifest: linked } = await finalize(reused, fake);
    assert.deepEqual(linked.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter });
});

test('finalize takes only the provisional manifest of a broadcast run', { skip: NO_ARTIFACTS }, async () => {
    for (const status of ['simulated', 'deployed', undefined]) {
        const deployment = { ...pendingManifest(), deploymentStatus: status };
        await assert.rejects(finalize(deployment, chain(deployment)), /finalize takes the provisional manifest/, String(status));
    }
});

test('finalize refuses creations that are missing, failed, elsewhere or not on chain', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    const cases = [
        [fake => { fake.log.receipts = fake.log.receipts.filter(receipt => receipt.contractAddress !== VAULT); }, /0 receipts creating the vault/],
        [fake => { fake.log.receipts.push({ ...fake.log.receipts[2] }); }, /2 receipts creating the vault/],
        [fake => { delete fake.state.receipts[TX.vault]; }, /vault creation .* is not on chain/],
        [fake => { fake.state.receipts[TX.adapter].status = '0x0'; }, /proofAdapter creation .* failed on chain/],
        [fake => { fake.state.receipts[TX.poseidon].contractAddress = VAULT; }, /poseidonLibrary creation .* created/],
        [fake => { fake.state.receipts[TX.vault].blockNumber = '0x5'; }, /not after the simulated head 5/],
        [fake => { fake.state.chainId = '0xaa36a7'; }, /RPC serves chain 11155111/],
        [fake => { fake.log.chain = 1; }, /broadcast log is for chain 1/],
    ];
    for (const [corrupt, error] of cases) {
        const fake = chain(deployment);
        corrupt(fake);
        await assert.rejects(finalize(deployment, fake), error);
    }
});

test('finalize waits for confirmations', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    await assert.rejects(finalize(deployment, chain(deployment, 7), 2), /1 confirmations, 2 required/);
    const { manifest: final } = await finalize(deployment, chain(deployment, 8), 2);
    assert.equal(final.deployBlock, 7);
});

test('finalize reports code and storage on chain that are not the manifest\'s, and writes nothing', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    // The vault on chain was deployed with other keys than the manifest records.
    const other = chain({ ...deployment, stateSigningKeyY: String(BigInt(WIDE_Y_Y) + 2n) });
    const { manifest: none, mismatches } = await finalize(deployment, other);
    assert.equal(none, undefined);
    assert.deepEqual(mismatches.map(m => `${m.source}:${m.field}`), ['rpc:vault_runtime_codehash']);
    // The manifest's own codehashes are not the expected ones.
    const recorded = { ...deployment, adapterRuntimeCodehash: `0x${'00'.repeat(32)}` };
    const result = await finalize(recorded, chain(recorded));
    assert.deepEqual(result.mismatches.map(m => `${m.source}:${m.field}`), ['deployment:adapter_runtime_codehash']);
    // Owner and treasury are storage, which the codehash does not cover.
    const fake = chain(deployment);
    fake.state.storage[selector('owner()')] = word(TREASURY);
    fake.state.storage[selector('treasury()')] = word(OWNER);
    const swapped = await finalize(deployment, fake);
    assert.equal(swapped.manifest, undefined);
    assert.deepEqual(swapped.mismatches.map(m => m.field), ['owner', 'treasury']);
});

// ------------------------------------------------------- the gasless-withdrawal paymaster

const PAYMASTER = '0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9';
const FACTORY = '0xd8058efe0198ae9dd7d563e1b4938dcbc86a1f81';
const IMPLEMENTATION = createAddress(FACTORY, 1);
const DEAD = '0x000000000000000000000000000000000000dead';
const ZERO = `0x${'0'.repeat(40)}`;
const fixture = name => readFileSync(join(FIXTURES, name), 'utf8').trim();
const VECTORS = JSON.parse(readFileSync(join(FIXTURES, 'transit-vectors.json'), 'utf8'));
const snake = name => name.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);

/// The manifest's paymasterGasPolicy from the vectors' gas_policy (decimal strings there).
function gasPolicyManifest() {
    const policy = { callFloor: VECTORS.gas_policy.call_floor.map(Number), callCap: VECTORS.gas_policy.call_hard_cap.map(Number) };
    for (const name of GAS_POLICY_SCALARS) policy[name] = Number(VECTORS.gas_policy[snake(name)]);
    return policy;
}

/// A provisional manifest of a broadcast with the paymaster (GASLESS=1), owner == deployer.
function gaslessManifest() {
    const creation = accountCreationCode(IMPLEMENTATION);
    const base = {
        ...pendingManifest(),
        nativeAssetWeiPerUnit: 1_000_000_000,
        entryPoint: CANONICAL_ENTRY_POINT,
        entryPointRuntimeCodehash: ENTRY_POINT_V070_CODEHASH,
        senderCreator: SENDER_CREATOR,
        senderCreatorRuntimeCodehash: SENDER_CREATOR_V070_CODEHASH,
        withdrawalPaymaster: PAYMASTER,
        withdrawalAccountFactory: FACTORY,
        withdrawalAccountImplementation: IMPLEMENTATION,
        accountCreationCode: creation,
        accountCreationCodeKeccak256: keccak256(hexToBytes(creation)),
        paymasterOwner: OWNER,
        paymasterOwnershipTransferPending: false,
        paymasterDeployer: OWNER,
        paymasterFeeKeeper: ZERO,
        paymasterStakeWei: '100000000000000000',
        factoryStakeWei: '100000000000000000',
        paymasterUnstakeDelaySeconds: 86_400,
        paymasterInitialDepositWei: '1000000000000000000',
        paymasterPolicy: { maxSponsoredCostWei: '50000000000000000', flatFeeWei: '0', minEscapeNetWei: '10000000000000000', escapesEnabled: false },
        paymasterFeeCeilings: { maxFeeWei: '100000000000', priorityFeeWei: '3000000000' },
        paymasterGasPolicy: gasPolicyManifest(),
    };
    const hashes = expectedCodehashes(ARTIFACTS, deploymentInputs(base));
    return {
        ...base,
        paymasterRuntimeCodehash: hashes.paymaster_runtime_codehash,
        factoryRuntimeCodehash: hashes.factory_runtime_codehash,
        accountImplementationRuntimeCodehash: hashes.account_implementation_runtime_codehash,
    };
}

/// `chain(deployment)` plus the paymaster's creation (block 7), the canonical runtimes, and the
/// EntryPoint's and the paymaster's answers, every one as the manifest records it.
function gaslessChain(deployment, latest = 7) {
    const fake = chain(deployment, latest);
    const code = expectedRuntimeCode(ARTIFACTS, deploymentInputs(deployment));
    Object.assign(fake.state.code, {
        [PAYMASTER]: code.paymaster,
        [FACTORY]: code.factory,
        [IMPLEMENTATION]: code.implementation,
        [CANONICAL_ENTRY_POINT]: fixture('entrypoint-v0.7.0.runtime.hex'),
        [SENDER_CREATOR]: fixture('sender-creator-v0.7.0.runtime.hex'),
    });
    fake.state.receipts[TX.paymaster] = { transactionHash: TX.paymaster, status: '0x1', blockNumber: '0x7', contractAddress: PAYMASTER };
    fake.log.transactions.push({ hash: TX.paymaster, transactionType: 'CREATE', contractAddress: PAYMASTER });
    fake.log.receipts.push({ ...fake.state.receipts[TX.paymaster] });
    const policy = deployment.paymasterPolicy;
    fake.state.entryPoint = {
        deposit: BigInt(deployment.paymasterInitialDepositWei),
        stakes: {
            [PAYMASTER]: { staked: 1n, stake: BigInt(deployment.paymasterStakeWei), delay: BigInt(deployment.paymasterUnstakeDelaySeconds) },
            [FACTORY]: { staked: 1n, stake: BigInt(deployment.factoryStakeWei), delay: BigInt(deployment.paymasterUnstakeDelaySeconds) },
        },
    };
    fake.state.paymaster = {
        gasPolicy: gasPolicyWords(deployment.paymasterGasPolicy),
        policy: [BigInt(policy.maxSponsoredCostWei), BigInt(policy.flatFeeWei), BigInt(policy.minEscapeNetWei), policy.escapesEnabled ? 1n : 0n, 0n],
        maxFeeCeiling: BigInt(deployment.paymasterFeeCeilings.maxFeeWei),
        priorityFeeCeiling: BigInt(deployment.paymasterFeeCeilings.priorityFeeWei),
        feeKeeper: deployment.paymasterFeeKeeper,
        owner: deployment.paymasterOwner,
        pendingOwner: ZERO,
    };
    fake.state.calls = (to, data) => {
        const method = data.slice(0, 10);
        const argument = `0x${data.slice(-40)}`;
        if (to === CANONICAL_ENTRY_POINT) {
            if (method === selector('balanceOf(address)')) return words([argument === PAYMASTER ? fake.state.entryPoint.deposit : 0n]);
            if (method === selector('getDepositInfo(address)')) {
                const info = fake.state.entryPoint.stakes[argument] ?? { staked: 0n, stake: 0n, delay: 0n };
                return words([argument === PAYMASTER ? fake.state.entryPoint.deposit : 0n, info.staked, info.stake, info.delay, 0n]);
            }
        }
        if (to === PAYMASTER) {
            const p = fake.state.paymaster;
            if (method === selector('gasPolicy()')) return words(p.gasPolicy);
            if (method === selector('policy()')) return words(p.policy);
            if (method === selector('maxFeeCeiling()')) return words([p.maxFeeCeiling]);
            if (method === selector('priorityFeeCeiling()')) return words([p.priorityFeeCeiling]);
            if (method === selector('feeKeeper()')) return word(p.feeKeeper);
            if (method === selector('owner()')) return word(p.owner);
            if (method === selector('pendingOwner()')) return word(p.pendingOwner);
        }
        throw new Error(`unexpected eth_call ${method} at ${to}`);
    };
    return fake;
}

test('the paymaster, factory and account logic runtime code fills exactly their immutables', { skip: NO_ARTIFACTS }, () => {
    const deployment = gaslessManifest();
    const inputs = deploymentInputs(deployment);
    const code = expectedRuntimeCode(ARTIFACTS, inputs);
    const immutables = gaslessImmutables(inputs);
    const contracts = [
        ['ZkApiWithdrawalPaymaster', code.paymaster, immutables.paymaster],
        ['ZkApiWithdrawalAccountFactory', code.factory, immutables.factory],
        ['ZkApiWithdrawalAccount', code.implementation, immutables.implementation],
    ];
    for (const [name, derived, values] of contracts) {
        const art = JSON.parse(readFileSync(join(ARTIFACTS, `${name}.sol`, `${name}.json`), 'utf8'));
        const original = art.deployedBytecode.object.replace(/^0x/, '');
        const body = derived.slice(2);
        assert.equal(body.length, original.length, `${name}: same length`);
        const names = new Map();
        const visit = node => {
            if (Array.isArray(node)) return node.forEach(visit);
            if (!node || typeof node !== 'object') return;
            if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') names.set(String(node.id), node.name);
            for (const value of Object.values(node)) if (value && typeof value === 'object') visit(value);
        };
        visit(art.ast);
        const patched = new Set();
        const references = Object.entries(art.deployedBytecode.immutableReferences);
        assert.equal(references.length, Object.keys(values).length, `${name}: every declared immutable is referenced`);
        for (const [id, refs] of references) {
            const value = values[names.get(id)];
            assert.ok(value, `${name}: ${names.get(id)} is derived`);
            for (const ref of refs) {
                assert.equal(body.slice(2 * ref.start, 2 * (ref.start + ref.length)), value, `${name}: ${names.get(id)} at ${ref.start}`);
                for (let i = ref.start; i < ref.start + ref.length; i++) patched.add(i);
            }
        }
        for (let i = 0; i < original.length / 2; i++) {
            if (!patched.has(i)) assert.equal(body.slice(2 * i, 2 * i + 2), original.slice(2 * i, 2 * i + 2), `${name}: byte ${i} is the artifact's`);
        }
    }
    // The paymaster's immutables are the deployment's pins, in the words the contract stores.
    assert.equal(immutables.paymaster.entryPoint, word(CANONICAL_ENTRY_POINT).slice(2));
    assert.equal(immutables.paymaster.accountCreationCodeHash, deployment.accountCreationCodeKeccak256.slice(2));
    assert.equal(immutables.factory.implementation, word(IMPLEMENTATION).slice(2));
    assert.equal(immutables.implementation.self, word(IMPLEMENTATION).slice(2));
    // The vectors' creation code is the factory's constants around its account logic.
    assert.equal(accountCreationCode(VECTORS.implementation), VECTORS.account_creation_code.toLowerCase());
    assert.equal(keccak256(hexToBytes(VECTORS.account_creation_code)), VECTORS.account_creation_code_keccak256.toLowerCase());
    assert.equal(createAddress(VECTORS.factory, 1), VECTORS.implementation.toLowerCase());
});

test('the gasless fields of a manifest are checked against each other', { skip: NO_ARTIFACTS }, () => {
    const deployment = gaslessManifest();
    const other = createAddress(FACTORY, 2);
    assert.throws(() => expectedCodehashes(ARTIFACTS, deploymentInputs({ ...deployment, withdrawalAccountImplementation: other })), /nonce-1 creation/);
    assert.throws(() => expectedCodehashes(ARTIFACTS, deploymentInputs({ ...deployment, accountCreationCode: accountCreationCode(other) })), /not the factory's creation code/);
    assert.throws(() => expectedCodehashes(ARTIFACTS, deploymentInputs({ ...deployment, accountCreationCodeKeccak256: `0x${'11'.repeat(32)}` })), /not keccak256 of the creation code/);
    assert.throws(() => expectedCodehashes(ARTIFACTS, deploymentInputs({ ...deployment, nativeAssetWeiPerUnit: 2 ** 60 })), /not a safe integer/);
    assert.throws(() => expectedCodehashes(ARTIFACTS, deploymentInputs({ ...deployment, entryPoint: 'not an address' })), /entryPoint: not an address/);
});

test('the canonical runtimes are pinned by the fixtures\' keccak256, and only a paymaster deployment has gasless codehashes', { skip: NO_ARTIFACTS }, () => {
    assert.equal(keccak256(hexToBytes(fixture('entrypoint-v0.7.0.runtime.hex'))), ENTRY_POINT_V070_CODEHASH);
    assert.equal(keccak256(hexToBytes(fixture('sender-creator-v0.7.0.runtime.hex'))), SENDER_CREATOR_V070_CODEHASH);
    assert.equal(ENTRY_POINT_V070_CODEHASH, VECTORS.entry_point_codehash.toLowerCase());
    assert.equal(SENDER_CREATOR_V070_CODEHASH, VECTORS.sender_creator_codehash.toLowerCase());
    assert.equal(createAddress(CANONICAL_ENTRY_POINT, 1), SENDER_CREATOR);
    const plain = expectedCodehashes(ARTIFACTS, deploymentInputs(pendingManifest()));
    assert.deepEqual(Object.keys(plain), ['vault_runtime_codehash', 'adapter_runtime_codehash', 'poseidon_runtime_codehash']);
    const withPaymaster = expectedCodehashes(ARTIFACTS, deploymentInputs(gaslessManifest()));
    assert.deepEqual(Object.keys(withPaymaster), [...Object.keys(plain), 'paymaster_runtime_codehash', 'factory_runtime_codehash',
        'account_implementation_runtime_codehash', 'entry_point_runtime_codehash', 'sender_creator_runtime_codehash']);
    assert.equal(withPaymaster.entry_point_runtime_codehash, ENTRY_POINT_V070_CODEHASH);
    assert.equal(withPaymaster.vault_runtime_codehash, plain.vault_runtime_codehash);
});

test('finalize records the paymaster creation and checks its deposit, stakes, policies and owner', { skip: NO_ARTIFACTS }, async () => {
    const deployment = gaslessManifest();
    const { manifest: final, mismatches, expected } = await finalize(deployment, gaslessChain(deployment));
    assert.deepEqual(mismatches, []);
    assert.equal(final.deploymentStatus, 'deployed');
    assert.equal(final.deployBlock, 7);
    assert.deepEqual(final.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter, poseidonLibrary: TX.poseidon, withdrawalPaymaster: TX.paymaster });
    assert.equal(expected.paymaster_runtime_codehash, deployment.paymasterRuntimeCodehash);
    assert.equal(final.withdrawalPaymaster, PAYMASTER);
    // A larger deposit and stake than recorded are fine (anyone may add to them).
    const topped = gaslessChain(deployment);
    topped.state.entryPoint.deposit *= 2n;
    topped.state.entryPoint.stakes[FACTORY].stake *= 2n;
    assert.deepEqual((await finalize(deployment, topped)).mismatches, []);
    // A nominated owner: the deployer owns the paymaster until PAYMASTER_OWNER accepts; both states pass.
    const handover = { ...deployment, paymasterOwner: DEAD, paymasterOwnershipTransferPending: true };
    const nominated = gaslessChain(handover);
    nominated.state.paymaster.owner = OWNER;
    nominated.state.paymaster.pendingOwner = DEAD;
    assert.deepEqual((await finalize(handover, nominated)).mismatches, []);
    const accepted = gaslessChain(handover);
    accepted.state.paymaster.owner = DEAD;
    assert.deepEqual((await finalize(handover, accepted)).mismatches, []);
    // Confirmations count from the newest creation: a paymaster mined a block after the vault
    // (nonce-ordered sends across full blocks) is the one that must wait; deployBlock stays the vault's.
    const later = latest => {
        const fake = gaslessChain(deployment, latest);
        fake.state.receipts[TX.paymaster].blockNumber = '0x8';
        fake.log.receipts.find(receipt => receipt.transactionHash === TX.paymaster).blockNumber = '0x8';
        return fake;
    };
    await assert.rejects(finalize(deployment, later(8), 2), /withdrawalPaymaster's creation \(block 8\) has 1 confirmations, 2 required/);
    const { manifest: waited, mismatches: none } = await finalize(deployment, later(9), 2);
    assert.deepEqual(none, []);
    assert.equal(waited.deployBlock, 7);
});

test('finalize reports a paymaster whose code or state is not the manifest\'s, and writes nothing', { skip: NO_ARTIFACTS }, async () => {
    const deployment = gaslessManifest();
    const cases = [
        ['paymaster_deposit', fake => { fake.state.entryPoint.deposit -= 1n; }],
        ['paymaster_stake', fake => { fake.state.entryPoint.stakes[PAYMASTER].staked = 0n; }],
        ['factory_stake', fake => { fake.state.entryPoint.stakes[FACTORY].delay = 1n; }],
        ['paymaster_gas_policy.marginGas', fake => { fake.state.paymaster.gasPolicy[8 + GAS_POLICY_SCALARS.indexOf('marginGas')] += 1n; }],
        ['paymaster_gas_policy.callCap[3]', fake => { fake.state.paymaster.gasPolicy[7] -= 1n; }],
        ['paymaster_policy.escapesEnabled', fake => { fake.state.paymaster.policy[3] = 1n; }],
        ['paymaster_policy.sponsorshipPaused', fake => { fake.state.paymaster.policy[4] = 1n; }],
        ['paymaster_fee_ceilings.maxFeeWei', fake => { fake.state.paymaster.maxFeeCeiling += 1n; }],
        ['paymaster_fee_keeper', fake => { fake.state.paymaster.feeKeeper = DEAD; }],
        ['paymaster_owner', fake => { fake.state.paymaster.owner = DEAD; }],
        ['entry_point_runtime_codehash', fake => { fake.state.code[CANONICAL_ENTRY_POINT] = '0x6000'; }],
        ['sender_creator_runtime_codehash', fake => { delete fake.state.code[SENDER_CREATOR]; }],
        ['factory_runtime_codehash', fake => { fake.state.code[FACTORY] = fake.state.code[PAYMASTER]; }],
        ['account_implementation_runtime_codehash', fake => { fake.state.code[IMPLEMENTATION] = '0x'; }],
    ];
    for (const [field, corrupt] of cases) {
        const fake = gaslessChain(deployment);
        corrupt(fake);
        const result = await finalize(deployment, fake);
        assert.equal(result.manifest, undefined, field);
        assert.deepEqual(result.mismatches.map(m => `${m.source}:${m.field}`), [`rpc:${field}`], field);
    }
    // A nominee other than the recorded owner, in either slot.
    const handover = { ...deployment, paymasterOwner: DEAD, paymasterOwnershipTransferPending: true };
    const wrong = gaslessChain(handover);
    wrong.state.paymaster.owner = OWNER;
    wrong.state.paymaster.pendingOwner = TREASURY;
    assert.deepEqual((await finalize(handover, wrong)).mismatches.map(m => m.field), ['paymaster_owner']);
    // The paymaster on chain was deployed against another vault (its immutables differ).
    const other = gaslessChain({ ...deployment, vault: POSEIDON });
    other.state.code[VAULT] = other.state.code[POSEIDON];
    const result = await finalize(deployment, { log: other.log, rpc: gaslessChain(deployment).rpc, state: null });
    assert.deepEqual(result.mismatches, []);
    const mismatched = await finalize(deployment, { log: other.log, rpc: async (method, params) => {
        if (method === 'eth_getCode' && [PAYMASTER, FACTORY].includes(params[0].toLowerCase())) return other.state.code[params[0].toLowerCase()];
        return gaslessChain(deployment).rpc(method, params);
    } });
    assert.deepEqual(mismatched.mismatches.map(m => `${m.source}:${m.field}`), ['rpc:paymaster_runtime_codehash', 'rpc:factory_runtime_codehash']);
    // The manifest's own recorded gasless codehashes are not the expected ones.
    const recorded = { ...deployment, senderCreatorRuntimeCodehash: `0x${'00'.repeat(32)}`, factoryRuntimeCodehash: `0x${'11'.repeat(32)}` };
    const own = await finalize(recorded, gaslessChain(recorded));
    assert.deepEqual(own.mismatches.map(m => `${m.source}:${m.field}`), ['deployment:factory_runtime_codehash', 'deployment:sender_creator_runtime_codehash']);
});

test('finalize refuses a paymaster creation missing from the log, and a manifest without the field', { skip: NO_ARTIFACTS }, async () => {
    const deployment = gaslessManifest();
    const fake = gaslessChain(deployment);
    fake.log.receipts = fake.log.receipts.filter(receipt => receipt.contractAddress !== PAYMASTER);
    await assert.rejects(finalize(deployment, fake), /0 receipts creating the withdrawalPaymaster/);
    const failed = gaslessChain(deployment);
    failed.state.receipts[TX.paymaster].status = '0x0';
    await assert.rejects(finalize(deployment, failed), /withdrawalPaymaster creation .* failed on chain/);
    const legacy = pendingManifest();
    delete legacy.withdrawalPaymaster;
    await assert.rejects(finalize(legacy, chain(legacy)), /no withdrawalPaymaster field/);
});

test('a manifest with withdrawalPaymaster null finalizes on the vault\'s checks alone', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    assert.equal(deployment.withdrawalPaymaster, null);
    // The fake chain answers no EntryPoint or paymaster call: none is made.
    const { manifest: final, mismatches, expected } = await finalize(deployment, chain(deployment));
    assert.deepEqual(mismatches, []);
    assert.equal(final.withdrawalPaymaster, null);
    assert.deepEqual(Object.keys(expected), ['vault_runtime_codehash', 'adapter_runtime_codehash', 'poseidon_runtime_codehash']);
    assert.deepEqual(final.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter, poseidonLibrary: TX.poseidon });
});

test('--check re-audits every recorded codehash, the gasless ones included', { skip: NO_ARTIFACTS }, async () => {
    const deployment = gaslessManifest();
    const clean = await auditDeployment({ artifacts: ARTIFACTS, deployment, check: true, rpc: gaslessChain(deployment).rpc });
    assert.deepEqual(clean.mismatches, []);
    const recorded = { ...deployment, paymasterRuntimeCodehash: `0x${'22'.repeat(32)}`, entryPointRuntimeCodehash: `0x${'33'.repeat(32)}` };
    const audit = await auditDeployment({ artifacts: ARTIFACTS, deployment: recorded, check: true });
    assert.deepEqual(audit.mismatches.map(m => `${m.source}:${m.field}`), ['deployment:paymaster_runtime_codehash', 'deployment:entry_point_runtime_codehash']);
    const chainOnly = gaslessChain(deployment);
    chainOnly.state.code[SENDER_CREATOR] = '0x6000';
    const rpcAudit = await auditDeployment({ artifacts: ARTIFACTS, deployment, check: true, rpc: chainOnly.rpc });
    assert.deepEqual(rpcAudit.mismatches.map(m => `${m.source}:${m.field}`), ['rpc:sender_creator_runtime_codehash']);
    // The command line: exit 0 on a clean manifest, 1 on a recorded mismatch, with the report's eight hashes.
    const dir = mkdtempSync(join(tmpdir(), 'zkapi-codehashes-'));
    try {
        const script = join(ROOT, 'scripts/expected-codehashes.mjs');
        writeFileSync(join(dir, 'clean.json'), JSON.stringify(deployment));
        writeFileSync(join(dir, 'wrong.json'), JSON.stringify(recorded));
        const ok = spawnSync(process.execPath, [script, '--artifacts', ARTIFACTS, '--deployment', join(dir, 'clean.json'), '--check'], { encoding: 'utf8' });
        assert.equal(ok.status, 0, ok.stderr);
        const report = JSON.parse(ok.stdout);
        assert.deepEqual(report.mismatches, []);
        assert.equal(report.paymaster_runtime_codehash, deployment.paymasterRuntimeCodehash);
        assert.equal(report.sender_creator_runtime_codehash, SENDER_CREATOR_V070_CODEHASH);
        const bad = spawnSync(process.execPath, [script, '--artifacts', ARTIFACTS, '--deployment', join(dir, 'wrong.json'), '--check'], { encoding: 'utf8' });
        assert.equal(bad.status, 1, bad.stderr);
        assert.deepEqual(JSON.parse(bad.stdout).mismatches.map(m => m.field), ['paymaster_runtime_codehash', 'entry_point_runtime_codehash']);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
