#!/usr/bin/env node
// Expected runtime codehashes of a zkAPI deployment (vault revision 3), computed from the
// pinned-compiler Forge artifacts alone: the vault's deployedBytecode with the Bn254Poseidon
// link applied and its immutableReferences filled from the constructor arguments, the adapter's
// deployedBytecode, and the library's deployedBytecode (with its own address in a call-protection
// prefix, if the compiler emitted one). A deployment with the gasless-withdrawal paymaster adds
// the paymaster's, the transit-account factory's and the account logic's deployedBytecode with
// their immutables filled the same way, and the two canonical ERC-4337 v0.7.0 runtimes (the
// EntryPoint and its SenderCreator), which are pinned constants. Anyone can rebuild the artifacts
// from source (protocol/contracts/foundry.toml pins solc, via_ir, 10,000 runs, bytecode_hash
// "none" and cbor_metadata false) and audit a deployment.
//
//   node scripts/expected-codehashes.mjs --deployment .demo/deployment.json [--check] [--rpc URL]
//   node scripts/expected-codehashes.mjs --deployment .demo/deployment.json.pending --rpc URL \
//     --finalize .demo/deployment.json [--broadcast-log FILE] [--confirmations N]
//   node scripts/expected-codehashes.mjs --poseidon 0x.. --note-ttl 2592000 --challenge-period 172800 \
//     --max-pause-duration 3888000 --request-charge-cap 50000 --proof-adapter 0x.. \
//     --state-key-x .. --state-key-y .. --clearance-key-x .. --clearance-key-y .. \
//     [--vault 0x.. --entry-point 0x.. --paymaster 0x.. --factory 0x.. --account-implementation 0x.. \
//      --wei-per-unit 1000000000 --creation-code-keccak 0x..]
//
// --deployment reads Deploy.s.sol's manifest; flags override its fields. --artifacts DIR selects
// the Forge out directory (default protocol/contracts/out). --check compares the result with the
// manifest's recorded codehashes, and --rpc URL with eth_getCode at the manifest's addresses (the
// EntryPoint's and SenderCreator's included); any mismatch exits 1. Prints JSON; integers wider
// than 2^53 - 1 print as decimal strings.
//
// --finalize OUT turns Deploy.s.sol's provisional manifest (OUTPUT_PATH.pending, deploymentStatus
// "pending") into the deployment manifest, once the broadcast is checked on chain. forge writes the
// provisional manifest while it simulates, before it sends anything, so its addresses, codehashes
// and post-deploy checks describe the simulation. Finalizing takes each creation's transaction
// from the receipts in forge's broadcast log (--broadcast-log; default
// demo/contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json), and requires, through the RPC:
// the manifest's chain; each receipt on chain, successful and creating the manifest's address; at
// least --confirmations (default 1) blocks on the newest creation; every runtime codehash (the
// manifest's, and on chain); and the vault's owner and treasury. With the paymaster it also
// requires its creation receipt (the factory and the account logic are created by constructors
// and are checked by their code), its EntryPoint deposit of at least the manifest's initial
// deposit, its stake and the factory's, and its policy, fee ceilings, gas policy, fee keeper and
// owner (or nominated owner) to be the manifest's. Only then does it write OUT: the manifest with
// deploymentStatus "deployed", deployBlock (the block that created the vault, the indexer's and the
// profiles' deploy_block) and deployTransactions. Any mismatch exits 1 and any other failure exits
// 2; neither writes OUT. A manifest with withdrawalPaymaster null (GASLESS=0) carries no gasless
// field and finalizes on the vault's checks alone.
//
// Integers are read exactly. Deploy.s.sol writes the signing-key coordinates and every wei amount
// as decimal strings and every other number below 2^53. A wider bare JSON number in a manifest
// from elsewhere is read from its source text, never rounded; a number that is neither a safe
// integer nor an integer literal (a wide fraction or exponent form) is refused.
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DAY = 86_400n;
const MIN_TREASURY_CHANGE_DELAY = 2n * DAY;
const MIN_UNPAUSE_CLAIM_GRACE = DAY;

// ------------------------------------------------------------------ keccak256 (Keccak-f[1600])

const MASK64 = (1n << 64n) - 1n;
const ROUND_CONSTANTS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// ROTATIONS[x][y], the rho offsets.
const ROTATIONS = [
    [0n, 36n, 3n, 41n, 18n],
    [1n, 44n, 10n, 45n, 2n],
    [62n, 6n, 43n, 15n, 61n],
    [28n, 55n, 25n, 21n, 56n],
    [27n, 20n, 39n, 8n, 14n],
];

function rotl(value, shift) {
    return shift === 0n ? value : ((value << shift) | (value >> (64n - shift))) & MASK64;
}

function keccakF(state) {
    const b = new Array(25);
    for (const constant of ROUND_CONSTANTS) {
        const c = [0, 1, 2, 3, 4].map(x => state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
        for (let x = 0; x < 5; x++) {
            const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n);
            for (let y = 0; y < 25; y += 5) state[y + x] ^= d;
        }
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x][y]);
        }
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK64 & b[((x + 2) % 5) + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
}

export function keccak256(bytes) {
    const rate = 136;
    const padded = new Uint8Array(Math.floor(bytes.length / rate + 1) * rate);
    padded.set(bytes);
    padded[bytes.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    const state = new Array(25).fill(0n);
    for (let offset = 0; offset < padded.length; offset += rate) {
        for (let lane = 0; lane < rate / 8; lane++) {
            let value = 0n;
            for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(padded[offset + 8 * lane + i]);
            state[lane] ^= value;
        }
        keccakF(state);
    }
    let out = '0x';
    for (let lane = 0; lane < 4; lane++) {
        for (let i = 0; i < 8; i++) out += Number((state[lane] >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, '0');
    }
    return out;
}

// ------------------------------------------------------------------------------- helpers

function fail(message) {
    throw new Error(message);
}

export function hexToBytes(hex) {
    const body = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (!/^([0-9a-fA-F]{2})*$/.test(body)) fail(`not hex bytes: ${hex.slice(0, 80)}...`);
    return Uint8Array.from(body.match(/../g) ?? [], pair => parseInt(pair, 16));
}

/// A JavaScript number is accepted only as a safe integer: a wider one was already rounded.
function exactNumber(value, label) {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
        fail(`${label}: ${value} is not a safe integer (pass a decimal string or a BigInt)`);
    }
    return value;
}

function word(value, label) {
    exactNumber(value, label);
    let n;
    try {
        n = BigInt(value);
    } catch {
        fail(`${label}: not an integer: ${value}`);
    }
    if (n < 0n || n >= 1n << 256n) fail(`${label}: out of range`);
    return n.toString(16).padStart(64, '0');
}

function address(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail(`${label}: not an address: ${value}`);
    return value.toLowerCase();
}

function bytes32(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) fail(`${label}: not a 32-byte hex string: ${value}`);
    return value.toLowerCase();
}

function uint(value, bits, label) {
    if (value === undefined || value === null || value === '') fail(`missing ${label}`);
    exactNumber(value, label);
    let n;
    try {
        n = BigInt(value);
    } catch {
        fail(`${label}: not an integer: ${value}`);
    }
    if (n < 0n || n >= 1n << BigInt(bits)) fail(`${label}: does not fit uint${bits}`);
    return n;
}

function artifact(dir, name) {
    const path = join(dir, `${name}.sol`, `${name}.json`);
    try {
        return JSON.parse(readFileSync(path, 'utf8'));
    } catch (error) {
        fail(`cannot read ${path} (run forge build first): ${error.message}`);
    }
}

/// AST id -> name of every immutable state variable.
function immutableNames(ast) {
    if (!ast) fail('artifact has no AST; build with ast = true (foundry.toml)');
    const names = new Map();
    const visit = node => {
        if (Array.isArray(node)) return node.forEach(visit);
        if (!node || typeof node !== 'object') return;
        if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') names.set(String(node.id), node.name);
        for (const value of Object.values(node)) if (value && typeof value === 'object') visit(value);
    };
    visit(ast);
    return names;
}

/// Writes `hexValue` (an even-length hex string) at byte offset `start` of the hex code string.
function patch(code, start, length, hexValue) {
    if (hexValue.length !== 2 * length) fail('patch length');
    const at = 2 * start;
    if (at + 2 * length > code.length) fail('patch beyond the code');
    return code.slice(0, at) + hexValue + code.slice(at + 2 * length);
}

/// `contract`'s deployedBytecode with every immutable reference filled from `values`, a map from
/// the immutable's AST name to its 32-byte hex word. Every reference must have a value and every
/// value an immutable: a contract whose immutables changed fails here instead of hashing wrongly.
function filledRuntimeCode(contract, art, values) {
    const refs = art.deployedBytecode;
    if (Object.keys(refs.linkReferences ?? {}).length) fail(`${contract} is expected to link no library`);
    let code = refs.object.replace(/^0x/, '');
    const names = immutableNames(art.ast);
    const filled = new Set();
    for (const [id, places] of Object.entries(refs.immutableReferences ?? {})) {
        const name = names.get(id) ?? fail(`${contract}: immutable reference ${id} has no declaration in the AST`);
        const value = values[name] ?? fail(`${contract} immutable ${name} is not derived by this script`);
        for (const ref of places) code = patch(code, ref.start, ref.length, value);
        filled.add(name);
    }
    for (const name of Object.keys(values)) if (!filled.has(name)) fail(`${contract} has no immutable ${name}`);
    if (/[^0-9a-fA-F]/.test(code)) fail(`${contract} runtime code still has an unlinked placeholder`);
    return code;
}

// ------------------------------------------------------------------------------- codehashes

/// The constructor-derived immutables of ZkApiVault, by name, as 32-byte hex words.
export function vaultImmutables(inputs) {
    const challengePeriod = uint(inputs.challengePeriod, 64, 'challengePeriod');
    const maxPauseDuration = uint(inputs.maxPauseDuration, 64, 'maxPauseDuration');
    if (challengePeriod === 0n) fail('challengePeriod must be positive');
    if (maxPauseDuration < 2n * challengePeriod) fail('maxPauseDuration must be at least 2 * challengePeriod');
    const treasuryChangeDelay = challengePeriod > MIN_TREASURY_CHANGE_DELAY ? challengePeriod : MIN_TREASURY_CHANGE_DELAY;
    const unpauseClaimGrace = challengePeriod > MIN_UNPAUSE_CLAIM_GRACE ? challengePeriod : MIN_UNPAUSE_CLAIM_GRACE;
    return {
        noteTtl: word(uint(inputs.noteTtl, 64, 'noteTtl'), 'noteTtl'),
        challengePeriod: word(challengePeriod, 'challengePeriod'),
        treasuryChangeDelay: word(treasuryChangeDelay, 'treasuryChangeDelay'),
        unpauseClaimGrace: word(unpauseClaimGrace, 'unpauseClaimGrace'),
        requestChargeCap: word(uint(inputs.requestChargeCap, 128, 'requestChargeCap'), 'requestChargeCap'),
        proofAdapter: word(address(inputs.proofAdapter, 'proofAdapter'), 'proofAdapter'),
        stateSigningKeyX: word(inputs.stateSigningKeyX, 'stateSigningKeyX'),
        stateSigningKeyY: word(inputs.stateSigningKeyY, 'stateSigningKeyY'),
        clearanceSigningKeyX: word(inputs.clearanceSigningKeyX, 'clearanceSigningKeyX'),
        clearanceSigningKeyY: word(inputs.clearanceSigningKeyY, 'clearanceSigningKeyY'),
        maxPauseDuration: word(maxPauseDuration, 'maxPauseDuration'),
    };
}

// ------------------------------------------------------------- gasless withdrawals (ERC-4337)

/// The canonical EntryPoint v0.7.0 and the SenderCreator it created (its nonce 1, an immutable of
/// its runtime), pinned by the keccak256 of their runtime code; identical on every chain.
export const CANONICAL_ENTRY_POINT = '0x0000000071727de22e5e9d8baf0edac6f37da032';
export const ENTRY_POINT_V070_CODEHASH = '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58';
export const SENDER_CREATOR = '0xefc2c1444ebcc4db75e7613d20c6a62ff67a167c';
export const SENDER_CREATOR_V070_CODEHASH = '0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689';
// ZkApiWithdrawalAccountFactory's constants: every transit account's creation code is
// CREATION_STUB ‖ PROXY_HEAD ‖ <account logic address> ‖ PROXY_TAIL (74 bytes).
const CREATION_STUB = '600d80380380916000396000f3';
const PROXY_HEAD = '36600060003760a0603d36396000600060a03601600073';
const PROXY_TAIL = '5af43d600060003e3d600082603b57fd5bf3';
/// ZkApiWithdrawalPaymaster.GasPolicy after its two uint256[4] arrays (callFloor, callHardCap),
/// in ABI order; the manifest's paymasterGasPolicy names them the same, with callHardCap as callCap.
export const GAS_POLICY_SCALARS = Object.freeze([
    'postOpFloor', 'postOpCap', 'verificationFloor', 'verificationFloorInit', 'verificationCap', 'pvgFloor', 'pvgCap',
    'pmVerificationFloor', 'pmVerificationCap', 'postOpBaseGas', 'postOpEscapeGas', 'postOpFinalizeExtraGas',
    'postOpEscapeForwardGas', 'eoaPushGas', 'newAccountGas', 'payoutPushGas', 'creditGas', 'accountCallOverheadGas',
    'accountCallOverheadEscapeGas', 'marginGas', 'finalizeReserveGas', 'maxAttempts',
]);

function rlpInteger(n) {
    if (n === 0n) return '80';
    let hex = n.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    const length = hex.length / 2;
    if (length === 1 && n < 0x80n) return hex;
    if (length > 55) fail('rlp: integer too wide');
    return (0x80 + length).toString(16) + hex;
}

/// The address CREATE gives the contract `deployer` creates at `nonce`.
export function createAddress(deployer, nonce) {
    const payload = `94${address(deployer, 'deployer').slice(2)}${rlpInteger(uint(nonce, 64, 'nonce'))}`;
    const rlp = `${(0xc0 + payload.length / 2).toString(16)}${payload}`;
    return `0x${keccak256(hexToBytes(rlp)).slice(26)}`;
}

/// The 74-byte creation code of every transit account of a factory whose account logic is at
/// `implementation` (ZkApiWithdrawalAccountFactory.accountCreationCode()).
export function accountCreationCode(implementation) {
    return `0x${CREATION_STUB}${PROXY_HEAD}${address(implementation, 'implementation').slice(2)}${PROXY_TAIL}`;
}

/// The 30 words ZkApiWithdrawalPaymaster.gasPolicy() returns, from a manifest's paymasterGasPolicy.
export function gasPolicyWords(policy) {
    if (!policy || typeof policy !== 'object') fail('missing paymasterGasPolicy');
    const words = [];
    for (const key of ['callFloor', 'callCap']) {
        if (!Array.isArray(policy[key]) || policy[key].length !== 4) fail(`paymasterGasPolicy.${key} must list four kinds`);
        for (let kind = 0; kind < 4; kind++) words.push(uint(policy[key][kind], 256, `paymasterGasPolicy.${key}[${kind}]`));
    }
    for (const key of GAS_POLICY_SCALARS) words.push(uint(policy[key], 256, `paymasterGasPolicy.${key}`));
    return words;
}

/// The immutables of the paymaster, the factory and the account logic, by name, as 32-byte hex
/// words, from a manifest's gasless fields; checks the fields against each other first (the logic
/// is the factory's nonce-1 creation, the creation code is the factory's constants around it, and
/// its keccak256 is both contracts' accountCreationCodeHash).
export function gaslessImmutables(inputs) {
    const entryPoint = address(inputs.entryPoint, 'entryPoint');
    const vault = address(inputs.vault, 'vault');
    const paymaster = address(inputs.withdrawalPaymaster, 'withdrawalPaymaster');
    const factory = address(inputs.withdrawalAccountFactory, 'withdrawalAccountFactory');
    const implementation = address(inputs.withdrawalAccountImplementation, 'withdrawalAccountImplementation');
    const derived = createAddress(factory, 1);
    if (implementation !== derived) {
        fail(`withdrawalAccountImplementation ${implementation} is not the factory's nonce-1 creation ${derived}`);
    }
    const creation = accountCreationCode(implementation);
    if (inputs.accountCreationCode !== undefined && String(inputs.accountCreationCode).toLowerCase() !== creation) {
        fail(`accountCreationCode is not the factory's creation code for the logic at ${implementation}`);
    }
    const creationHash = keccak256(hexToBytes(creation));
    if (inputs.accountCreationCodeKeccak256 !== undefined
        && bytes32(inputs.accountCreationCodeKeccak256, 'accountCreationCodeKeccak256') !== creationHash) {
        fail(`accountCreationCodeKeccak256 is not keccak256 of the creation code (${creationHash})`);
    }
    const hashWord = creationHash.slice(2);
    return {
        paymaster: {
            entryPoint: word(entryPoint, 'entryPoint'),
            vault: word(vault, 'vault'),
            adapter: word(address(inputs.proofAdapter, 'proofAdapter'), 'proofAdapter'),
            factory: word(factory, 'withdrawalAccountFactory'),
            WEI_PER_UNIT: word(uint(inputs.nativeAssetWeiPerUnit, 256, 'nativeAssetWeiPerUnit'), 'nativeAssetWeiPerUnit'),
            STATE_X: word(inputs.stateSigningKeyX, 'stateSigningKeyX'),
            STATE_Y: word(inputs.stateSigningKeyY, 'stateSigningKeyY'),
            CLEAR_X: word(inputs.clearanceSigningKeyX, 'clearanceSigningKeyX'),
            CLEAR_Y: word(inputs.clearanceSigningKeyY, 'clearanceSigningKeyY'),
            MAX_PAUSE_DURATION: word(uint(inputs.maxPauseDuration, 64, 'maxPauseDuration'), 'maxPauseDuration'),
            accountCreationCodeHash: hashWord,
        },
        factory: {
            entryPoint: word(entryPoint, 'entryPoint'),
            vault: word(vault, 'vault'),
            paymaster: word(paymaster, 'withdrawalPaymaster'),
            implementation: word(implementation, 'withdrawalAccountImplementation'),
            accountCreationCodeHash: hashWord,
        },
        implementation: { self: word(implementation, 'withdrawalAccountImplementation') },
        accountCreationCode: creation,
    };
}

/// Whether `inputs` describe a deployment with the paymaster (withdrawalPaymaster set, not null).
export function hasGasless(inputs) {
    return inputs.withdrawalPaymaster !== undefined && inputs.withdrawalPaymaster !== null;
}

export function expectedRuntimeCode(artifactsDir, inputs) {
    const poseidon = address(inputs.poseidonLibrary, 'poseidonLibrary').slice(2);

    const vaultArtifact = artifact(artifactsDir, 'ZkApiVault');
    let vault = vaultArtifact.deployedBytecode.object.replace(/^0x/, '');
    const links = vaultArtifact.deployedBytecode.linkReferences ?? {};
    let linked = 0;
    for (const [file, libraries] of Object.entries(links)) {
        for (const [name, refs] of Object.entries(libraries)) {
            if (name !== 'Bn254Poseidon') fail(`ZkApiVault links an unexpected library ${file}:${name}`);
            for (const ref of refs) {
                vault = patch(vault, ref.start, ref.length, poseidon);
                ++linked;
            }
        }
    }
    if (linked === 0) fail('ZkApiVault has no Bn254Poseidon link reference');
    const names = immutableNames(vaultArtifact.ast);
    const values = vaultImmutables(inputs);
    const filled = new Set();
    for (const [id, refs] of Object.entries(vaultArtifact.deployedBytecode.immutableReferences ?? {})) {
        const name = names.get(id) ?? fail(`immutable reference ${id} has no declaration in the AST`);
        const value = values[name] ?? fail(`ZkApiVault immutable ${name} is not derived by this script`);
        for (const ref of refs) vault = patch(vault, ref.start, ref.length, value);
        filled.add(name);
    }
    for (const name of Object.keys(values)) if (!filled.has(name)) fail(`ZkApiVault has no immutable ${name}`);
    if (/[^0-9a-fA-F]/.test(vault)) fail('ZkApiVault runtime code still has an unlinked placeholder');

    const adapterArtifact = artifact(artifactsDir, 'Groth16ProofAdapter');
    const adapterRefs = adapterArtifact.deployedBytecode;
    if (Object.keys(adapterRefs.linkReferences ?? {}).length || Object.keys(adapterRefs.immutableReferences ?? {}).length) {
        fail('Groth16ProofAdapter is expected to have no links and no immutables');
    }
    const adapter = adapterRefs.object.replace(/^0x/, '');

    const libraryArtifact = artifact(artifactsDir, 'Bn254Poseidon');
    let library = libraryArtifact.deployedBytecode.object.replace(/^0x/, '');
    // A library with call protection starts with PUSH20 <its own address>, written at deployment.
    // Bn254Poseidon's via-IR code has none (all its functions are pure), so its code does not
    // depend on its address.
    if (library.startsWith('73' + '0'.repeat(40))) library = patch(library, 1, 20, poseidon);

    const code = { vault: `0x${vault}`, adapter: `0x${adapter}`, poseidon: `0x${library}` };
    if (!hasGasless(inputs)) return code;
    const immutables = gaslessImmutables(inputs);
    code.paymaster = `0x${filledRuntimeCode('ZkApiWithdrawalPaymaster', artifact(artifactsDir, 'ZkApiWithdrawalPaymaster'), immutables.paymaster)}`;
    code.factory = `0x${filledRuntimeCode('ZkApiWithdrawalAccountFactory', artifact(artifactsDir, 'ZkApiWithdrawalAccountFactory'), immutables.factory)}`;
    code.implementation = `0x${filledRuntimeCode('ZkApiWithdrawalAccount', artifact(artifactsDir, 'ZkApiWithdrawalAccount'), immutables.implementation)}`;
    return code;
}

export function expectedCodehashes(artifactsDir, inputs) {
    const code = expectedRuntimeCode(artifactsDir, inputs);
    const hashes = {
        vault_runtime_codehash: keccak256(hexToBytes(code.vault)),
        adapter_runtime_codehash: keccak256(hexToBytes(code.adapter)),
        poseidon_runtime_codehash: keccak256(hexToBytes(code.poseidon)),
    };
    if (code.paymaster) {
        hashes.paymaster_runtime_codehash = keccak256(hexToBytes(code.paymaster));
        hashes.factory_runtime_codehash = keccak256(hexToBytes(code.factory));
        hashes.account_implementation_runtime_codehash = keccak256(hexToBytes(code.implementation));
        hashes.entry_point_runtime_codehash = ENTRY_POINT_V070_CODEHASH;
        hashes.sender_creator_runtime_codehash = SENDER_CREATOR_V070_CODEHASH;
    }
    return hashes;
}

/// Parses a deployment manifest without rounding: a JSON number above 2^53 - 1 becomes a BigInt
/// read from its source text (JSON.parse source text access, Node 21 and later), and any other
/// number that is not a safe integer (a fraction, an exponent) is refused.
export function parseDeployment(text) {
    return JSON.parse(text, (key, value, context) => {
        if (typeof value !== 'number' || Number.isSafeInteger(value)) return value;
        const source = context?.source;
        if (typeof source === 'string' && /^(0|[1-9][0-9]*)$/.test(source)) return BigInt(source);
        return fail(`deployment field ${key}: ${source ?? value} is not an exact integer; write it as a decimal string`);
    });
}

// ------------------------------------------------------------------------- audit and finalize

/// A JSON-RPC client: `rpc(method, params)` resolves to the result, or throws.
export function jsonRpc(url) {
    let id = 0;
    return async (method, params) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
            signal: AbortSignal.timeout(20_000),
        });
        const body = await response.json();
        if (body.error || !('result' in body)) fail(`${method}: ${JSON.stringify(body.error ?? body)}`);
        return body.result;
    };
}

async function codehashAt(rpc, target) {
    const code = await rpc('eth_getCode', [target, 'latest']);
    if (typeof code !== 'string') fail(`eth_getCode ${target}: ${JSON.stringify(code)}`);
    return keccak256(hexToBytes(code));
}

export function selector(signature) {
    return keccak256(new TextEncoder().encode(signature)).slice(0, 10);
}

function quantity(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) fail(`${label}: not a hex quantity: ${value}`);
    return BigInt(value);
}

/// Calldata of `signature` with `args`, each a 32-byte word (an address, an integer or a bytes32).
export function encodeCall(signature, args = []) {
    return selector(signature) + args.map((value, i) => {
        if (typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value)) return value.slice(2).toLowerCase();
        return word(value, `${signature} argument ${i}`);
    }).join('');
}

/// `to`'s answer to `signature(args)` through `rpc`, as the `count` 32-byte words it returns.
export async function callWords(rpc, to, signature, args, count) {
    const data = await rpc('eth_call', [{ to, data: encodeCall(signature, args) }, 'latest']);
    if (typeof data !== 'string' || !/^0x([0-9a-fA-F]{64})*$/.test(data) || (data.length - 2) / 64 !== count) {
        fail(`${signature} at ${to}: unexpected return ${data}`);
    }
    const words = [];
    for (let i = 0; i < count; i++) words.push(BigInt(`0x${data.slice(2 + 64 * i, 66 + 64 * i)}`));
    return words;
}

const addressOf = value => `0x${value.toString(16).padStart(40, '0')}`;

/// The constructor-derived inputs of a manifest, with `overrides` (CLI flags) applied.
export function deploymentInputs(deployment, overrides = {}) {
    const inputs = {
        poseidonLibrary: deployment.poseidonLibrary,
        proofAdapter: deployment.proofAdapter,
        noteTtl: deployment.noteTtl,
        challengePeriod: deployment.challengePeriod,
        maxPauseDuration: deployment.maxPauseDuration,
        requestChargeCap: deployment.requestChargeCap,
        stateSigningKeyX: deployment.stateSigningKeyX,
        stateSigningKeyY: deployment.stateSigningKeyY,
        clearanceSigningKeyX: deployment.clearanceSigningKeyX,
        clearanceSigningKeyY: deployment.clearanceSigningKeyY,
        withdrawalPaymaster: deployment.withdrawalPaymaster ?? null,
        ...overrides,
    };
    if (hasGasless(inputs)) {
        Object.assign(inputs, {
            vault: deployment.vault,
            entryPoint: deployment.entryPoint ?? CANONICAL_ENTRY_POINT,
            withdrawalAccountFactory: deployment.withdrawalAccountFactory,
            withdrawalAccountImplementation: deployment.withdrawalAccountImplementation,
            nativeAssetWeiPerUnit: deployment.nativeAssetWeiPerUnit,
            accountCreationCode: deployment.accountCreationCode,
            accountCreationCodeKeccak256: deployment.accountCreationCodeKeccak256,
            ...overrides,
        });
    }
    return inputs;
}

/// The expected codehashes of `deployment`, compared with its recorded ones (`check`) and with the
/// code at its addresses (`rpc`, a jsonRpc client). Returns { inputs, expected, mismatches }.
export async function auditDeployment({ artifacts, deployment, overrides = {}, check = false, rpc = null }) {
    const inputs = deploymentInputs(deployment, overrides);
    const expected = expectedCodehashes(artifacts, inputs);
    const gasless = hasGasless(inputs);
    const mismatches = [];
    const compare = (source, field, actual) => {
        if (typeof actual !== 'string' || actual.toLowerCase() !== expected[field]) {
            mismatches.push({ source, field, expected: expected[field], actual: actual ?? null });
        }
    };
    if (check) {
        compare('deployment', 'vault_runtime_codehash', deployment.vaultRuntimeCodehash);
        compare('deployment', 'adapter_runtime_codehash', deployment.adapterRuntimeCodehash);
        compare('deployment', 'poseidon_runtime_codehash', deployment.poseidonRuntimeCodehash);
        if (gasless) {
            compare('deployment', 'paymaster_runtime_codehash', deployment.paymasterRuntimeCodehash);
            compare('deployment', 'factory_runtime_codehash', deployment.factoryRuntimeCodehash);
            compare('deployment', 'account_implementation_runtime_codehash', deployment.accountImplementationRuntimeCodehash);
            compare('deployment', 'entry_point_runtime_codehash', deployment.entryPointRuntimeCodehash);
            compare('deployment', 'sender_creator_runtime_codehash', deployment.senderCreatorRuntimeCodehash);
        }
    }
    if (rpc) {
        const vault = deployment.vault ?? fail('--rpc needs the vault address from --deployment');
        compare('rpc', 'vault_runtime_codehash', await codehashAt(rpc, address(vault, 'vault')));
        compare('rpc', 'adapter_runtime_codehash', await codehashAt(rpc, address(inputs.proofAdapter, 'proofAdapter')));
        compare('rpc', 'poseidon_runtime_codehash', await codehashAt(rpc, address(inputs.poseidonLibrary, 'poseidonLibrary')));
        if (gasless) {
            compare('rpc', 'paymaster_runtime_codehash', await codehashAt(rpc, address(inputs.withdrawalPaymaster, 'withdrawalPaymaster')));
            compare('rpc', 'factory_runtime_codehash', await codehashAt(rpc, address(inputs.withdrawalAccountFactory, 'withdrawalAccountFactory')));
            compare('rpc', 'account_implementation_runtime_codehash',
                await codehashAt(rpc, address(inputs.withdrawalAccountImplementation, 'withdrawalAccountImplementation')));
            compare('rpc', 'entry_point_runtime_codehash', await codehashAt(rpc, address(inputs.entryPoint, 'entryPoint')));
            compare('rpc', 'sender_creator_runtime_codehash', await codehashAt(rpc, address(deployment.senderCreator ?? SENDER_CREATOR, 'senderCreator')));
        }
    }
    return { inputs, expected, mismatches };
}

/// The paymaster's state the codehashes do not cover, read through `rpc` and compared with the
/// manifest: the EntryPoint deposit (at least the initial one), both stakes, the policy, the fee
/// ceilings, the gas policy, the fee keeper and the owner. With paymasterOwnershipTransferPending
/// the deployer owns the paymaster until the recorded owner accepts, so either the pending or the
/// accepted state passes. Mismatches are appended to `mismatches`.
export async function checkPaymasterState(rpc, deployment, mismatches) {
    const paymaster = address(deployment.withdrawalPaymaster, 'withdrawalPaymaster');
    const factory = address(deployment.withdrawalAccountFactory, 'withdrawalAccountFactory');
    const entryPoint = address(deployment.entryPoint ?? CANONICAL_ENTRY_POINT, 'entryPoint');
    const mismatch = (field, expected, actual) => mismatches.push({ source: 'rpc', field, expected, actual });

    const deposit = uint(deployment.paymasterInitialDepositWei, 256, 'paymasterInitialDepositWei');
    const [balance] = await callWords(rpc, entryPoint, 'balanceOf(address)', [paymaster], 1);
    if (balance < deposit) mismatch('paymaster_deposit', `>= ${deposit}`, balance.toString());

    const delay = uint(deployment.paymasterUnstakeDelaySeconds, 32, 'paymasterUnstakeDelaySeconds');
    for (const [field, target, key] of [['paymaster_stake', paymaster, 'paymasterStakeWei'], ['factory_stake', factory, 'factoryStakeWei']]) {
        const wanted = uint(deployment[key], 112, key);
        const [, staked, stake, unstakeDelay] = await callWords(rpc, entryPoint, 'getDepositInfo(address)', [target], 5);
        if (staked !== 1n || stake < wanted || unstakeDelay !== delay) {
            mismatch(field, { staked: true, stake: `>= ${wanted}`, unstakeDelaySec: delay.toString() },
                { staked: staked === 1n, stake: stake.toString(), unstakeDelaySec: unstakeDelay.toString() });
        }
    }

    const expectedPolicy = gasPolicyWords(deployment.paymasterGasPolicy);
    const actualPolicy = await callWords(rpc, paymaster, 'gasPolicy()', [], expectedPolicy.length);
    const names = [...[0, 1, 2, 3].map(k => `callFloor[${k}]`), ...[0, 1, 2, 3].map(k => `callCap[${k}]`), ...GAS_POLICY_SCALARS];
    for (let i = 0; i < names.length; i++) {
        if (actualPolicy[i] !== expectedPolicy[i]) mismatch(`paymaster_gas_policy.${names[i]}`, expectedPolicy[i].toString(), actualPolicy[i].toString());
    }

    const policy = deployment.paymasterPolicy ?? fail('missing paymasterPolicy');
    const [maxCost, flatFee, minEscapeNet, escapes, paused] = await callWords(rpc, paymaster, 'policy()', [], 5);
    const wantedPolicy = {
        maxSponsoredCostWei: uint(policy.maxSponsoredCostWei, 128, 'paymasterPolicy.maxSponsoredCostWei'),
        flatFeeWei: uint(policy.flatFeeWei, 64, 'paymasterPolicy.flatFeeWei'),
        minEscapeNetWei: uint(policy.minEscapeNetWei, 64, 'paymasterPolicy.minEscapeNetWei'),
        escapesEnabled: policy.escapesEnabled === true ? 1n : 0n,
    };
    const actual = { maxSponsoredCostWei: maxCost, flatFeeWei: flatFee, minEscapeNetWei: minEscapeNet, escapesEnabled: escapes };
    for (const [key, wanted] of Object.entries(wantedPolicy)) {
        if (actual[key] !== wanted) mismatch(`paymaster_policy.${key}`, wanted.toString(), actual[key].toString());
    }
    if (paused !== 0n) mismatch('paymaster_policy.sponsorshipPaused', 'false', 'true');

    const ceilings = deployment.paymasterFeeCeilings ?? fail('missing paymasterFeeCeilings');
    for (const [key, signature] of [['maxFeeWei', 'maxFeeCeiling()'], ['priorityFeeWei', 'priorityFeeCeiling()']]) {
        const wanted = uint(ceilings[key], 256, `paymasterFeeCeilings.${key}`);
        const [value] = await callWords(rpc, paymaster, signature, [], 1);
        if (value !== wanted) mismatch(`paymaster_fee_ceilings.${key}`, wanted.toString(), value.toString());
    }

    const keeper = address(deployment.paymasterFeeKeeper ?? `0x${'0'.repeat(40)}`, 'paymasterFeeKeeper');
    const [keeperWord] = await callWords(rpc, paymaster, 'feeKeeper()', [], 1);
    if (addressOf(keeperWord) !== keeper) mismatch('paymaster_fee_keeper', keeper, addressOf(keeperWord));

    const owner = address(deployment.paymasterOwner, 'paymasterOwner');
    const [ownerWord] = await callWords(rpc, paymaster, 'owner()', [], 1);
    const [pendingWord] = await callWords(rpc, paymaster, 'pendingOwner()', [], 1);
    const current = addressOf(ownerWord);
    const pending = addressOf(pendingWord);
    if (deployment.paymasterOwnershipTransferPending === true) {
        // Accepted meanwhile, or still nominated: both are the recorded owner.
        if (current !== owner && pending !== owner) mismatch('paymaster_owner', `${owner} (owner or pendingOwner)`, { owner: current, pendingOwner: pending });
    } else if (current !== owner) {
        mismatch('paymaster_owner', owner, current);
    }
}

/// forge's broadcast log of Deploy.s.sol on `chainId`, relative to the repository root.
export function defaultBroadcastLog(chainId) {
    return join(ROOT, 'demo/contracts/broadcast/Deploy.s.sol', String(chainId), 'run-latest.json');
}

/// Checks the broadcast of Deploy.s.sol's provisional manifest `deployment` on chain (see the
/// header) and returns { manifest, mismatches, expected }: `manifest` is the final deployment
/// manifest, present only when nothing mismatched. Throws when the deployment cannot be confirmed.
/// Creations are matched to the manifest's addresses through the log's receipts only: forge's
/// `transactions` entries can pair a hash with another creation's address.
export async function finalizeDeployment({ artifacts, deployment, broadcastLog, rpc, confirmations = 1 }) {
    if (deployment.deploymentStatus !== 'pending') {
        fail(`deploymentStatus is ${JSON.stringify(deployment.deploymentStatus ?? null)}: finalize takes the provisional manifest of a broadcast run ("pending"); a dry run deploys nothing`);
    }
    if (!('withdrawalPaymaster' in deployment)) {
        fail('the provisional manifest has no withdrawalPaymaster field (an address, or null with GASLESS=0): it was not written by the current Deploy.s.sol');
    }
    const gasless = hasGasless(deployment);
    const chainId = uint(deployment.chainId, 64, 'chainId');
    const rpcChain = quantity(await rpc('eth_chainId', []), 'eth_chainId');
    if (rpcChain !== chainId) fail(`the RPC serves chain ${rpcChain}, the manifest is for chain ${chainId}`);
    if (BigInt(broadcastLog?.chain ?? -1) !== chainId) fail(`the broadcast log is for chain ${broadcastLog?.chain}, not ${chainId}`);
    const lowerBound = uint(deployment.deployBlockLowerBound, 64, 'deployBlockLowerBound');

    const creations = { vault: deployment.vault, proofAdapter: deployment.proofAdapter };
    if (deployment.poseidonLibraryReused !== true) creations.poseidonLibrary = deployment.poseidonLibrary;
    if (gasless) creations.withdrawalPaymaster = deployment.withdrawalPaymaster;
    const transactions = {};
    const blocks = {};
    for (const [role, target] of Object.entries(creations)) {
        const at = address(target, role);
        const logged = (broadcastLog.receipts ?? []).filter(
            receipt => typeof receipt?.contractAddress === 'string' && receipt.contractAddress.toLowerCase() === at,
        );
        if (logged.length !== 1) {
            fail(`the broadcast log has ${logged.length} receipts creating the ${role} at ${target}; complete the broadcast (forge script --resume) or check the deployer's nonce`);
        }
        const hash = logged[0].transactionHash;
        const receipt = await rpc('eth_getTransactionReceipt', [hash]);
        if (!receipt) fail(`the ${role} creation ${hash} is not on chain (dropped or reorganized)`);
        if (quantity(receipt.status, `${role} receipt status`) !== 1n) fail(`the ${role} creation ${hash} failed on chain`);
        if (typeof receipt.contractAddress !== 'string' || receipt.contractAddress.toLowerCase() !== at) {
            fail(`the ${role} creation ${hash} created ${receipt.contractAddress}, not ${target}`);
        }
        const block = quantity(receipt.blockNumber, `${role} receipt blockNumber`);
        if (block <= lowerBound) fail(`the ${role} was created in block ${block}, not after the simulated head ${lowerBound}`);
        transactions[role] = hash;
        blocks[role] = block;
    }
    const deployBlock = blocks.vault;
    if (deployBlock > BigInt(Number.MAX_SAFE_INTEGER)) fail(`deployBlock ${deployBlock} is above 2^53 - 1`);
    // Confirmations count from the newest creation (nonce-ordered sends can land in later
    // blocks than the vault's), so every creation, and the state read at the head below, has at
    // least `confirmations`.
    const [newestRole, newestBlock] = Object.entries(blocks).reduce((newest, entry) => (entry[1] > newest[1] ? entry : newest));
    const latest = quantity(await rpc('eth_blockNumber', []), 'eth_blockNumber');
    const seen = latest >= newestBlock ? latest - newestBlock + 1n : 0n;
    if (seen < BigInt(confirmations)) {
        fail(`the ${newestRole}'s creation (block ${newestBlock}) has ${seen} confirmations, ${confirmations} required: finalize again later`);
    }

    const { expected, mismatches } = await auditDeployment({ artifacts, deployment, check: true, rpc });
    // The codehashes cover the code and every immutable; owner and treasury are storage.
    for (const field of ['owner', 'treasury']) {
        const word = await rpc('eth_call', [{ to: address(deployment.vault, 'vault'), data: selector(`${field}()`) }, 'latest']);
        if (typeof word !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(word)) fail(`${field}(): unexpected return ${word}`);
        const actual = `0x${word.slice(-40)}`.toLowerCase();
        const wanted = address(deployment[field], field);
        if (actual !== wanted || BigInt(word) >> 160n !== 0n) mismatches.push({ source: 'rpc', field, expected: wanted, actual: word });
    }
    // The paymaster's deposit, stakes, policy and owner are storage of the paymaster and the
    // EntryPoint; the factory and the account logic have no state of their own.
    if (gasless) await checkPaymasterState(rpc, deployment, mismatches);
    if (mismatches.length) return { mismatches, expected };
    const manifest = {
        ...deployment,
        deploymentStatus: 'deployed',
        deployBlock: Number(deployBlock),
        deployTransactions: transactions,
    };
    return { manifest, mismatches, expected };
}

// ------------------------------------------------------------------------------------- CLI

const FLAGS = {
    '--poseidon': 'poseidonLibrary',
    '--proof-adapter': 'proofAdapter',
    '--note-ttl': 'noteTtl',
    '--challenge-period': 'challengePeriod',
    '--max-pause-duration': 'maxPauseDuration',
    '--request-charge-cap': 'requestChargeCap',
    '--state-key-x': 'stateSigningKeyX',
    '--state-key-y': 'stateSigningKeyY',
    '--clearance-key-x': 'clearanceSigningKeyX',
    '--clearance-key-y': 'clearanceSigningKeyY',
    '--vault': 'vault',
    '--entry-point': 'entryPoint',
    '--paymaster': 'withdrawalPaymaster',
    '--factory': 'withdrawalAccountFactory',
    '--account-implementation': 'withdrawalAccountImplementation',
    '--wei-per-unit': 'nativeAssetWeiPerUnit',
    '--creation-code-keccak': 'accountCreationCodeKeccak256',
};

function parseArgs(argv) {
    const args = { artifacts: join(ROOT, 'protocol/contracts/out'), inputs: {}, check: false, confirmations: 1 };
    for (let i = 0; i < argv.length; i++) {
        const flag = argv[i];
        const next = () => argv[++i] ?? fail(`${flag} needs a value`);
        if (flag === '--artifacts') args.artifacts = resolve(next());
        else if (flag === '--deployment') args.deployment = resolve(next());
        else if (flag === '--rpc') args.rpc = next();
        else if (flag === '--check') args.check = true;
        else if (flag === '--finalize') args.finalize = resolve(next());
        else if (flag === '--broadcast-log') args.broadcastLog = resolve(next());
        else if (flag === '--confirmations') args.confirmations = Number(uint(next(), 32, '--confirmations'));
        else if (FLAGS[flag]) args.inputs[FLAGS[flag]] = next();
        else fail(`unknown argument ${flag}`);
    }
    return args;
}

const printable = (key, value) => (typeof value === 'bigint' ? value.toString() : value);

async function main() {
    const args = parseArgs(process.argv.slice(2));
    const deployment = args.deployment ? parseDeployment(readFileSync(args.deployment, 'utf8')) : {};
    if (args.check && !args.deployment) fail('--check needs --deployment');
    if (args.finalize) {
        if (!args.deployment || !args.rpc) fail('--finalize needs --deployment (the provisional manifest) and --rpc');
        if (Object.keys(args.inputs).length) fail('--finalize takes every input from the manifest');
        if (args.finalize === args.deployment) fail('--finalize writes a new file; keep the provisional manifest');
        const logPath = args.broadcastLog ?? defaultBroadcastLog(deployment.chainId);
        if (!existsSync(logPath)) fail(`no broadcast log at ${logPath} (pass --broadcast-log)`);
        const broadcastLog = JSON.parse(readFileSync(logPath, 'utf8'));
        const { manifest, mismatches, expected } = await finalizeDeployment({
            artifacts: args.artifacts,
            deployment,
            broadcastLog,
            rpc: jsonRpc(args.rpc),
            confirmations: args.confirmations,
        });
        const report = { artifacts: args.artifacts, broadcastLog: logPath, ...expected, mismatches };
        if (manifest) {
            const temporary = `${args.finalize}.tmp`;
            writeFileSync(temporary, `${JSON.stringify(manifest, printable, 2)}\n`);
            renameSync(temporary, args.finalize);
            Object.assign(report, { finalized: args.finalize, deployBlock: manifest.deployBlock, deployTransactions: manifest.deployTransactions });
        }
        console.log(JSON.stringify(report, printable, 2));
        if (mismatches.length) process.exit(1);
        return;
    }
    const { inputs, expected, mismatches } = await auditDeployment({
        artifacts: args.artifacts,
        deployment,
        overrides: args.inputs,
        check: args.check,
        rpc: args.rpc ? jsonRpc(args.rpc) : null,
    });
    const report = { artifacts: args.artifacts, inputs, ...expected };
    if (args.check || args.rpc) report.mismatches = mismatches;
    console.log(JSON.stringify(report, printable, 2));
    if (mismatches.length) process.exit(1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch(error => {
        console.error(`expected-codehashes: ${error.message}`);
        process.exit(2);
    });
}
