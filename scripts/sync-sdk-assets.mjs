// Copy a proof setup's keys into the SDK and record the artifact provenance in
// sdk/assets/manifest.json (schema 2). scripts/build-browser-client.sh runs it
// after building sdk/wasm/.
//
//   node scripts/sync-sdk-assets.mjs --setup dev|mpc-1 [--network sepolia|mainnet ...]
//   node scripts/sync-sdk-assets.mjs --check
//
// Deployed profiles (every one, or those named by --network) must pin exactly
// the setup's circuit, setup id and key hashes, or nothing is written.
// Placeholder profiles (deployment_status "not_deployed") are skipped: they
// pin no deployment.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    ASSET_MANIFEST_FILES, ASSET_MANIFEST_SCHEMA, BUNDLE_SETUP_IDS, NETWORKS, REQUIRED_CIRCUIT_ID,
    readBundleIdentity, verifyBrowserSdkAssets
} from '../sdk/build.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SETUP_DIRECTORIES = { dev: 'protocol/setup/v2-concession-dev', 'mpc-1': 'protocol/setup/v2-concession' };
const KEY_FILES = ['request.pk', 'withdrawal.pk', 'request.vk'];
// The inputs of the WebAssembly build: sourceRevision must describe them.
const WASM_SOURCES = ['protocol/rust', 'rust-toolchain.toml', 'scripts/build-browser-client.sh'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();

function options(argv) {
    const result = { check: false, setup: null, networks: [] };
    for (let index = 0; index < argv.length; index += 1) {
        const flag = argv[index];
        if (flag === '--check') result.check = true;
        else if (flag === '--setup') result.setup = argv[++index];
        else if (flag === '--network') result.networks.push(argv[++index]);
        else throw new Error(`Unknown option ${flag}.`);
    }
    if (!result.check && !BUNDLE_SETUP_IDS.includes(result.setup)) {
        throw new Error(`--setup must be one of ${BUNDLE_SETUP_IDS.join(', ')}.`);
    }
    for (const network of result.networks) {
        if (!NETWORKS.includes(network)) throw new Error(`Unknown network ${network}.`);
    }
    return result;
}

// The pins scripts/build-browser-client.sh enforces, recorded for rebuilders.
async function toolchain() {
    const channel = /^channel\s*=\s*"([^"]+)"/m.exec(await fs.readFile(path.join(root, 'rust-toolchain.toml'), 'utf8'));
    const bindgen = /REQUIRED_WASM_BINDGEN="([^"]+)"/.exec(
        await fs.readFile(path.join(root, 'scripts/build-browser-client.sh'), 'utf8'));
    if (!channel || !bindgen) throw new Error('Cannot read the pinned Rust and wasm-bindgen versions.');
    return { rustc: channel[1], wasmBindgen: bindgen[1] };
}

async function readJson(relative) {
    return JSON.parse(await fs.readFile(path.join(root, relative), 'utf8'));
}

async function sync({ setup: setupId, networks }) {
    const setupDirectory = SETUP_DIRECTORIES[setupId];
    const setup = await readJson(`${setupDirectory}/manifest.json`);
    if (setup.circuit_id !== REQUIRED_CIRCUIT_ID || setup.setup_id !== setupId || setup.reduction !== 'circom') {
        throw new Error(`${setupDirectory} is not a ${REQUIRED_CIRCUIT_ID} ${setupId} setup with the circom reduction.`);
    }
    const keys = {};
    for (const file of KEY_FILES) {
        const bytes = await fs.readFile(path.join(root, setupDirectory, file));
        if (sha256(bytes) !== setup.files?.[file]) {
            throw new Error(`${setupDirectory}/${file} does not match its setup manifest.`);
        }
        keys[file] = { bytes, sha256: sha256(bytes) };
    }
    const pins = {
        circuit_id: setup.circuit_id,
        setup_id: setup.setup_id,
        request_proving_key_sha256: keys['request.pk'].sha256,
        withdrawal_proving_key_sha256: keys['withdrawal.pk'].sha256,
        request_verifying_key_sha256: keys['request.vk'].sha256,
        request_vk_keccak256: setup.vk_keccak256.request,
        withdrawal_vk_keccak256: setup.vk_keccak256.withdrawal
    };
    for (const network of networks.length ? networks : NETWORKS) {
        const trusted = (await readJson(`sdk/assets/config/${network}.json`)).trusted_deployment || {};
        if (trusted.deployment_status === 'not_deployed') {
            console.log(`Skipped the ${network} placeholder profile (not_deployed).`);
            continue;
        }
        for (const [field, expected] of Object.entries(pins)) {
            if (String(trusted[field] ?? '').toLowerCase() !== String(expected).toLowerCase()) {
                throw new Error(`The ${network} profile pins ${field} ${trusted[field]}, the ${setupId} setup has `
                    + `${expected}; no asset manifest was updated.`);
            }
        }
    }
    const bundle = await readBundleIdentity(path.join(root, 'sdk'));
    if (bundle.circuitId !== REQUIRED_CIRCUIT_ID || bundle.setupId !== setupId) {
        throw new Error(`sdk/wasm is built for ${bundle.circuitId}/${bundle.setupId}, not ${REQUIRED_CIRCUIT_ID}/${setupId}: `
            + `run scripts/build-browser-client.sh --setup ${setupId}.`);
    }
    if (git('status', '--porcelain', '--', ...WASM_SOURCES)) {
        throw new Error(`Commit the WebAssembly sources (${WASM_SOURCES.join(', ')}) first: `
            + 'sourceRevision must name the revision the bundle was built from.');
    }
    for (const file of KEY_FILES) {
        await fs.writeFile(path.join(root, 'sdk/assets/proofs', file), keys[file].bytes);
    }
    const files = {};
    for (const relative of ASSET_MANIFEST_FILES) {
        files[relative] = sha256(await fs.readFile(path.join(root, 'sdk', relative)));
    }
    const manifest = {
        schema: ASSET_MANIFEST_SCHEMA,
        circuitId: setup.circuit_id,
        setupId: setup.setup_id,
        sourceRevision: git('rev-parse', 'HEAD'),
        toolchain: await toolchain(),
        vkKeccak256: { request: pins.request_vk_keccak256, withdrawal: pins.withdrawal_vk_keccak256 },
        files
    };
    await fs.writeFile(path.join(root, 'sdk/assets/manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    console.log('Updated SDK artifact provenance; review and commit the generated changes.');
}

const parsed = options(process.argv.slice(2));
if (parsed.check) {
    const manifest = await verifyBrowserSdkAssets();
    console.log(`SDK public artifact hashes verified (${manifest.circuitId}, setup ${manifest.setupId}).`);
} else {
    await sync(parsed);
}
