// examples/sample-host (design §10.5): one origin serves the legacy
// note-bound build at /zkapi/ and the concession build at /zkapi/v2c/, and a
// host loader import()s the legacy entry while a legacy runtime holds an open
// note. The build test installs both packages the way npm would
// (node_modules/zkapi-sdk and node_modules/zkapi-sdk-legacy), builds the
// sample host, and runs its bundled loader over a shared wallet store.
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { deployedProfile } from './helpers/deployed-profile.mjs';
import { memoryIndexedDb } from './helpers/request-archive-harness.mjs';
import { chooseZkapiBuild, loadZkapi } from '../../examples/sample-host/src/loader.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const hostSource = path.join(repoRoot, 'examples/sample-host');
// The revision release/v2-note-bound is cut at: the legacy build's package.
const LEGACY_REVISION = 'ac9be63';
const LEGACY_DEPLOYMENT = 'zkapi-native-eth-sepolia-note-bound-v1-fresh-20260930';
const CURRENT_DEPLOYMENT = 'zkapi-test-sepolia-concession';
const BUILDS = Object.freeze({
    legacy: { deploymentId: LEGACY_DEPLOYMENT, circuitId: 'zkapi-v2-note-bound-v1', publicPath: '/zkapi/',
        configUrl: '/zkapi/browser-config.json', workerUrl: '/zkapi/assets/zkapiWasmWorker.js' },
    current: { deploymentId: CURRENT_DEPLOYMENT, circuitId: 'zkapi-v2-concession-v1', publicPath: '/zkapi/v2c/',
        configUrl: '/zkapi/v2c/browser-config.json', workerUrl: '/zkapi/v2c/assets/zkapiWasmWorker.js' }
});
const holding = (deploymentId, runtime, withdrawals = []) => ({ deploymentId, runtime, withdrawals });

test('the loader picks the legacy build only while a legacy runtime holds a note', () => {
    assert.deepEqual(chooseZkapiBuild([], BUILDS), { build: 'current', reason: 'no_runtime_note', legacyOpen: [] });
    assert.equal(chooseZkapiBuild([holding(LEGACY_DEPLOYMENT, true)], BUILDS).build, 'legacy');
    assert.equal(chooseZkapiBuild([holding(CURRENT_DEPLOYMENT, true), holding(LEGACY_DEPLOYMENT, false,
        [{ noteId: 3, mode: 'escape', phase: 'pending' }])], BUILDS).reason, 'current_runtime_holds_note');
    // A legacy escape still pending with no note in the runtime slot: the
    // current build loads, and the host can offer the legacy one to finish it.
    const pending = chooseZkapiBuild([holding(LEGACY_DEPLOYMENT, false, [{ noteId: 3, mode: 'escape', phase: 'pending' }])],
        BUILDS);
    assert.deepEqual(pending, { build: 'current', reason: 'no_runtime_note',
        legacyOpen: [{ noteId: 3, mode: 'escape', phase: 'pending' }] });
    assert.equal(chooseZkapiBuild([holding(LEGACY_DEPLOYMENT, false, pending.legacyOpen)], BUILDS,
        { prefer: 'legacy' }).reason, 'requested');
    assert.throws(() => chooseZkapiBuild([holding(CURRENT_DEPLOYMENT, true)], BUILDS, { prefer: 'legacy' }),
        { code: 'legacy_build_blocked' });
    assert.equal(chooseZkapiBuild([holding('zkapi-older', true)], BUILDS).reason, 'other_deployment_runtime');
    assert.throws(() => chooseZkapiBuild([], { ...BUILDS, legacy: BUILDS.current }), /different deployments/);
});

test('loadZkapi points the chosen package at its own assets', async () => {
    const configured = [];
    const loaded = await loadZkapi(BUILDS, {
        readHoldings: async () => [holding(LEGACY_DEPLOYMENT, true)],
        importBuild: async build => ({ build, configureBrowserSdk: options => configured.push(options) })
    });
    assert.equal(loaded.sdk.build, 'legacy');
    assert.deepEqual(configured, [{ configUrl: '/zkapi/browser-config.json', workerUrl: '/zkapi/assets/zkapiWasmWorker.js' }]);
    assert.equal(loaded.deployment, BUILDS.legacy);
});

function hasRevision(revision) {
    try {
        execFileSync('git', ['-C', repoRoot, 'cat-file', '-e', `${revision}^{commit}`], { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

/** This package with a deployed profile: its shipped profiles are placeholders. */
async function currentPackage(directory) {
    await fs.mkdir(directory, { recursive: true });
    await fs.copyFile(path.join(repoRoot, 'package.json'), path.join(directory, 'package.json'));
    const tests = path.join(repoRoot, 'sdk/test');
    await fs.cp(path.join(repoRoot, 'sdk'), path.join(directory, 'sdk'), {
        recursive: true, filter: entry => entry !== tests && !entry.startsWith(`${tests}${path.sep}`)
    });
    await fs.writeFile(path.join(directory, 'sdk/assets/config/sepolia.json'),
        `${JSON.stringify(deployedProfile('sepolia'), null, 2)}\n`);
    const manifestFile = path.join(directory, 'sdk/assets/manifest.json');
    const manifest = JSON.parse(await fs.readFile(manifestFile, 'utf8'));
    for (const relative of Object.keys(manifest.files)) {
        manifest.files[relative] = sha256(await fs.readFile(path.join(directory, 'sdk', relative)));
    }
    await fs.writeFile(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
}

/** The legacy build's package as release/v2-note-bound publishes it. */
async function legacyPackage(directory) {
    await fs.mkdir(directory, { recursive: true });
    execFileSync('sh', ['-c', 'git -C "$1" archive --format=tar "$2" package.json sdk | tar -x -C "$3" --exclude sdk/test',
        'sh', repoRoot, LEGACY_REVISION, directory]);
}

test('the sample host builds both deployments side by side and its bundle loads the right SDK', {
    skip: hasRevision(LEGACY_REVISION) ? false : `needs git history for ${LEGACY_REVISION} (release/v2-note-bound)`
}, async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-sample-host-'));
    const saved = Object.fromEntries(['indexedDB', 'window', 'localStorage', 'location']
        .map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
    try {
        // npm's layout for the two package entries.
        const host = path.join(temp, 'host');
        await fs.cp(hostSource, host, { recursive: true, filter: entry => !path.relative(hostSource, entry).split(path.sep)
            .some(part => part === 'node_modules' || part === 'dist') });
        await currentPackage(path.join(temp, 'packages/current'));
        await legacyPackage(path.join(temp, 'packages/legacy'));
        await fs.mkdir(path.join(host, 'node_modules'), { recursive: true });
        await fs.symlink(path.join(temp, 'packages/current'), path.join(host, 'node_modules/zkapi-sdk'), 'dir');
        await fs.symlink(path.join(temp, 'packages/legacy'), path.join(host, 'node_modules/zkapi-sdk-legacy'), 'dir');
        await fs.symlink(path.join(repoRoot, 'node_modules/esbuild'), path.join(host, 'node_modules/esbuild'), 'dir');

        const { buildSampleHost } = await import(pathToFileURL(path.join(host, 'build.mjs')).href);
        const out = path.join(temp, 'dist');
        const { builds } = await buildSampleHost({ outDir: out });
        assert.deepEqual(builds, BUILDS);
        assert.deepEqual(JSON.parse(await fs.readFile(path.join(out, 'zkapi-builds.json'), 'utf8')), BUILDS);

        // Each package published its own pinned WebAssembly, keys and worker
        // under its own publicPath.
        const legacyManifest = JSON.parse(await fs.readFile(path.join(temp, 'packages/legacy/sdk/assets/manifest.json'), 'utf8'));
        const currentManifest = JSON.parse(await fs.readFile(path.join(temp, 'packages/current/sdk/assets/manifest.json'), 'utf8'));
        const served = async relative => sha256(await fs.readFile(path.join(out, relative)));
        assert.equal(await served('zkapi/wasm/zkapi_browser_bg.wasm'), legacyManifest.files['wasm/zkapi_browser_bg.wasm']);
        assert.equal(await served('zkapi/v2c/wasm/zkapi_browser_bg.wasm'), currentManifest.files['wasm/zkapi_browser_bg.wasm']);
        assert.notEqual(legacyManifest.files['wasm/zkapi_browser_bg.wasm'], currentManifest.files['wasm/zkapi_browser_bg.wasm']);
        for (const key of ['request.pk', 'withdrawal.pk']) {
            assert.equal(await served(`zkapi/proofs/${key}`), legacyManifest.files[`assets/proofs/${key}`]);
            assert.equal(await served(`zkapi/v2c/proofs/${key}`), currentManifest.files[`assets/proofs/${key}`]);
        }
        const assets = async relative => JSON.parse(await fs.readFile(path.join(out, relative), 'utf8'));
        assert.equal((await assets('zkapi/sdk-assets.json')).circuitId, 'zkapi-v2-note-bound-v1');
        const currentAssets = await assets('zkapi/v2c/sdk-assets.json');
        assert.deepEqual([currentAssets.circuitId, currentAssets.publicPath], ['zkapi-v2-concession-v1', '/zkapi/v2c/']);
        // Each worker bundles its own package's ../wasm/zkapi_browser.js glue.
        const legacyWorker = await fs.readFile(path.join(out, 'zkapi/assets/zkapiWasmWorker.js'), 'utf8');
        const currentWorker = await fs.readFile(path.join(out, 'zkapi/v2c/assets/zkapiWasmWorker.js'), 'utf8');
        assert.match(currentWorker, /browser_check_unrecoverable_response/);
        assert.doesNotMatch(legacyWorker, /browser_check_unrecoverable_response/);
        assert.ok((await fs.stat(path.join(out, 'index.html'))).isFile());
        // The app reaches each package entry only through import(): two chunks,
        // and a page fetches one of them.
        const chunks = [...(await fs.readFile(path.join(out, 'app/app.js'), 'utf8'))
            .matchAll(/import\("\.\/(chunks\/[^"]+)"\)/g)].map(match => match[1]);
        assert.equal(new Set(chunks).size, 2, 'each package entry is its own chunk');
        const exitKitChunks = await Promise.all(chunks.map(async chunk =>
            (await fs.readFile(path.join(out, 'app', chunk), 'utf8')).includes('zkapi-exit-kit-v1')));
        assert.deepEqual(exitKitChunks.sort(), [false, true]);

        // The bundled loader over one shared store.
        globalThis.indexedDB = memoryIndexedDb();
        globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
        globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
        globalThis.location = { href: 'https://host.example/', hostname: 'host.example' };
        const app = await import(pathToFileURL(path.join(out, 'app/app.js')).href);
        const legacyStore = await import(pathToFileURL(
            path.join(temp, 'packages/legacy/sdk/services/browserWalletStore.js')).href);
        const currentStore = await import(pathToFileURL(
            path.join(temp, 'packages/current/sdk/services/browserWalletStore.js')).href);
        const note = (contractAddress, noteId) => ({ protocol_version: 2, chain_id: 11155111, contract_address: contractAddress,
            note_id: noteId, secret_s: '0x5', deposit_amount: 1_000_000, expiry_ts: 2_000_000_000, current_balance: 1_000_000,
            balance_blinding: '0x1', current_commitment_x: '0x2', current_commitment_y: '0x3', current_anchor: '0x1',
            is_genesis: true, state_signature: null });

        const empty = await app.startZkapi();
        assert.deepEqual([empty.build, empty.reason], ['current', 'no_runtime_note']);
        assert.equal(typeof empty.sdk.browserWalletRuntime.exportExitKit, 'function', 'the concession SDK chunk');
        assert.equal(empty.sdk.configureBrowserSdk().configUrl, 'https://host.example/zkapi/v2c/browser-config.json');

        await legacyStore.writeBrowserWallet({ deploymentId: LEGACY_DEPLOYMENT, billingAsset: 'native_eth',
            state: note(`0x${'49'.repeat(20)}`, 7) });
        const legacy = await app.startZkapi();
        assert.deepEqual([legacy.build, legacy.reason], ['legacy', 'legacy_runtime_holds_note']);
        assert.equal(legacy.sdk.browserWalletRuntime.exportExitKit, undefined, 'the note-bound SDK chunk');
        assert.equal(legacy.sdk.configureBrowserSdk().workerUrl, 'https://host.example/zkapi/assets/zkapiWasmWorker.js');
        assert.notEqual(legacy.sdk.browserWalletRuntime, empty.sdk.browserWalletRuntime);

        // The legacy note closed and its escape pending; a new note in the
        // current build's runtime: the legacy build cannot load over it.
        indexedDB.clear();
        await legacyStore.putBrowserWithdrawal({ recordId: `${LEGACY_DEPLOYMENT}:7`, deploymentId: LEGACY_DEPLOYMENT,
            noteId: 7, mode: 'escape', phase: 'pending', state: note(`0x${'49'.repeat(20)}`, 7) });
        await currentStore.writeBrowserWallet({ deploymentId: CURRENT_DEPLOYMENT, billingAsset: 'native_eth',
            state: note(`0x${'22'.repeat(20)}`, 1) });
        const current = await app.startZkapi();
        assert.deepEqual([current.build, current.reason, current.legacyOpen.map(entry => entry.noteId)],
            ['current', 'current_runtime_holds_note', [7]]);
        await assert.rejects(app.startZkapi({ prefer: 'legacy' }), { code: 'legacy_build_blocked' });
    } finally {
        for (const [name, descriptor] of Object.entries(saved)) {
            if (descriptor) Object.defineProperty(globalThis, name, descriptor);
            else delete globalThis[name];
        }
        await fs.rm(temp, { recursive: true, force: true });
    }
});
