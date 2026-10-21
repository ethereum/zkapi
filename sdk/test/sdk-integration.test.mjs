import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { buildBrowserSdkAssets, verifyBrowserSdkAssets } from '../build.mjs';
import { configureBrowserSdk, browserSdkOptions, browserSdkTransport, beginBrowserSdkInitialization } from '../configure.js';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { deployedProfile } from './helpers/deployed-profile.mjs';

test('SDK imports without a host UI, codec global, wallet connection or network request', async () => {
    assert.equal(globalThis.zkapiWallet, undefined);
    const sdk = await import('../index.js');
    assert.equal(typeof sdk.zkapiClient.init, 'function');
    assert.equal(sdk.zkapiClient.initialized, false);
    assert.equal(sdk.browserWalletRuntime.worker, null);
    assert.deepEqual(sdk.CHAT_SPENDING_TIER_USD, [1, 2, 3, 4.5, 6]);
});

test('transport omits account credentials for both direct and opt-in host proxy requests', async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (...args) => { calls.push(args); return new Response('{}'); };
    try {
        const init = { method: 'POST', credentials: 'include', body: 'public-proof', headers: { 'x-test': 'value' } };
        await browserSdkTransport('https://service.example/leases', init, { preferProxy: true });
        assert.equal(calls[0][1].credentials, 'omit');
        assert.equal(init.credentials, 'include');
        const hints = { preferProxy: true };
        configureBrowserSdk({ transport: async (...args) => { calls.push(args); return new Response('{}'); } });
        await browserSdkTransport('https://service.example/leases', init, hints);
        assert.deepEqual(calls[1][1], { ...init, credentials: 'omit' });
        assert.equal(calls[1][1].body, init.body);
        assert.equal(calls[1][1].headers, init.headers);
        assert.equal(calls[1][2], hints);
    } finally {
        globalThis.fetch = originalFetch;
        configureBrowserSdk({ transport: null });
    }
});

test('host configuration resolves explicit paths and retains trusted same-origin proxy routing', async () => {
    const originalLocation = globalThis.location;
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.location = { href: 'https://host.example/chat/', origin: 'https://host.example' };
    globalThis.fetch = async (...args) => { calls.push(args); return new Response('{}'); };
    try {
        configureBrowserSdk({ configUrl: '/zkapi/browser-config.json', workerUrl: '/zkapi/assets/zkapiWasmWorker.js' });
        const runtime = new BrowserWalletRuntime();
        await runtime.loadBrowserConfig();
        assert.equal(calls[0][0], 'https://host.example/zkapi/browser-config.json');
        assert.equal(calls[0][1].credentials, 'omit');
        const config = deployedProfile();
        runtime.browserConfig = config;
        await runtime.remoteFetch(config.trusted_deployment.protocol_server_url + '/v2/requests', { method: 'POST', body: '{"proof":"private-proof"}', credentials: 'include' });
        assert.equal(calls[1][0], 'https://host.example/zkapi-deployment/v2/requests');
        assert.equal(calls[1][1].credentials, 'omit');
        assert.equal(calls[1][1].body, '{"proof":"private-proof"}');
        await runtime.directJson(config.deployment_manifest_url);
        assert.equal(calls[2][1].credentials, 'omit');
        globalThis.fetch = async (...args) => { calls.push(args); return calls.length === 4 ? new Response('', {status:404}) : new Response('{}'); };
        await runtime.remoteFetch(config.trusted_deployment.protocol_server_url + '/v2/requests', { credentials: 'include', body: 'proof', method: 'POST' });
        assert.equal(calls[3][1].credentials, 'omit');
        assert.equal(calls[4][1].credentials, 'omit');
        assert.equal(browserSdkOptions().workerUrl, 'https://host.example/zkapi/assets/zkapiWasmWorker.js');
        const manifest = { ...config.trusted_deployment, privacy_mode: { openrouter_inference_base: 'https://openrouter.ai/api/v1' } };
        assert.equal(runtime.buildClientConfig(manifest, config).proving_keys.request.url, 'https://host.example/zkapi/proofs/request.pk');
    } finally {
        globalThis.location = originalLocation;
        globalThis.fetch = originalFetch;
    }
});

test('the shipped network profiles are placeholders that no host build accepts', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-sdk-assets-'));
    try {
        const pinned = await verifyBrowserSdkAssets();
        assert.equal(pinned.schema, 2);
        assert.equal(pinned.circuitId, 'zkapi-v2-concession-v1');
        for (const network of ['sepolia', 'mainnet']) {
            await assert.rejects(buildBrowserSdkAssets({ outDir: path.join(temp, network), network, build }),
                { code: 'deployment_not_deployed' });
            await assert.rejects(fs.access(path.join(temp, network)), 'nothing was written');
        }
        await assert.rejects(buildBrowserSdkAssets({outDir: temp, network: 'invalid', build}), /Network/);
        await assert.rejects(buildBrowserSdkAssets({outDir: temp, publicPath: '//other.example/', build}), /same-origin/);
    } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

// A copy of the package whose profile pins a deployed vault: build.mjs reads
// the profiles, keys and WebAssembly next to itself, so a host build of a
// deployed profile is tested on a copy with that profile and a rehashed
// manifest, never by letting a caller inject a profile.
async function packageCopy(temp) {
    const source = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
    const copy = path.join(temp, 'package', 'sdk');
    const tests = path.join(source, 'test');
    await fs.cp(source, copy, { recursive: true, filter: entry => entry !== tests && !entry.startsWith(`${tests}${path.sep}`) });
    const sha256 = async relative => crypto.createHash('sha256').update(await fs.readFile(path.join(copy, relative))).digest('hex');
    const manifestFile = path.join(copy, 'assets/manifest.json');
    const rewrite = async ({ profiles = {}, manifest = {} } = {}) => {
        for (const [network, profile] of Object.entries(profiles)) {
            await fs.writeFile(path.join(copy, `assets/config/${network}.json`), `${JSON.stringify(profile, null, 2)}\n`);
        }
        const current = JSON.parse(await fs.readFile(manifestFile, 'utf8'));
        for (const relative of Object.keys(current.files)) current.files[relative] = await sha256(relative);
        await fs.writeFile(manifestFile, `${JSON.stringify({ ...current, ...manifest }, null, 2)}\n`);
    };
    const module = await import(`${pathToFileURL(path.join(copy, 'build.mjs')).href}?copy=${Date.now()}${Math.random()}`);
    return { copy, rewrite, module };
}

test('a deployed profile builds under the new publicPath with its pinned keys, request.vk and setup', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-sdk-assets-'));
    try {
        const pinned = await verifyBrowserSdkAssets();
        const { rewrite, module } = await packageCopy(temp);
        await rewrite({ profiles: { sepolia: deployedProfile('sepolia') } });
        const result = await module.buildBrowserSdkAssets({ outDir: path.join(temp, 'out'), network: 'sepolia', build });
        assert.equal(result.configUrl, '/zkapi/v2c/browser-config.json', 'new keys are served under a new path');
        assert.equal(result.workerUrl, '/zkapi/v2c/assets/zkapiWasmWorker.js');
        assert.equal(result.config.trusted_deployment.chain_id, 11155111);
        assert.equal(result.config.trusted_deployment.setup_id, pinned.setupId);
        for (const file of ['request.pk', 'withdrawal.pk', 'request.vk']) {
            assert.equal(result.files[`proofs/${file}`], pinned.files[`assets/proofs/${file}`], file);
        }
        assert.equal(result.files['wasm/zkapi_browser_bg.wasm'], pinned.files['wasm/zkapi_browser_bg.wasm']);
        const sdkAssets = JSON.parse(await fs.readFile(path.join(temp, 'out/sdk-assets.json'), 'utf8'));
        assert.deepEqual({ schema: sdkAssets.schema, circuitId: sdkAssets.circuitId, setupId: sdkAssets.setupId,
            publicPath: sdkAssets.publicPath, sourceRevision: sdkAssets.sourceRevision },
        { schema: 2, circuitId: 'zkapi-v2-concession-v1', setupId: pinned.setupId, publicPath: '/zkapi/v2c/',
            sourceRevision: pinned.sourceRevision });
        const worker = await fs.readFile(path.join(result.directory, 'assets/zkapiWasmWorker.js'), 'utf8');
        assert.match(worker, /\.\.\/wasm\/zkapi_browser_bg\.wasm/);
        assert.doesNotMatch(worker, /ChatApp|funding-page|networkProxy/);
        const custom = await module.buildBrowserSdkAssets({ outDir: path.join(temp, 'custom'), network: 'sepolia',
            publicPath: '/chat/zkapi/v2c/', build });
        assert.equal(custom.configUrl, '/chat/zkapi/v2c/browser-config.json');
    } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

test('host builds refuse a profile of another setup and unpinned keys, and build a single-party mainnet', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-sdk-assets-'));
    try {
        const { rewrite, module } = await packageCopy(temp);
        const out = name => path.join(temp, name);
        const attempt = async (network, profile, name) => {
            await rewrite({ profiles: { [network]: profile } });
            return module.buildBrowserSdkAssets({ outDir: out(name), network, build });
        };
        const sepolia = changes => deployedProfile('sepolia', changes);
        await assert.rejects(attempt('sepolia', sepolia({ setup_id: 'mpc-1' }), 'setup'), { code: 'setup_mismatch' });
        await assert.rejects(attempt('sepolia', sepolia({ circuit_id: 'zkapi-v2-note-bound-v1' }), 'circuit'),
            { code: 'incompatible_proof_circuit' });
        await assert.rejects(attempt('sepolia', sepolia({ exit_concession: undefined }), 'revision'),
            { code: 'exit_concession_required' });
        await assert.rejects(attempt('sepolia', sepolia({ request_verifying_key_sha256: '0'.repeat(64) }), 'vk'),
            /request\.vk does not match/);
        await assert.rejects(attempt('sepolia', sepolia({ withdrawal_proving_key_sha256: '0'.repeat(64) }), 'pk'),
            /withdrawal\.pk does not match/);
        // A single-party mainnet vault (deployed with ALLOW_DEV_SETUP=1) builds like any other
        // network: its profile pins the bundle's setup.
        const mainnet = await attempt('mainnet', deployedProfile('mainnet'), 'mainnet');
        await fs.access(mainnet.directory);
        // A manifest that relabels the bundle's setup is refused: the
        // WebAssembly itself reports the setup it was built for.
        await rewrite({ profiles: { sepolia: sepolia({ setup_id: 'mpc-1' }) }, manifest: { setupId: 'mpc-1' } });
        await assert.rejects(module.verifyBrowserSdkAssets(), { code: 'setup_mismatch' });
        await assert.rejects(module.buildBrowserSdkAssets({ outDir: out('relabelled'), network: 'sepolia', build }),
            { code: 'setup_mismatch' });
        for (const name of ['setup', 'circuit', 'revision', 'vk', 'pk', 'relabelled']) {
            await assert.rejects(fs.access(out(name)), `${name}: nothing was written`);
        }
        // A deployed profile may say so, as the finalized manifest, serverd,
        // clientd and scripts/deployment-profile.mjs do; any other status is
        // refused.
        await rewrite({ profiles: { sepolia: sepolia({ deployment_status: 'pending' }) }, manifest: { setupId: 'dev' } });
        await assert.rejects(module.buildBrowserSdkAssets({ outDir: out('pending'), network: 'sepolia', build }),
            /unknown deployment_status/);
        await rewrite({ profiles: { sepolia: sepolia({ deployment_status: 'deployed' }) }, manifest: { setupId: 'dev' } });
        const deployed = await module.buildBrowserSdkAssets({ outDir: out('deployed'), network: 'sepolia', build });
        await fs.access(deployed.directory);
    } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

test('SDK rejects unsupported options and cannot change its trust/transport configuration after initialization begins', () => {
    for (const mode of ['invalid', 'auto', 'daemon']) {
        assert.throws(() => configureBrowserSdk({ mode }), /Only browser mode is supported/);
    }
    assert.throws(() => configureBrowserSdk({ transport: {} }), /transport/);
    assert.throws(() => configureBrowserSdk({ configUrl: 'https://user:secret@example.com/config' }), /credentials/);
    assert.throws(() => configureBrowserSdk({ ignoredOption: true }), /Unknown/);
    beginBrowserSdkInitialization();
    assert.throws(() => configureBrowserSdk({ configUrl: 'https://other.example/config' }), /before initializing/);
});
