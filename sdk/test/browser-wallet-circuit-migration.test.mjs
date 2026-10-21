import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';

const CIRCUIT_ID = 'zkapi-v2-concession-v1';

function manifest() {
    return {
        protocol_version: 2,
        proof_backend: 'groth16_bn254',
        deployment_id: 'note-bound-test',
        chain_id: 1,
        contract_address: '0x' + '11'.repeat(20),
        billing_asset: 'native_eth', billing_unit: 'gwei', native_asset_wei_per_unit: '1000000000',
        native_price_feed_address: '0x' + '22'.repeat(20), native_price_feed_decimals: 8,
        native_price_max_age_seconds: 3600, rpc_url: 'https://rpc.example',
        protocol_server_url: 'https://server.example',
        indexer_url: 'https://indexer.example',
        request_charge_cap: 1000,
        state_signing_key: { x: '0x1', y: '0x2' },
        clearance_signing_key: { x: '0x3', y: '0x4' },
        proof_setup: {
            circuit_id: CIRCUIT_ID,
            request_proving_key_sha256: 'aa'.repeat(32),
            withdrawal_proving_key_sha256: 'bb'.repeat(32)
        },
        privacy_mode: {
            openrouter_inference_base: 'https://openrouter.ai/api/v1',
            verifier_url: 'https://verifier.example'
        }
    };
}

test('browser rejects missing, legacy, and unknown circuits with migration guidance', () => {
    const runtime = new BrowserWalletRuntime();
    for (const circuitId of [undefined, '', 'legacy-unbound', 'zkapi-v2-note-bound-v1', 'unknown-future-circuit']) {
        const deployment = manifest();
        deployment.proof_setup.circuit_id = circuitId;
        assert.throws(() => runtime.validateManifest(deployment), error => {
            assert.equal(error.code, 'incompatible_proof_circuit');
            assert.match(error.message, /Funding is unavailable/);
            assert.match(error.message, /new vault/);
            assert.match(error.message, /existing funds and recovery data/);
            return true;
        });
    }
    const legacy = manifest();
    delete legacy.proof_setup;
    assert.throws(() => runtime.validateManifest(legacy), { code: 'incompatible_proof_circuit' });
    assert.doesNotThrow(() => runtime.validateManifest(manifest()));
});

test('browser requires its trusted configuration to pin the same circuit', () => {
    const runtime = new BrowserWalletRuntime();
    const deployment = manifest();
    runtime.browserConfig = { trusted_deployment: {
        ...deployment,
        ...deployment.proof_setup,
        ...deployment.privacy_mode,
        setup_id: 'dev',
        exit_concession: 1,
        vault_revision: 3,
        clearance_ownership_proof: 'required'
    } };
    runtime.validateManifestTrust(deployment);
    delete runtime.browserConfig.trusted_deployment.circuit_id;
    assert.throws(() => runtime.validateManifestTrust(deployment), /pinned proof circuit/);
    runtime.browserConfig.trusted_deployment.circuit_id = 'legacy-unbound';
    assert.throws(() => runtime.validateManifestTrust(deployment), /pinned proof circuit/);
});

/** A build-pinned profile (browser-config.json's trusted_deployment) for a manifest. */
function trustedFor(deployment, changes = {}) {
    return { ...deployment, ...deployment.proof_setup, ...deployment.privacy_mode, setup_id: 'dev',
        exit_concession: 1, vault_revision: 3, clearance_ownership_proof: 'required', ...changes };
}

// A build's own profile is checked before anything else: a profile that pins
// a legacy circuit, or none, never initializes. (A legacy manifest served to a
// concession build only refuses deposits and chats; exits run from the pins:
// browser-wallet-init-exit.test.mjs.)
test('a build pinning a legacy circuit, or no profile, never initializes: no proof worker, no wallet storage', async t => {
    const originalLocation = globalThis.location;
    const originalStorage = globalThis.localStorage;
    t.after(() => {
        globalThis.location = originalLocation;
        globalThis.localStorage = originalStorage;
    });
    globalThis.location = { href: 'https://host.example/', search: '' };
    globalThis.localStorage = {
        getItem: () => null,
        setItem: () => assert.fail('legacy funding must not persist deployment selection'),
        removeItem: () => assert.fail('no stored selection to remove')
    };
    const legacy = manifest();
    legacy.proof_setup.circuit_id = 'zkapi-v2-note-bound-v1';
    for (const [browserConfig, expected] of [
        [{ deployment_manifest_url: 'https://server.example/config.json', trusted_deployment: trustedFor(legacy) },
            { code: 'incompatible_proof_circuit' }],
        [{ deployment_manifest_url: 'https://server.example/config.json' }, /omitted its trusted deployment pins/]
    ]) {
        const runtime = new BrowserWalletRuntime();
        runtime.loadBrowserConfig = async () => browserConfig;
        runtime.directJson = async () => assert.fail('a build that cannot run never asks the operator');
        await assert.rejects(runtime.prepareDeposit(1000), expected);
        assert.equal(runtime.worker, null);
        assert.equal(runtime.initialized, false);
    }
});


test('historical packaged vault pins cannot be relabeled as a repaired deployment', () => {
    const runtime = new BrowserWalletRuntime();
    runtime.browserConfig = { deployment_status: 'migration_required' };
    assert.throws(() => runtime.validateManifestTrust({}), /newly deployed note-bound vault/);
});

test('a build pinning a token deployment is rejected before deployment selection, worker creation or wallet writes', async t => {
    const oldLocation = globalThis.location;
    const oldStorage = globalThis.localStorage;
    t.after(() => { globalThis.location = oldLocation; globalThis.localStorage = oldStorage; });
    globalThis.location = { href: 'https://host.example/', search: '' };
    globalThis.localStorage = {
        getItem: () => null,
        setItem: () => assert.fail('unsupported deployments must not change saved selection'),
        removeItem: () => assert.fail('no stored selection to remove')
    };
    for (const asset of ['erc20', undefined]) {
        const runtime = new BrowserWalletRuntime();
        const token = { ...manifest(), billing_asset: asset, billing_token_address: `0x${'44'.repeat(20)}` };
        runtime.loadBrowserConfig = async () => ({ deployment_manifest_url: 'https://server.example/config.json',
            trusted_deployment: trustedFor(token) });
        runtime.directJson = async () => assert.fail('a build that cannot run never asks the operator');
        await assert.rejects(runtime.prepareDeposit(1000), /only native ETH deployments are supported/);
        assert.equal(runtime.worker, null);
        assert.equal(runtime.initialized, false);
    }
});

test('a placeholder profile, a profile without the concession exit or an unknown setup never initializes', () => {
    const runtime = new BrowserWalletRuntime();
    const deployment = manifest();
    const trusted = { ...deployment, ...deployment.proof_setup, ...deployment.privacy_mode,
        setup_id: 'dev', exit_concession: 1, vault_revision: 3, clearance_ownership_proof: 'required' };
    runtime.browserConfig = { trusted_deployment: trusted };
    runtime.validateManifestTrust(deployment);
    runtime.browserConfig = { trusted_deployment: { ...trusted, deployment_status: 'not_deployed' } };
    assert.throws(() => runtime.validateManifestTrust(deployment), { code: 'deployment_not_deployed' });
    for (const exitConcession of [undefined, 0, 2, '1']) {
        runtime.browserConfig = { trusted_deployment: { ...trusted, exit_concession: exitConcession } };
        assert.throws(() => runtime.validateManifestTrust(deployment), { code: 'exit_concession_required' });
    }
    // vault_revision 2 alone (the hardened note-bound vault) is not enough.
    runtime.browserConfig = { trusted_deployment: { ...trusted, exit_concession: undefined, vault_revision: 2 } };
    assert.throws(() => runtime.validateManifestTrust(deployment), { code: 'exit_concession_required' });
    for (const setupId of [undefined, 'rehearsal', 'DEV']) {
        runtime.browserConfig = { trusted_deployment: { ...trusted, setup_id: setupId } };
        assert.throws(() => runtime.validateManifestTrust(deployment), /invalid trusted setup_id/);
    }
    // Only vault revision 3 with required ownership proofs and a positive W.
    for (const change of [{ vault_revision: 2 }, { vault_revision: undefined }, { clearance_ownership_proof: 'optional' },
        { clearance_ownership_proof: undefined }, { settlement_window_seconds: 0 }, { settlement_window_seconds: '14705' }]) {
        runtime.browserConfig = { trusted_deployment: { ...trusted, ...change } };
        assert.throws(() => runtime.validateManifestTrust(deployment), /invalid trusted/, JSON.stringify(change));
    }
});

test('the proof worker must run a bundle of the pinned circuit and setup', async () => {
    const runtime = new BrowserWalletRuntime();
    const identity = { circuit_id: CIRCUIT_ID, setup_id: 'dev' };
    runtime.worker = { call: async operation => { assert.equal(operation, 'identity'); return identity; } };
    runtime.browserConfig = { trusted_deployment: { circuit_id: CIRCUIT_ID, setup_id: 'dev' } };
    await runtime.assertWorkerBundle();
    runtime.browserConfig = { trusted_deployment: { circuit_id: CIRCUIT_ID, setup_id: 'mpc-1' } };
    await assert.rejects(runtime.assertWorkerBundle(), { code: 'setup_mismatch' });
    runtime.browserConfig = { trusted_deployment: { circuit_id: 'zkapi-v2-note-bound-v1', setup_id: 'dev' } };
    await assert.rejects(runtime.assertWorkerBundle(), { code: 'setup_mismatch' });
});
