#!/usr/bin/env node
// The client and server profiles of a finalized concession-exit deployment
// (design §10.3), from the manifest `scripts/expected-codehashes.mjs
// --finalize` wrote (docs/migration-concession-vault.md, B2 step 5):
//
//   node scripts/deployment-profile.mjs --finalized deployment.json \
//     --deployment-id zkapi-native-eth-sepolia-concession-v1 \
//     --protocol-server-url https://... --indexer-url https://... --rpc-url https://... \
//     --verifier-url https://... [--bundler-url https://...] [--format trusted|sdk|clientd] \
//     [--base FILE] [--out FILE]
//
// - `trusted` (the default) prints `{ "trusted_deployment": ... }`: the
//   manifest serverd, `zkapi db init` and zkapi-challenged read with
//   --deployment.
// - `sdk` writes that profile into the browser config `--base` (for example
//   sdk/assets/config/sepolia.json), keeping its browser fields.
// - `clientd` fills the placeholder `--base`
//   (zkapi-clientd/internal/zkapi/deployments/<network>.json) under clientd's
//   own field names.
//
// It refuses a pending or simulated manifest, a missing or legacy
// deployment ID, and a setup whose verifying keys are not the vault's; it
// writes the signing-key coordinates (decimal strings in the manifest) as
// 0x hex, as every consumer parses them. A manifest deployed with the gasless
// withdrawal paymaster gives every profile its `gasless` object (the pins,
// the creation code, the gas policy and `bundler_url`, the operator's bundler
// from --bundler-url, null when none is published); one deployed with
// GASLESS=0 gives `gasless: null`, and the clientd profile says so in its
// limitations.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseDeployment } from './expected-codehashes.mjs';
import { isProfileBundlerUrl, trustedDeployment } from './v2-acceptance.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// The setup directory of each setup ID a deployment may use.
const SETUP_DIRS = Object.freeze({ 'mpc-1': 'protocol/setup/v2-concession', dev: 'protocol/setup/v2-concession-dev' });

const felt = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;

/**
 * The key pins of `setupDir` for `finalized`: the setup must be the
 * deployment's (circuit, setup ID and both verifying-key hashes), and each
 * key file present must hash to what the setup's manifest records.
 */
export function setupPins(setupDir, finalized) {
    const manifest = JSON.parse(fs.readFileSync(path.join(setupDir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.circuit_id, finalized.circuitId, `${setupDir} is not the setup of circuit ${finalized.circuitId}`);
    assert.equal(manifest.setup_id, finalized.setupId, `${setupDir} is setup ${manifest.setup_id}, the vault's is ${finalized.setupId}`);
    assert.equal(manifest.vk_keccak256.request.toLowerCase(), finalized.requestVkKeccak256.toLowerCase(),
        'the setup\'s request verifying key is not the vault\'s');
    assert.equal(manifest.vk_keccak256.withdrawal.toLowerCase(), finalized.withdrawalVkKeccak256.toLowerCase(),
        'the setup\'s withdrawal verifying key is not the vault\'s');
    for (const [file, hash] of Object.entries(manifest.files)) {
        const keyPath = path.join(setupDir, file);
        if (fs.existsSync(keyPath)) {
            assert.equal(createHash('sha256').update(fs.readFileSync(keyPath)).digest('hex'), hash, `${keyPath} is not the key its manifest pins`);
        }
    }
    return { requestPk: manifest.files['request.pk'], withdrawalPk: manifest.files['withdrawal.pk'],
        requestVk: manifest.files['request.vk'], withdrawalVk: manifest.files['withdrawal.vk'] };
}

/**
 * The `trusted_deployment` profile. `deploymentId` must be new: the legacy
 * deployments' IDs name circuit zkapi-v2-note-bound-v1, and a browser keeps
 * both builds' wallets in one store keyed by that ID.
 */
export function deploymentProfile(finalized, { deploymentId, protocolServerUrl, indexerUrl, rpcUrl, verifierUrl,
    inferenceBase = 'https://openrouter.ai/api/v1', priceFeed, settlementWindowSeconds, keyHashes, canary = null, bundlerUrl = null }) {
    assert.ok(typeof deploymentId === 'string' && /^[a-z0-9][a-z0-9.-]{2,127}$/.test(deploymentId),
        'name the deployment with a new deployment ID (lowercase letters, digits, dots and dashes)');
    assert.ok(!deploymentId.includes('note-bound'), 'a deployment ID of the legacy vault cannot name the concession vault');
    for (const [name, value] of Object.entries({ protocolServerUrl, indexerUrl, rpcUrl, verifierUrl, priceFeed })) {
        assert.ok(typeof value === 'string' && value, `${name} is required`);
    }
    assert.ok(Number.isSafeInteger(settlementWindowSeconds) && settlementWindowSeconds > 0, 'settlementWindowSeconds is required');
    assert.ok(bundlerUrl === null || isProfileBundlerUrl(bundlerUrl),
        '--bundler-url is an https URL (or http to localhost or 127.0.0.1) without credentials, query or fragment: '
        + 'zkapi-clientd refuses a profile whose bundler URL carries any of these, so a hosted bundler\'s API key cannot ride in the URL');
    assert.ok(bundlerUrl === null || finalized.withdrawalPaymaster != null, '--bundler-url names a bundler for a deployment without the paymaster');
    const profile = trustedDeployment(finalized, { deploymentId, protocolServerUrl, indexerUrl, rpcUrl, priceFeed, keyHashes,
        settlementWindowSeconds, inferenceBase, verifierUrl, bundlerUrl });
    return { ...profile, canary };
}

/**
 * clientd's packaged profile: `base` (its placeholder) with the deployment's
 * values under clientd's names.
 */
export function clientdProfile(base, profile, finalized, keyHashes) {
    assert.equal(base.chain_id, profile.chain_id, 'the clientd placeholder is for another network');
    const filled = structuredClone(base);
    Object.assign(filled, {
        deployment_status: 'deployed',
        deployment_id: profile.deployment_id,
        rpc_url: profile.rpc_url,
        contract_address: profile.contract_address,
        proof_adapter_address: profile.proof_adapter_address,
        poseidon_library_address: profile.poseidon_library_address,
        deploy_block: profile.deploy_block,
        protocol_server_url: profile.protocol_server_url,
        indexer_url: profile.indexer_url,
        request_charge_cap: profile.request_charge_cap,
        note_ttl_seconds: profile.note_ttl,
        challenge_period_seconds: profile.challenge_period,
        max_pause_duration_seconds: profile.max_pause_duration,
        settlement_window_seconds: profile.settlement_window_seconds,
        vault_revision: 3,
        exit_concession: 1,
        clearance_ownership_proof: 'required',
        state_signing_key: profile.state_signing_key,
        clearance_signing_key: profile.clearance_signing_key,
        deployment_evidence: {
            vault_runtime_keccak256: finalized.vaultRuntimeCodehash,
            adapter_runtime_keccak256: finalized.adapterRuntimeCodehash,
            poseidon_runtime_keccak256: finalized.poseidonRuntimeCodehash,
            // The gasless pins, checked before a `--fees payout` withdrawal; null without the paymaster.
            entry_point_runtime_keccak256: profile.gasless?.entry_point_runtime_codehash ?? null,
            sender_creator_runtime_keccak256: profile.gasless?.sender_creator_runtime_codehash ?? null,
            paymaster_runtime_keccak256: profile.gasless?.withdrawal_paymaster_runtime_codehash ?? null,
            factory_runtime_keccak256: profile.gasless?.withdrawal_account_factory_runtime_codehash ?? null,
            account_implementation_runtime_keccak256: profile.gasless?.withdrawal_account_implementation_runtime_codehash ?? null,
        },
        gasless: profile.gasless,
    });
    filled.proof_setup = { ...base.proof_setup, repository_path: SETUP_DIRS[finalized.setupId] ?? base.proof_setup?.repository_path,
        circuit_id: profile.circuit_id, setup_id: profile.setup_id,
        request_proving_key_sha256: keyHashes.requestPk, request_verifying_key_sha256: keyHashes.requestVk,
        withdrawal_proving_key_sha256: keyHashes.withdrawalPk, withdrawal_verifying_key_sha256: keyHashes.withdrawalVk,
        request_vk_keccak256: profile.request_vk_keccak256, withdrawal_vk_keccak256: profile.withdrawal_vk_keccak256 };
    filled.privacy_mode = { ...base.privacy_mode, verifier_url: profile.verifier_url };
    // The placeholder's own limitations go; the others stay for review. A
    // deployment without the paymaster says so, as the placeholder did.
    filled.limitations = (base.limitations ?? []).filter(text => !/^Placeholder:/.test(text));
    if (profile.gasless === null) {
        filled.limitations.push('The gasless withdrawal paymaster (ERC-4337) is not deployed with this vault; a withdrawal pays its own network fee from the signing address.');
    }
    return filled;
}

function options(args) {
    const flags = { '--finalized': 'finalized', '--deployment-id': 'deploymentId', '--protocol-server-url': 'protocolServerUrl',
        '--indexer-url': 'indexerUrl', '--rpc-url': 'rpcUrl', '--verifier-url': 'verifierUrl', '--inference-base': 'inferenceBase',
        '--price-feed': 'priceFeed', '--settlement-window-seconds': 'settlementWindowSeconds', '--setup-dir': 'setupDir',
        '--canary': 'canary', '--format': 'format', '--base': 'base', '--out': 'out', '--bundler-url': 'bundlerUrl' };
    const parsed = { format: 'trusted' };
    for (let i = 0; i < args.length; i += 2) {
        const key = flags[args[i]];
        assert.ok(key && args[i + 1] !== undefined, `Unknown or incomplete option: ${args[i]} (see the header of scripts/deployment-profile.mjs)`);
        parsed[key] = args[i + 1];
    }
    assert.ok(parsed.finalized, '--finalized FILE is required');
    assert.ok(['trusted', 'sdk', 'clientd'].includes(parsed.format), '--format is trusted, sdk or clientd');
    assert.ok(parsed.format === 'trusted' || parsed.base, `--format ${parsed.format} needs --base FILE`);
    return parsed;
}

// A profile field carried as a JSON number must be a safe integer: a BigInt reaching the
// serializer is a manifest number above 2^53 - 1 in a field the profile does not take as text.
function refuseWide(key, value) {
    assert.ok(typeof value !== 'bigint', `${key}: ${value} is above 2^53 - 1 and the profile carries it as a number; write it as a decimal string in the manifest`);
    return value;
}

function main(args) {
    const opts = options(args);
    // The manifest is read as expected-codehashes.mjs reads it: a bare number above 2^53 - 1
    // becomes a BigInt (a wei amount then prints exactly), never a rounded double.
    const finalized = parseDeployment(fs.readFileSync(opts.finalized, 'utf8'));
    const base = opts.base ? JSON.parse(fs.readFileSync(opts.base, 'utf8')) : null;
    const baseProfile = opts.format === 'sdk' ? base.trusted_deployment : base;
    const setupDir = path.resolve(ROOT, opts.setupDir ?? SETUP_DIRS[finalized.setupId] ?? '');
    assert.ok(opts.setupDir || SETUP_DIRS[finalized.setupId], `name the setup directory of setup ${finalized.setupId} with --setup-dir`);
    const keyHashes = setupPins(setupDir, finalized);
    const settlement = opts.settlementWindowSeconds ?? baseProfile?.settlement_window_seconds;
    const profile = deploymentProfile(finalized, {
        deploymentId: opts.deploymentId, protocolServerUrl: opts.protocolServerUrl, indexerUrl: opts.indexerUrl,
        rpcUrl: opts.rpcUrl ?? baseProfile?.rpc_url, verifierUrl: opts.verifierUrl,
        inferenceBase: opts.inferenceBase ?? baseProfile?.openrouter_inference_base ?? baseProfile?.privacy_mode?.openrouter_inference_base,
        priceFeed: opts.priceFeed ?? baseProfile?.native_price_feed_address,
        settlementWindowSeconds: settlement == null ? undefined : Number(settlement), keyHashes,
        canary: opts.canary ? JSON.parse(opts.canary) : (baseProfile?.canary ?? null),
        bundlerUrl: opts.bundlerUrl ?? null,
    });
    let output;
    if (opts.format === 'trusted') output = { trusted_deployment: profile };
    else if (opts.format === 'sdk') output = { ...base, trusted_deployment: profile };
    else output = clientdProfile(base, profile, finalized, keyHashes);
    const text = `${JSON.stringify(output, refuseWide, 2)}\n`;
    if (opts.out) fs.writeFileSync(opts.out, text);
    else process.stdout.write(text);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        main(process.argv.slice(2));
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}

