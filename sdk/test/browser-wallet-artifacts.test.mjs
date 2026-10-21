import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import test from 'node:test';
const __dirname = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const root = __dirname;

function sha256(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function sourceBlockAt(source, markerIndex) {
    assert.ok(markerIndex >= 0, 'source block marker is missing');
    const blockStart = source.indexOf('{', markerIndex);
    assert.ok(blockStart >= 0, 'source block opening brace is missing');
    let depth = 0;
    for (let index = blockStart; index < source.length; index += 1) {
        if (source[index] === '{') depth += 1;
        if (source[index] === '}') {
            depth -= 1;
            if (depth === 0) return source.slice(blockStart, index + 1);
        }
    }
    assert.fail('source block closing brace is missing');
}

function sourceMethodAt(source, marker) {
    const markerIndex = source.indexOf(marker);
    assert.ok(markerIndex >= 0, `source method marker is missing: ${marker}`);
    const parametersStart = source.indexOf('(', markerIndex);
    assert.ok(parametersStart >= 0, `source method parameters are missing: ${marker}`);

    let parameterDepth = 0;
    let parametersEnd = -1;
    for (let index = parametersStart; index < source.length; index += 1) {
        if (source[index] === '(') parameterDepth += 1;
        if (source[index] === ')') {
            parameterDepth -= 1;
            if (parameterDepth === 0) {
                parametersEnd = index;
                break;
            }
        }
    }
    assert.ok(parametersEnd >= 0, `source method parameters do not close: ${marker}`);

    const bodyStart = source.indexOf('{', parametersEnd);
    assert.ok(bodyStart >= 0, `source method body is missing: ${marker}`);
    return source.slice(markerIndex, bodyStart) + sourceBlockAt(source, bodyStart);
}

test('browser build contains every wallet WASM operation', () => {
    const bytes = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser_bg.wasm'));
    const module = new WebAssembly.Module(bytes);
    const exports = new Set(WebAssembly.Module.exports(module).map(entry => entry.name));
    const expected = [
        'browser_circuit_id',
        'browser_setup_id',
        'browser_generate_deposit',
        'browser_confirm_deposit',
        'browser_wallet_status',
        'browser_tree_path',
        'browser_tree_path_from_leaves',
        'browser_prepare_request',
        'browserrequestprover_new',
        'browserrequestprover_prepare_request',
        'browser_complete_response',
        'browser_withdrawal_nullifier',
        'browser_successor_nullifier',
        'browser_prepare_withdrawal',
        'browser_verify_request',
        'browser_check_unrecoverable_response',
        'browser_note_path_matches',
        'browsernotetree_new',
        'browsernotetree_apply',
        'browsernotetree_root',
        'browsernotetree_next_note_id',
        'browsernotetree_path'
    ];
    for (const name of expected) {
        assert.ok(exports.has(name), `missing WASM export ${name}`);
    }
    // Every wallet operation the bundle exports is listed above.
    const operations = [...exports].filter(name => /^browser/.test(name) && !/__wbg|_free$/.test(name));
    assert.deepEqual(operations.sort(), [...expected].sort());
});

test('browser worker retains the decoded request prover and retries failed initialization', () => {
    const glue = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser.js'), 'utf8');
    const worker = fs.readFileSync(path.join(__dirname, 'services/zkapiWasmWorker.js'), 'utf8');
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');

    assert.match(glue, /export class BrowserRequestProver/);
    assert.match(worker, /const requestProvers = new Map\(\)/);
    assert.match(worker, /new BrowserRequestProver\(bytes\)/);
    assert.match(worker, /case 'preloadRequestProver':\s*await loadRequestProver\(payload\.provingKey\)/);
    assert.match(worker, /return parse\(prover\.prepare_request\(/);
    assert.match(worker, /if \(keyBytes\.get\(cacheKey\) === promise\) keyBytes\.delete\(cacheKey\)/);
    assert.match(worker, /requestProvers\.delete\(cacheKey\)/);
    assert.doesNotMatch(worker, /\bbrowser_prepare_request\b/);
    assert.match(runtime, /prewarmRequestProver\(\)/);
    assert.match(runtime, /this\.worker\.call\('preloadRequestProver'/);
    assert.match(runtime, /if \(this\.runtime\.state \|\| this\.runtime\.pendingDeposit\)/);
    const prepareDeposit = sourceMethodAt(runtime, 'async prepareDeposit(amount,');
    const walletStatus = sourceMethodAt(runtime, 'async walletStatus()');
    assert.match(prepareDeposit, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        prepareDeposit.indexOf('void this.prewarmRequestProver()')
            > prepareDeposit.indexOf('await withBrowserWalletLock'),
        'deposit warm-up must not block its lightweight worker preparation'
    );
    assert.match(walletStatus, /const status = await this\.worker\.call\('walletStatus'/);
    assert.match(walletStatus, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        walletStatus.indexOf('void this.prewarmRequestProver()')
            > walletStatus.indexOf("await this.worker.call('walletStatus'"),
        'funded-page warm-up must begin only after initial wallet status resolves'
    );
});

test('static proof keys are the concession development setup and match its manifest', () => {
    const setup = path.join(root, '../protocol/setup/v2-concession-dev');
    const setupManifest = JSON.parse(fs.readFileSync(path.join(setup, 'manifest.json'), 'utf8'));
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'assets/manifest.json'), 'utf8'));
    assert.equal(setupManifest.circuit_id, 'zkapi-v2-concession-v1');
    assert.equal(manifest.schema, 2);
    assert.equal(manifest.circuitId, setupManifest.circuit_id);
    assert.equal(manifest.setupId, setupManifest.setup_id);
    assert.match(manifest.sourceRevision, /^[0-9a-f]{40}$/);
    assert.deepEqual(manifest.vkKeccak256, setupManifest.vk_keccak256);
    for (const file of ['request.pk', 'withdrawal.pk', 'request.vk']) {
        assert.equal(sha256(path.join(root, 'assets/proofs', file)), setupManifest.files[file], file);
        assert.equal(manifest.files[`assets/proofs/${file}`], setupManifest.files[file], file);
    }
    assert.equal(sha256(path.join(root, 'assets/proofs/request.pk')),
        '7dbfde825f30f2467d1963e4f89bf807497895f499b8a9d6fc7aa6ff8844feba');
    assert.equal(sha256(path.join(root, 'assets/proofs/withdrawal.pk')),
        '43e327f74da63dbb06e09071d07863b23d4d2e1ebc5bf9516034c6cd9b2e9ab1');
    assert.equal(sha256(path.join(root, 'assets/proofs/request.vk')),
        '11d68d68aff6a234763343a4d48918c29bf566c38d2487ac021b24e634362caf');
    // Each key file names its circuit, setup and kind.
    for (const kind of ['request', 'withdrawal']) {
        const header = `zkapi-v2-concession-v1/${manifest.setupId}/${kind}\0`;
        assert.equal(fs.readFileSync(path.join(root, `assets/proofs/${kind}.pk`)).subarray(0, header.length).toString('latin1'), header);
    }
});

for (const network of ['sepolia', 'mainnet']) {
    test(`the ${network} profile is a not_deployed placeholder pinning the shipped circuit, setup and keys`, () => {
        const config = JSON.parse(fs.readFileSync(path.join(__dirname, `assets/config/${network}.json`), 'utf8'));
        const manifest = JSON.parse(fs.readFileSync(path.join(root, 'assets/manifest.json'), 'utf8'));
        const trusted = config.trusted_deployment;
        assert.equal(trusted.deployment_status, 'not_deployed');
        assert.equal(trusted.chain_id, network === 'mainnet' ? 1 : 11155111);
        assert.equal(trusted.circuit_id, 'zkapi-v2-concession-v1');
        assert.equal(trusted.setup_id, manifest.setupId);
        assert.equal(trusted.request_proving_key_sha256, sha256(path.join(root, 'assets/proofs/request.pk')));
        assert.equal(trusted.withdrawal_proving_key_sha256, sha256(path.join(root, 'assets/proofs/withdrawal.pk')));
        assert.equal(trusted.request_verifying_key_sha256, sha256(path.join(root, 'assets/proofs/request.vk')));
        assert.equal(trusted.request_vk_keccak256, manifest.vkKeccak256.request);
        assert.equal(trusted.withdrawal_vk_keccak256, manifest.vkKeccak256.withdrawal);
        assert.equal(trusted.vault_revision, 3);
        assert.equal(trusted.exit_concession, 1);
        assert.equal(trusted.clearance_ownership_proof, 'required');
        // Nothing that only a deployment determines is pinned yet.
        for (const field of ['deployment_id', 'contract_address', 'deploy_block', 'protocol_server_url', 'indexer_url',
            'state_signing_key', 'clearance_signing_key', 'vault_runtime_codehash', 'proof_adapter_address',
            'adapter_runtime_codehash', 'poseidon_library_address', 'poseidon_runtime_codehash', 'verifier_url']) {
            assert.equal(trusted[field], null, field);
        }
        assert.equal(config.deployment_manifest_url, null);
        assert.deepEqual(config.allowed_deployment_manifest_urls, []);
        // The design's parameters for the network (§10.4) and its canary (§10.7 C).
        const planned = network === 'mainnet'
            ? { challenge_period: 172_800, note_ttl: 2_592_000, max_pause_duration: 3_888_000, settlement_window_seconds: 21_905 }
            : { challenge_period: 43_200, note_ttl: 2_592_000, max_pause_duration: 604_800, settlement_window_seconds: 14_705 };
        for (const [field, value] of Object.entries(planned)) assert.equal(trusted[field], value, field);
        assert.ok(trusted.max_pause_duration >= 2 * trusted.challenge_period);
        assert.deepEqual(trusted.canary, network === 'mainnet'
            ? { per_note_max_wei: '250000000000000000', aggregate_max_wei: '25000000000000000000', until: null }
            : null);
        assert.equal(trusted.billing_asset, 'native_eth');
        assert.equal(trusted.billing_unit, 'gwei');
        assert.equal(config.proving_keys_base_url, './proofs/');
        assert.equal(config.deployment_api_proxy_path, '/zkapi-deployment/');
    });
}

test('browser direct requests derive output headroom from the proof-backed dollar budget', async () => {
    const compat = await import(pathToFileURL(path.join(__dirname, 'services/zkapiRequestCompat.mjs')));
    assert.deepEqual(
        compat.ensureDirectCompletionLimit(
            { model: 'anthropic/claude-opus-5' },
            {
                spendingLimitUsd: 2,
                model: {
                    pricing: { completion: '0.000025' },
                    top_provider: { max_completion_tokens: 128_000 }
                }
            }
        ),
        { model: 'anthropic/claude-opus-5', max_tokens: 36_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'openai/gpt-5.6-sol' }, { spendingLimitUsd: 5 }),
        { model: 'openai/gpt-5.6-sol', max_tokens: 90_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'example/model' }),
        { model: 'example/model' }
    );
    assert.equal(compat.ensureDirectCompletionLimit({ max_tokens: 32 }).max_tokens, 32);
    assert.equal(compat.ensureDirectCompletionLimit({ max_completion_tokens: 48 }).max_completion_tokens, 48);
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ max_output_tokens: 64 }),
        { max_tokens: 64 }
    );
});

test('wallet transactions use a bounded preflight gas limit and leave EIP-1559 fees to MetaMask', async () => {
    const gas = await import(pathToFileURL(path.join(__dirname, 'services/zkapiGas.mjs')));
    assert.equal(gas.bufferedGasLimit('0x6d094d'), '0x839b46');
    assert.throws(
        () => gas.bufferedGasLimit(16_000_000n),
        error => error.code === 'transaction_gas_limit_exceeded'
    );
    assert.throws(() => gas.bufferedGasLimit('0x0'), /invalid gas estimate/);
    const contractErrors = await import(pathToFileURL(path.join(__dirname, 'services/zkapiContractError.mjs')));
    const staleRoot = contractErrors.contractEstimateError({
        message: 'execution reverted',
        data: { originalError: { data: '0x607447de' } }
    });
    assert.equal(staleRoot.code, 'stale_root');
    assert.match(staleRoot.message, /vault changed/i);
    const unknown = contractErrors.contractEstimateError({ message: 'execution reverted' });
    assert.equal(unknown.code, 'gas_estimation_failed');
    assert.match(unknown.message, /Transaction simulation failed: execution reverted/);
    assert.doesNotMatch(unknown.message, /market|gas price/i);
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const send = sourceMethodAt(client, 'async sendContractTransaction(');
    const estimateIndex = send.indexOf("method: 'eth_estimateGas'");
    const gasIndex = send.indexOf('transaction.gas = bufferedGasLimit(estimate)');
    const submitIndex = send.indexOf("method: 'eth_sendTransaction'");
    assert.ok(estimateIndex >= 0 && gasIndex > estimateIndex && submitIndex > gasIndex);
    assert.match(send, /catch \(error\) \{[\s\S]*const estimateError = contractEstimateError\(error\);[\s\S]*tagTransactionError\(estimateError, 'estimate', false\)[\s\S]*\}\s*let hash;[\s\S]*method: 'eth_sendTransaction'/);
    // An exit's failed simulation is advisory (E4.5): a fixed, bounded limit
    // (behaviour: browser-wallet-exit-submission.test.mjs).
    assert.match(send, /exitEstimate\.blocking\?\.\(estimateError\)/);
    assert.ok(gas.EXIT_FALLBACK_GAS_LIMIT < gas.MAX_TRANSACTION_GAS_LIMIT);
    assert.doesNotMatch(send, /transaction\.(?:gasPrice|maxFeePerGas|maxPriorityFeePerGas)\s*=/);
    assert.match(client, /contractRevertSelector\(error\)/);
    assert.match(client, /error\?\.code !== 'stale_root'/);
});

test('published vault challenge-period getter is probed before the reverting fallback', () => {
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const method = sourceMethodAt(client, 'async loadChallengePeriod()');
    const publishedGetter = method.indexOf('ABI.legacyChallengePeriod');
    const fallbackGetter = method.indexOf('ABI.challengePeriod');

    assert.ok(publishedGetter >= 0, 'published CHALLENGE_PERIOD() getter is missing');
    assert.ok(fallbackGetter >= 0, 'challengePeriod() fallback getter is missing');
    assert.ok(
        publishedGetter < fallbackGetter,
        'the known-reverting fallback must not be probed before the published getter'
    );
});

test('a saved withdrawal proof is reused until its valid_until, never refreshed with new siblings', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const rootSync = fs.readFileSync(path.join(__dirname, 'services/zkapiWithdrawalRoot.mjs'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    assert.match(runtime, /expectedActiveRoot/);
    assert.match(runtime, /waitForExpectedActiveRoot/);
    assert.match(rootSync, /indexer_root_lag/);
    assert.match(client, /`0x\$\{ABI\.currentRoot\}`/);
    // Deposits still re-prove on any stale root.
    assert.match(client, /const attempts = 3/);
    assert.match(client, /Refreshing the deposit before retrying/);
    // Exits do no Merkle work and the vault accepts any root it ever held:
    // a proof stays usable until valid_until (E4.7) and calldata carries no
    // path. Behaviour: browser-wallet-exit-rules.test.mjs.
    const reuse = sourceMethodAt(runtime, 'reusablePlan(');
    assert.match(reuse, /withdrawalProofStillValid\(inputs\)/);
    assert.doesNotMatch(runtime, /siblingsRoot/);
    const withdraw = sourceMethodAt(client, 'async performWithdrawal(');
    assert.match(client, /const REPROVABLE_EXIT_ERRORS = Object\.freeze\(\['proof_expired', 'unknown_root'\]\)/);
    assert.match(withdraw, /REPROVABLE_EXIT_ERRORS\.includes\(error\?\.code\)/);
});

test('withdrawal root synchronization waits for the indexer and fails closed', async () => {
    const roots = await import(pathToFileURL(path.join(__dirname, 'services/zkapiWithdrawalRoot.mjs')));
    let calls = 0;
    const current = await roots.waitForExpectedActiveRoot(async () => {
        calls += 1;
        return { active_root: calls === 1 ? '0x10' : '0x11' };
    }, 17n, { attempts: 3, delayMs: 0, sleep: async () => {} });
    assert.equal(current.active_root, '0x11');
    assert.equal(calls, 2);
    assert.equal(roots.sameFelt('0x11', 17n), true);

    await assert.rejects(
        roots.waitForExpectedActiveRoot(
            async () => ({ active_root: '0x12' }),
            '0x13',
            { attempts: 2, delayMs: 0, sleep: async () => {} }
        ),
        error => error.code === 'indexer_root_lag'
    );
});

test('only a never-submitted prepared deposit can be replaced after cancellation', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    assert.match(runtime, /pending\.phase !== 'prepared' \|\| pending\.submissionId[\s\S]*pending\.transactionHash \|\| pending\.transactionHashes\?\.length/);
    assert.match(runtime, /await this\.commit\(\{ \.\.\.this\.runtime, pendingDeposit: null \}\)/);
    assert.match(runtime, /A previous deposit may already be in MetaMask\. Recover it before changing the amount/);
});

test('browser deposits refresh an unsigned Merkle path before submission', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const refresh = sourceMethodAt(runtime, 'async refreshPendingDeposit(');
    assert.match(refresh, /async refreshPendingDeposit\(amount, expectedActiveRoot = null,/);
    assert.match(refresh, /const refreshed = \{[\s\S]*\.\.\.pending,[\s\S]*next_note_id: path\.note_id,[\s\S]*active_root: path\.active_root,[\s\S]*zero_path: path\.siblings/);
    assert.doesNotMatch(refresh, /secret:/);
    assert.match(client, /await browserWalletRuntime\.refreshPendingDeposit\([\s\S]*Number\(amount\),[\s\S]*expectedActiveRoot/);
    assert.match(client, /const attempts = 3/);
    assert.match(client, /error\?\.code !== 'stale_root'/);
});
