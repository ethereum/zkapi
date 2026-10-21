// Invoked by zkapi-proof/examples/wasm_roundtrip.rs with a public test fixture:
// proves a genesis request and a kind-0 escape with the shipped bundle
// (sdk/wasm and sdk/assets/proofs) and prints both for native verification.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const sdk = path.resolve(process.argv[2]);
const fixture = JSON.parse(fs.readFileSync(0, 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(sdk, 'assets/manifest.json'), 'utf8'));
const wasm = await import(pathToFileURL(path.join(sdk, 'wasm/zkapi_browser.js')));
await wasm.default({ module_or_path: fs.readFileSync(path.join(sdk, 'wasm/zkapi_browser_bg.wasm')) });
assert.equal(wasm.browser_circuit_id(), 'zkapi-v2-concession-v1');
assert.equal(wasm.browser_circuit_id(), fixture.circuit_id);
assert.equal(wasm.browser_setup_id(), manifest.setupId);
const config = JSON.stringify(fixture.config);
const state = wasm.browser_confirm_deposit(config, JSON.stringify(fixture.deposit));
const prover = new wasm.BrowserRequestProver(fs.readFileSync(path.join(sdk, 'assets/proofs/request.pk')));
const { request } = JSON.parse(prover.prepare_request(config, state, JSON.stringify(fixture.request)));
prover.free();
const withdrawal = JSON.parse(wasm.browser_prepare_withdrawal(config, state,
    JSON.stringify(fixture.withdrawal), fs.readFileSync(path.join(sdk, 'assets/proofs/withdrawal.pk'))));
assert.equal(withdrawal.mode, 'escape');
process.stdout.write(JSON.stringify({ request, withdrawal }));
