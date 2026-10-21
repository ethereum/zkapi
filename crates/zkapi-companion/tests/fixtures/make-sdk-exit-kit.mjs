// Seals tests/fixtures/sdk-exit-kit-v1.json with the browser SDK's own exit
// kit code (sdk/services/zkapiExitKit.mjs: buildExitKitPayload, sealExitKit),
// so the companion's `exit-kit escape` is tested against what the SDK writes.
//
//   ZKAPI_KIT_FIXTURE_INPUTS=/tmp/inputs.json cargo test --release \
//     -p zkapi-companion --lib -- --ignored write_sdk_kit_fixture_inputs
//   node crates/zkapi-companion/tests/fixtures/make-sdk-exit-kit.mjs /tmp/inputs.json
//
// ZKAPI_EXIT_KIT_MODULE overrides the SDK module's path.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const modulePath = process.env.ZKAPI_EXIT_KIT_MODULE
    || path.join(here, '../../../../sdk/services/zkapiExitKit.mjs');
const { buildExitKitPayload, sealExitKit } = await import(pathToFileURL(modulePath).href);

const inputs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const payload = buildExitKitPayload({
    trustedDeployment: inputs.trusted_deployment,
    state: inputs.state,
    stateSeq: inputs.state_seq,
    exportedAt: inputs.exported_at,
    merklePath: inputs.state.deposit_path
});
// The SDK's minimum for openExitKit; the shipped count is 600,000.
const kit = await sealExitKit(payload, 'zkapi exit kit fixture', { crypto: webcrypto, iterations: 100_000 });
fs.writeFileSync(path.join(here, 'sdk-exit-kit-v1.json'), JSON.stringify(kit, null, 1) + '\n');
