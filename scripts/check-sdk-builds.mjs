#!/usr/bin/env node
// Builds the SDK for both networks as `npm run build:browser` and
// `build:mainnet` do, and checks the outcome against the shipped profile:
// a network whose profile is a not_deployed placeholder (no concession vault
// is deployed there yet, design §10.3 and §10.5) must refuse with
// deployment_not_deployed and write nothing; a deployed profile must build.
// CI runs this instead of the bare builds while the placeholders ship.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'zkapi-sdk-builds-'));
try {
    for (const network of ['sepolia', 'mainnet']) {
        const profile = JSON.parse(fs.readFileSync(path.join(root, `sdk/assets/config/${network}.json`), 'utf8'));
        const placeholder = profile.trusted_deployment?.deployment_status === 'not_deployed';
        const outDir = path.join(temp, network);
        const result = spawnSync(process.execPath, ['scripts/build-sdk.mjs', '--network', network, '--out-dir', outDir],
            { cwd: root, encoding: 'utf8' });
        if (placeholder) {
            assert.notEqual(result.status, 0, `${network}: a placeholder profile built`);
            assert.match(result.stderr, /deployment_not_deployed/, `${network}: ${result.stderr}`);
            assert.equal(fs.existsSync(outDir), false, `${network}: a refused build wrote ${outDir}`);
            console.log(`${network}: placeholder profile, the build refuses (deployment_not_deployed) as it must`);
        } else {
            assert.equal(result.status, 0, `${network}: ${result.stderr}`);
            console.log(`${network}: built ${outDir}`);
        }
    }
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
