import assert from 'node:assert/strict';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import { build } from 'esbuild';
import { buildBrowserSdkAssets } from '../build.mjs';

async function fixture(t, failures, { malformedDownloads = 0, network = 'sepolia' } = {}) {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-worker-init-'));
    t.after(() => fs.rm(temp, { recursive: true, force: true }));
    await buildBrowserSdkAssets({ outDir: temp, network, build });
    const workerFile = path.join(temp, 'assets/zkapiWasmWorker.js');
    const bytes = await fs.readFile(path.join(temp, 'wasm/zkapi_browser_bg.wasm'));
    let downloads = 0;
    const server = http.createServer((request, response) => {
        downloads += 1;
        if (downloads <= failures) {
            response.writeHead(503, { 'content-type': 'application/wasm' });
            response.end();
        } else {
            response.writeHead(200, { 'content-type': 'application/wasm' });
            response.end(downloads <= malformedDownloads ? Buffer.from('not a WASM module') : bytes);
        }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
    const worker = new Worker(new URL('./helpers/wasm-worker-thread.mjs', import.meta.url), {
        workerData: { workerUrl: pathToFileURL(workerFile).href,
            wasmUrl: `http://127.0.0.1:${server.address().port}/zkapi_browser_bg.wasm` }
    });
    t.after(() => worker.terminate());
    const [ready] = await once(worker, 'message');
    assert.equal(ready.ready, true);
    let sequence = 0;
    const pending = new Map();
    worker.on('message', message => {
        const resolve = pending.get(message.id);
        if (resolve) { pending.delete(message.id); resolve(message); }
    });
    return {
        downloads: () => downloads,
        call(operation = 'walletStatus') {
            const id = ++sequence;
            return new Promise(resolve => {
                pending.set(id, resolve);
                worker.postMessage({ id, operation, payload: {} });
            });
        }
    };
}

test('worker retries a failed WASM download when the next wallet operation arrives', { timeout: 20_000 }, async t => {
    const worker = await fixture(t, 1);
    const failed = await worker.call();
    assert.equal(typeof failed.error, 'string');
    assert.equal(worker.downloads(), 1);
    const recovered = await worker.call();
    assert.equal(recovered.error, undefined);
    assert.equal(typeof recovered.result, 'object');
    assert.equal(worker.downloads(), 2);
    assert.equal((await worker.call('generateDeposit')).error, undefined);
    assert.equal(worker.downloads(), 2, 'successful initialization stays cached');
});

test('concurrent messages share a failed initialization and one successful retry', { timeout: 20_000 }, async t => {
    const worker = await fixture(t, 1);
    const failed = await Promise.all([worker.call(), worker.call()]);
    assert.ok(failed.every(message => typeof message.error === 'string'));
    assert.equal(worker.downloads(), 1);
    const recovered = await Promise.all([worker.call(), worker.call('generateDeposit')]);
    assert.ok(recovered.every(message => message.error === undefined));
    assert.equal(worker.downloads(), 2);
});

test('repeated download failures remain errors and a later retry can recover', { timeout: 20_000 }, async t => {
    const worker = await fixture(t, 2);
    assert.equal(typeof (await worker.call()).error, 'string');
    assert.equal(typeof (await worker.call()).error, 'string');
    assert.equal(worker.downloads(), 2);
    assert.equal((await worker.call()).error, undefined);
    assert.equal(worker.downloads(), 3);
});

test('healthy concurrent wallet operations initialize the shipped WASM once', { timeout: 20_000 }, async t => {
    const worker = await fixture(t, 0, { network: 'mainnet' });
    const messages = await Promise.all([worker.call(), worker.call('generateDeposit')]);
    assert.ok(messages.every(message => message.error === undefined));
    assert.equal(worker.downloads(), 1);
    assert.equal((await worker.call()).error, undefined);
    assert.equal(worker.downloads(), 1);
});

test('invalid WASM remains an error and a corrected download can initialize later', { timeout: 20_000 }, async t => {
    const worker = await fixture(t, 0, { malformedDownloads: 1 });
    assert.equal(typeof (await worker.call()).error, 'string');
    assert.equal(worker.downloads(), 1);
    assert.equal((await worker.call()).error, undefined);
    assert.equal(worker.downloads(), 2);
});
