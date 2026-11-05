import { parentPort, workerData } from 'node:worker_threads';

// Adapt only the Web Worker message API and asset URL. The bundled SDK worker,
// fetch/Response, WebAssembly engine and shipped WASM all execute unchanged.
globalThis.self = globalThis;
self.addEventListener = (type, listener) => {
    if (type === 'message') parentPort.on('message', data => listener({ data }));
};
self.postMessage = data => parentPort.postMessage(data);
const fetchAsset = globalThis.fetch;
globalThis.fetch = (url, init) => {
    if (new URL(url).pathname.endsWith('/zkapi_browser_bg.wasm')) {
        return fetchAsset(workerData.wasmUrl, init);
    }
    throw new Error('Unexpected asset request in WASM initialization test.');
};
await import(workerData.workerUrl);
parentPort.postMessage({ ready: true });
