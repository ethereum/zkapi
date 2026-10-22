import http from 'node:http';
import {pathToFileURL} from 'node:url';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const READS = new Set(['eth_chainId', 'eth_supportedEntryPoints', 'eth_getUserOperationReceipt',
    'eth_getUserOperationByHash', 'pimlico_getUserOperationGasPrice']);
const OPS = new Set(['eth_sendUserOperation', 'eth_estimateUserOperationGas']);
const ENTRY_POINT = '0x0000000071727de22e5e9d8baf0edac6f37da032';

/** A fixed-contract Sepolia gateway, never a general-purpose public bundler. */
export function validateRequest(body, pins) {
    if (!body || Array.isArray(body) || typeof body !== 'object' || body.jsonrpc !== '2.0'
        || !(Number.isSafeInteger(body.id) || (typeof body.id === 'string' && body.id.length <= 80))
        || !Array.isArray(body.params)) return 'Invalid JSON-RPC request';
    if (READS.has(body.method)) {
        if (body.method === 'eth_getUserOperationReceipt' || body.method === 'eth_getUserOperationByHash') {
            if (body.params.length !== 1 || !HASH.test(body.params[0])) return 'Invalid operation hash';
        } else if (body.params.length !== 0) return 'Unexpected parameters';
        return null;
    }
    if (!OPS.has(body.method)) return 'Method not available';
    if (body.params.length !== 2 || String(body.params[1]).toLowerCase() !== ENTRY_POINT) return 'Unsupported EntryPoint';
    const op = body.params[0];
    if (!op || typeof op !== 'object' || Array.isArray(op)) return 'Invalid operation';
    if (!ADDRESS.test(op.sender) || String(op.paymaster).toLowerCase() !== pins.paymaster.toLowerCase()) return 'Unsupported paymaster';
    if (op.factory !== undefined && String(op.factory).toLowerCase() !== pins.factory.toLowerCase()) return 'Unsupported factory';
    // v0.7 only. No caller-provided state overrides, delegations or v0.6 packed fields.
    if ('initCode' in op || 'paymasterAndData' in op || 'eip7702Auth' in op || 'authorizationList' in op) return 'Unsupported operation format';
    return null;
}

export async function startGuard(env = process.env) {
    if (env.CHAIN_ID !== '11155111') throw Error('This deployment is restricted to Sepolia');
    const pins = {paymaster: env.PAYMASTER_ADDRESS, factory: env.FACTORY_ADDRESS};
    if (!ADDRESS.test(pins.paymaster) || !ADDRESS.test(pins.factory)) throw Error('Missing contract pins');
    // Alto v1 skips minimum gas-price/PVG checks. Always select v2 even if
    // an operator accidentally leaves Alto's legacy default unchanged.
    const upstream = new URL('/v2/rpc', env.BUNDLER_URL || 'http://bundler:3000').href;
    const rpc = env.RPC_URL;
    const probe = await fetch(rpc, {method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]}), signal: AbortSignal.timeout(15000)});
    const chain = await probe.json();
    if (chain.result !== '0xaa36a7') throw Error('Upstream is not Sepolia');
    let active = 0, tokens = 4, last = Date.now();
    const server = http.createServer(async (req, res) => {
        const reply = (status, value) => {
            res.writeHead(status, {'content-type':'application/json', 'cache-control':'no-store'});
            res.end(JSON.stringify(value));
        };
        if (req.method === 'GET' && req.url === '/health') {
            try {
                const response = await fetch(upstream, {method:'POST', headers:{'content-type':'application/json'},
                    body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_supportedEntryPoints',params:[]}), signal:AbortSignal.timeout(5000)});
                const data = await response.json();
                const healthy = response.ok && Array.isArray(data.result) && data.result.length === 1 && data.result[0].toLowerCase() === ENTRY_POINT;
                reply(healthy ? 200 : 503, {healthy});
            } catch { reply(503, {healthy:false}); }
            return;
        }
        if (req.method !== 'POST' || req.url !== '/') return reply(404, {error:'Not found'});
        let input = '', bytes = 0;
        try {
            for await (const chunk of req) {
                bytes += chunk.length;
                if (bytes > 65536) { reply(413, {error:'Request too large'}); req.destroy(); return; }
                input += chunk.toString('utf8');
            }
            const body = JSON.parse(input);
            const invalid = validateRequest(body, pins);
            if (invalid) return reply(400, {jsonrpc:'2.0', id:null, error:{code:-32602,message:invalid}});
            const expensive = OPS.has(body.method);
            const now = Date.now();
            tokens = Math.min(4, tokens + (now-last)/1000); last = now;
            if (active >= 4 || (expensive && tokens < 1)) return reply(429, {jsonrpc:'2.0',id:body.id,error:{code:-32005,message:'Bundler busy; retry shortly'}});
            if (expensive) tokens -= 1;
            active++;
            try {
                const response = await fetch(upstream, {method:'POST', headers:{'content-type':'application/json'},
                    body:JSON.stringify(body), signal:AbortSignal.timeout(45000)});
                const data = await response.json();
                reply(response.status, data);
            } catch { reply(503, {jsonrpc:'2.0',id:body.id,error:{code:-32000,message:'Bundler temporarily unavailable'}}); }
            finally { active--; }
        } catch { if (!res.headersSent) reply(400, {jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid JSON'}}); }
    });
    server.headersTimeout = 10000;
    server.requestTimeout = 60000;
    server.keepAliveTimeout = 5000;
    server.listen(Number(env.PORT || 3002), '0.0.0.0');
    // Deliberately never log requests, proofs, operation hashes, senders or source addresses.
    return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    startGuard().catch(() => { console.error('Sepolia bundler guard startup failed'); process.exitCode = 1; });
}
