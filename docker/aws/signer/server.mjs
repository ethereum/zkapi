import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { ConfigError, RpcError, createSigner, createUpstream, parseSignerConfig } from './signer.mjs';

export function createHttpServer(signer) {
  return createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.method === 'GET' && request.url === '/health') {
      try {
        await signer.checkChain();
        const { sender, vault, ...policy } = signer.policy;
        // Retirement refusals are reported, never a failed health check: a
        // restart would start a new budget window.
        response.end(JSON.stringify({ status: 'ok', chain_id: Number(signer.chainId), sender, vault, ...policy, ...signer.retirementStatus() }));
      } catch {
        response.statusCode = 503;
        response.end(JSON.stringify({ status: 'unavailable' }));
      }
      return;
    }
    if (request.method !== 'POST' || request.url !== '/') {
      response.statusCode = 404;
      response.end(JSON.stringify({ error: 'Not found' }));
      return;
    }
    let id = null;
    try {
      let size = 0;
      const chunks = [];
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 65_536) throw new RpcError(-32600, 'Request body is too large');
        chunks.push(chunk);
      }
      let payload;
      try { payload = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { throw new RpcError(-32700, 'Invalid JSON'); }
      if (!payload || Array.isArray(payload) || payload.jsonrpc !== '2.0' || typeof payload.method !== 'string'
          || !['string', 'number'].includes(typeof payload.id)) {
        throw new RpcError(-32600, 'Expected a single JSON-RPC request with an ID');
      }
      id = payload.id;
      const result = await signer.handle(payload.method, payload.params ?? []);
      response.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    } catch (error) {
      // Never serialize unexpected Error objects or provider details. Signer
      // errors carry only fixed messages and structured, secret-free data.
      const safe = error instanceof RpcError ? error : new RpcError(-32603, 'Signer request failed');
      const body = { code: safe.code, message: safe.message };
      if (safe.data) body.data = safe.data;
      response.end(JSON.stringify({ jsonrpc: '2.0', id, error: body }));
    }
  });
}

const decimal = value => BigInt(value).toString(10);

async function main() {
  const { rpcUrl, listenHost, port, ...options } = parseSignerConfig(process.env);
  const signer = createSigner({ ...options, rpc: createUpstream(rpcUrl) });
  delete process.env.ZKAPI_CHALLENGE_PRIVATE_KEY;
  // Fails on a wrong chain or a block without a base fee. A low balance or a
  // base fee above the cap only warns: the challenger waits for a healthy signer.
  const status = await signer.status();
  const server = createHttpServer(signer);
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.listen(port, listenHost, () => {
    console.log(JSON.stringify({
      status: 'listening', chain_id: Number(signer.chainId), sender: signer.sender, vault: signer.vault,
      fee_model: 'eip1559', fee_cap_source: status.fee_cap_source,
      max_fee_per_gas_wei: decimal(status.max_fee_per_gas), priority_fee_per_gas_wei: decimal(status.priority_fee_per_gas),
      max_priority_fee_per_gas_wei: decimal(status.max_priority_fee_per_gas), fee_ceiling_wei: decimal(status.fee_ceiling),
      // The highest maxFeePerGas a MAX_GAS transaction can bid within the tx fee cap.
      tx_fee_cap_wei: decimal(status.tx_fee_cap_wei), max_fee_per_gas_allowed_at_max_gas_wei: decimal(BigInt(status.tx_fee_cap_wei) / BigInt(status.max_gas)),
      max_gas: decimal(status.max_gas), required_balance_wei: decimal(status.required_balance), balance_wei: decimal(status.balance),
      max_retirements_per_day: status.max_retirements_per_day, retire_on_miss: status.retire_on_miss,
      retirement_lookback_blocks: status.retirement_lookback_blocks,
      base_fee_per_gas_wei: decimal(status.base_fee_per_gas), warnings: status.warnings,
    }));
  });
  process.on('SIGTERM', () => server.close());
  process.on('SIGINT', () => server.close());
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    // Only fixed, secret-free messages are printed; anything else stays generic.
    const reason = error instanceof ConfigError || error instanceof RpcError
      ? `${error.message}${error.data?.reason ? ` (${error.data.reason})` : ''}`
      : 'check its private configuration and upstream RPC';
    console.error(`Challenge signer startup failed: ${reason}`);
    process.exitCode = 1;
  });
}
