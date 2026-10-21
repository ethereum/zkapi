import { Interface, Transaction, Wallet, getAddress, id, isHexString, keccak256 } from 'ethers';

// Configuration errors carry fixed, secret-free messages that startup may print.
export class ConfigError extends Error {}

export function parseChainId(value) {
  if (value !== '1' && value !== '11155111') throw new ConfigError('Explicit challenge chain ID must be 1 or 11155111');
  return BigInt(value);
}
// The calls of the concession-exit challenger (vault revision 3, circuit
// zkapi-v2-concession-v1): a defeat by a request proof at an escape's
// successor nullifier, a raise by one at its escaped nullifier, and the
// retirement of a closed note's leaf after a missed defeat. The revision-2
// challenge with siblings (0x8a43467c) is refused.
const REQUEST_INPUTS = '(uint16 protocolVersion,uint64 chainId,address contractAddress,uint256 activeRoot,uint256 stateSigningKeyX,uint256 stateSigningKeyY,uint64 requestTime,uint128 solvencyBound,uint256 requestNullifier,uint256 authorizationTag,uint256 anonymousCommitmentX,uint256 anonymousCommitmentY) inputs';
export const CHALLENGE_ABI = `function challengeEscapeWithdrawal(uint32 noteId,${REQUEST_INPUTS},bytes proof)`;
export const RAISE_ABI = `function raiseEscapeConcession(uint32 noteId,${REQUEST_INPUTS},bytes proof,uint128 amount)`;
export const RETIRE_ABI = 'function retireClosedLeaf(uint32 noteId,uint256[32] siblings)';
export const vaultInterface = new Interface([CHALLENGE_ABI, RAISE_ABI, RETIRE_ABI]);
export const GWEI = 1_000_000_000n;
export const DEFAULT_SEPOLIA_MAX_FEE_PER_GAS = 10n * GWEI;
export const DEFAULT_PRIORITY_FEE_PER_GAS = 1n * GWEI;
export const DEFAULT_FEE_CEILING = 10_000n * GWEI;
export const ABSOLUTE_FEE_CEILING = 1_000_000n * GWEI;
// geth's and reth's default --rpc.txfeecap: 1 ether of gas limit x maxFeePerGas.
export const DEFAULT_TX_FEE_CAP = 10n ** 18n;
export const UPSTREAM_TIMEOUT_MS = 8_000;
// Leaf retirements (about 6M gas each) follow only a missed defeat, which is
// rare and alarmed on, but any closed note simulates successfully, and a
// copy that mines after the leaf is gone still pays about 5.9M gas before it
// reverts StaleRoot. Retirement transactions signed per rolling day, one per
// nonce, are capped so that a compromised caller cannot spend the float
// meant for defeats and raises on them.
export const DEFAULT_MAX_RETIREMENTS_PER_DAY = 2n;
export const MAX_RETIREMENTS_PER_DAY_LIMIT = 1_000n;
export const RETIREMENT_WINDOW_MS = 86_400_000;
// The operator's retirement policy (design §5.4): the challenger retires a
// leaf only with --retire-on-miss (ZKAPI_CHALLENGE_RETIRE_ON_MISS, default
// true), only after a missed defeat, which is an escape that finalized. The
// signer applies the same switch and signs a retirement only for a note an
// escape finalized within the last ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS
// (default 50,400, about 7 days of 12 s blocks), so a compromised caller
// cannot spend retirements on notes closed by a mutual close or an expiry
// claim. The logs are read newest first, RETIREMENT_LOG_RANGE_BLOCKS at a time.
export const ESCAPE_FINALIZED_TOPIC = id('EscapeWithdrawalFinalized(uint32,uint256,uint128,address)');
export const DEFAULT_RETIREMENT_LOOKBACK_BLOCKS = 50_400n;
export const MAX_RETIREMENT_LOOKBACK_BLOCKS = 5_000_000n;
export const RETIREMENT_LOG_RANGE_BLOCKS = 10_000n;
// eth_getCode: zkapi-challenged checks the vault's, adapter's and Poseidon
// library's runtime codehashes against its deployment manifest through this
// RPC before it polls (design §5.5 startup probes).
const readMethods = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getLogs',
  'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getTransactionCount', 'eth_call', 'eth_estimateGas', 'eth_getBalance', 'eth_feeHistory', 'eth_getCode',
]);
// Callers may propose both EIP-1559 fee fields (or neither). Every other fee
// or envelope field (gasPrice, type, accessList, input, blob fields) is refused.
const transactionFields = new Set(['from', 'to', 'data', 'gas', 'nonce', 'value', 'chainId', 'maxFeePerGas', 'maxPriorityFeePerGas']);
const weiDetails = new Set(['base_fee_per_gas', 'max_fee_per_gas', 'max_priority_fee_per_gas', 'max_fee_per_gas_allowed', 'balance', 'required_balance']);
// geth refuses eth_sendRawTransaction before its pool when gas limit x
// maxFeePerGas exceeds --rpc.txfeecap: "tx fee (1.07 ether) exceeds the
// configured cap (1.00 ether)". Only a short message of that form counts.
const UPSTREAM_TX_FEE_CAP = /tx fee .* exceeds the configured cap/i;
const txFeeCapRefusal = error => typeof error?.message === 'string' && error.message.length <= 256 && UPSTREAM_TX_FEE_CAP.test(error.message);

export class RpcError extends Error {
  constructor(code, message, reason, details) {
    super(message); this.code = code;
    if (reason) this.data = { reason, ...details };
  }
}
const hex = value => `0x${value.toString(16)}`;
const min = (a, b) => (a < b ? a : b);
const QUANTITY = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;
function requireValid(condition, message, reason, details) {
  if (!condition) throw new RpcError(-32602, message, reason, details);
}
function address(value) {
  try { return getAddress(value).toLowerCase(); }
  catch { throw new RpcError(-32602, 'Invalid address'); }
}
function quantity(value, label) {
  requireValid(typeof value === 'string' && QUANTITY.test(value), `Invalid ${label}`);
  return BigInt(value);
}
// Malformed upstream answers are transient upstream failures, never invalid caller parameters.
function upstreamQuantity(value, message, reason = 'upstream_unavailable') {
  if (typeof value !== 'string' || !QUANTITY.test(value)) throw new RpcError(-32000, message, reason);
  return BigInt(value);
}

// Unset or empty means "use the default"; anything else must be a canonical
// positive decimal (no hex, sign, exponent, whitespace or leading zero).
function envInteger(env, name) {
  const value = env[name];
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,30}$/.test(value)) throw new ConfigError(`${name} must be a positive decimal integer`);
  return BigInt(value);
}
// A positive block count up to MAX_RETIREMENT_LOOKBACK_BLOCKS: unset or empty
// means the default.
function envLookback(env, name) {
  const value = envInteger(env, name);
  if (value !== undefined && value > MAX_RETIREMENT_LOOKBACK_BLOCKS) {
    throw new ConfigError(`${name} must be a decimal integer from 1 to ${MAX_RETIREMENT_LOOKBACK_BLOCKS}`);
  }
  return value;
}
// A count that may be zero: unset or empty means the default.
function envCount(env, name, limit) {
  const value = env[name];
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,30})$/.test(value) || BigInt(value) > limit) {
    throw new ConfigError(`${name} must be a decimal integer from 0 to ${limit}`);
  }
  return BigInt(value);
}
// Unset or empty means the default; otherwise exactly "true" or "false".
function envBoolean(env, name) {
  const value = env[name];
  if (value === undefined || value === '') return undefined;
  if (value !== 'true' && value !== 'false') throw new ConfigError(`${name} must be true or false`);
  return value === 'true';
}
export function parseSignerConfig(env) {
  if (env.ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI !== undefined) {
    throw new ConfigError('ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported; remove it and set ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI (the EIP-1559 fee cap in wei)');
  }
  const port = envInteger(env, 'ZKAPI_CHALLENGE_PORT') ?? 8547n;
  if (port > 65535n) throw new ConfigError('ZKAPI_CHALLENGE_PORT must be between 1 and 65535');
  return {
    chainId: parseChainId(env.ZKAPI_CHALLENGE_CHAIN_ID),
    privateKey: env.ZKAPI_CHALLENGE_PRIVATE_KEY,
    vault: env.ZKAPI_CHALLENGE_VAULT,
    rpcUrl: env.ZKAPI_CHALLENGE_RPC_URL,
    listenHost: env.ZKAPI_CHALLENGE_LISTEN_HOST || '127.0.0.1',
    port: Number(port),
    maxGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_GAS'),
    maxFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI'),
    priorityFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI'),
    maxPriorityFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI'),
    feeCeiling: envInteger(env, 'ZKAPI_CHALLENGE_FEE_CEILING_WEI'),
    txFeeCap: envInteger(env, 'ZKAPI_CHALLENGE_TX_FEE_CAP_WEI'),
    maxRetirementsPerDay: envCount(env, 'ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY', MAX_RETIREMENTS_PER_DAY_LIMIT),
    retireOnMiss: envBoolean(env, 'ZKAPI_CHALLENGE_RETIRE_ON_MISS'),
    retirementLookbackBlocks: envLookback(env, 'ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS'),
  };
}

// Upstream exceptions are never returned or logged: provider errors can contain
// URLs, credentials, raw signed transactions, or untrusted response bodies.
export function createUpstream(url, { timeoutMs = UPSTREAM_TIMEOUT_MS } = {}) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new ConfigError('Upstream RPC URL is invalid'); }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname))) {
    throw new ConfigError('Upstream RPC must use HTTPS or loopback HTTP');
  }
  let nextId = 0;
  return async (method, params) => {
    let body;
    try {
      const response = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }),
        signal: AbortSignal.timeout(timeoutMs), redirect: 'error',
      });
      if (!response.ok) throw new Error();
      body = await response.json();
    } catch { throw new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'); }
    if (body && typeof body === 'object' && body.error) {
      const reason = method === 'eth_sendRawTransaction' && txFeeCapRefusal(body.error) ? 'upstream_tx_fee_cap' : 'upstream_rejected';
      throw new RpcError(-32000, 'Upstream RPC rejected the request', reason);
    }
    if (!body || typeof body !== 'object' || !Object.hasOwn(body, 'result')) throw new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable');
    return body.result;
  };
}

export function createSigner({ privateKey, vault, rpc, chainId, maxGas = 12_000_000n, maxFeePerGas, priorityFeePerGas, maxPriorityFeePerGas, feeCeiling = DEFAULT_FEE_CEILING, txFeeCap = DEFAULT_TX_FEE_CAP, maxRetirementsPerDay, retireOnMiss, retirementLookbackBlocks, log = line => console.log(JSON.stringify(line)), now = () => Date.now(), ...unsupported }) {
  requireValid(Object.keys(unsupported).length === 0, 'Unsupported signer option');
  requireValid(chainId === 1n || chainId === 11155111n, 'Explicit challenge chain ID must be 1 or 11155111');
  // Mainnet never inherits the testnet default; null counts as unset.
  requireValid(maxFeePerGas != null || chainId !== 1n, 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI');
  const feeCapSource = maxFeePerGas == null ? 'default' : 'explicit';
  maxFeePerGas ??= DEFAULT_SEPOLIA_MAX_FEE_PER_GAS;
  let wallet;
  try { wallet = new Wallet(privateKey); } catch { throw new RpcError(-32602, 'Signer private key is invalid'); }
  const sender = wallet.address.toLowerCase();
  const destination = address(vault);
  requireValid(destination !== '0x0000000000000000000000000000000000000000', 'Vault must be nonzero');
  requireValid(typeof maxGas === 'bigint' && maxGas > 0n && maxGas <= 16_777_216n, 'Gas limit cap is invalid');
  const positive = value => typeof value === 'bigint' && value > 0n;
  requireValid(positive(feeCeiling) && feeCeiling <= ABSOLUTE_FEE_CEILING, 'Fee ceiling is invalid');
  requireValid(positive(txFeeCap), 'Transaction fee cap is invalid');
  maxRetirementsPerDay ??= DEFAULT_MAX_RETIREMENTS_PER_DAY;
  requireValid(typeof maxRetirementsPerDay === 'bigint' && maxRetirementsPerDay >= 0n && maxRetirementsPerDay <= MAX_RETIREMENTS_PER_DAY_LIMIT, 'Retirement budget is invalid');
  retireOnMiss ??= true;
  requireValid(typeof retireOnMiss === 'boolean', 'Retirement policy is invalid');
  retirementLookbackBlocks ??= DEFAULT_RETIREMENT_LOOKBACK_BLOCKS;
  requireValid(typeof retirementLookbackBlocks === 'bigint' && retirementLookbackBlocks > 0n
    && retirementLookbackBlocks <= MAX_RETIREMENT_LOOKBACK_BLOCKS, 'Retirement lookback is invalid');
  requireValid(positive(maxFeePerGas) && maxFeePerGas <= feeCeiling, 'Fee cap is invalid or exceeds the fee ceiling');
  requireValid(maxPriorityFeePerGas == null || (positive(maxPriorityFeePerGas) && maxPriorityFeePerGas <= maxFeePerGas), 'Priority fee cap is invalid or exceeds the fee cap');
  priorityFeePerGas ??= min(DEFAULT_PRIORITY_FEE_PER_GAS, maxPriorityFeePerGas ?? maxFeePerGas);
  requireValid(positive(priorityFeePerGas), 'Default priority fee is invalid or exceeds the priority fee cap');
  // A small multiple of the default tip, so a caller cannot make every
  // challenge pay the whole fee cap as tip unless the operator opts in.
  maxPriorityFeePerGas ??= min(maxFeePerGas, 10n * priorityFeePerGas);
  requireValid(priorityFeePerGas <= maxPriorityFeePerGas, 'Default priority fee is invalid or exceeds the priority fee cap');
  const feeBounds = { max_fee_per_gas: hex(maxFeePerGas), max_priority_fee_per_gas: hex(maxPriorityFeePerGas) };
  let queue = Promise.resolve();

  const policy = Object.freeze({
    sender, vault: destination, transaction_type: '0x2', fee_cap_source: feeCapSource,
    max_fee_per_gas: hex(maxFeePerGas), priority_fee_per_gas: hex(priorityFeePerGas),
    max_priority_fee_per_gas: hex(maxPriorityFeePerGas), fee_ceiling: hex(feeCeiling), tx_fee_cap_wei: hex(txFeeCap),
    max_gas: hex(maxGas), required_balance: hex(maxGas * maxFeePerGas),
    max_retirements_per_day: Number(maxRetirementsPerDay),
    retire_on_miss: retireOnMiss, retirement_lookback_blocks: Number(retirementLookbackBlocks),
  });

  // The leaf retirements broadcast (or possibly broadcast) in the last
  // RETIREMENT_WINDOW_MS, one entry per (note, nonce), by first signing time.
  // Each entry is one unit of the budget: a nonce mines at most one
  // transaction, and every retirement that mines costs about 6M gas, even
  // one that reverts StaleRoot because the leaf is already gone. A fee
  // replacement or re-send on a counted nonce therefore needs no new budget.
  // The same note on another nonce takes a new unit, and only once every
  // earlier counted nonce of that note is mined (retirement_in_flight):
  // copies cannot queue behind a pending retirement, each to pay about 5.9M
  // gas to revert once the first lands. A retirement refused for the budget
  // is counted and reported (status, /health, audit log). Kept in memory: a
  // restart of this sidecar starts a new window.
  const retirements = new Map();
  let retirementRefusals = 0;
  let lastRetirementRefusal = null;
  const retirementKey = (note, nonce) => `${note}:${nonce}`;
  function retirementsInWindow() {
    const cutoff = now() - RETIREMENT_WINDOW_MS;
    for (const [key, { at }] of retirements) if (at <= cutoff) retirements.delete(key);
    return retirements.size;
  }
  // Before any upstream call. Returns whether the retirement takes a new unit.
  function requireRetirementBudget(note, nonce) {
    const counted = retirementsInWindow();
    if (retirements.has(retirementKey(note, nonce))) return false;
    if (counted < Number(maxRetirementsPerDay)) return true;
    retirementRefusals += 1;
    lastRetirementRefusal = now();
    throw new RpcError(-32003, 'Leaf retirement budget for the last 24 hours is spent', 'retirement_budget_exhausted', {
      max_retirements_per_day: hex(maxRetirementsPerDay),
    });
  }
  // A note's retirement on a new nonce waits until the sender's latest nonce
  // count is past every nonce a retirement of that note was counted on. If
  // the earlier one retired the leaf, the simulation then refuses this one.
  async function requireNoRetirementInFlight(note) {
    retirementsInWindow();
    let earlier = -1;
    for (const entry of retirements.values()) if (entry.note === note && entry.nonce > earlier) earlier = entry.nonce;
    if (earlier < 0) return;
    const mined = upstreamQuantity(await rpc('eth_getTransactionCount', [sender, 'latest']), 'Upstream RPC returned an invalid nonce');
    if (mined > BigInt(earlier)) return;
    throw new RpcError(-32003, 'A retirement of this note may still mine on an earlier nonce', 'retirement_in_flight', {
      retirement_nonce: hex(earlier),
    });
  }
  // §5.4: a retirement follows a missed defeat, so an escape of the note
  // finalized. Looks for its EscapeWithdrawalFinalized log, newest blocks
  // first, within the lookback; an unreadable log range is a transient
  // upstream failure. Takes no budget either way.
  async function requireEscapeFinalized(note) {
    const latest = upstreamQuantity(await rpc('eth_blockNumber', []), 'Upstream RPC returned an invalid block number');
    const floor = latest >= retirementLookbackBlocks ? latest - retirementLookbackBlocks + 1n : 0n;
    const noteTopic = `0x${BigInt(note).toString(16).padStart(64, '0')}`;
    const finalizes = entry => entry && typeof entry === 'object' && entry.removed !== true
      && typeof entry.address === 'string' && entry.address.toLowerCase() === destination
      && Array.isArray(entry.topics) && entry.topics.length === 2
      && String(entry.topics[0]).toLowerCase() === ESCAPE_FINALIZED_TOPIC && String(entry.topics[1]).toLowerCase() === noteTopic;
    for (let to = latest; ; ) {
      const from = to - floor + 1n > RETIREMENT_LOG_RANGE_BLOCKS ? to - RETIREMENT_LOG_RANGE_BLOCKS + 1n : floor;
      const logs = await rpc('eth_getLogs', [{ address: destination, fromBlock: hex(from), toBlock: hex(to), topics: [ESCAPE_FINALIZED_TOPIC, noteTopic] }]);
      if (!Array.isArray(logs)) throw new RpcError(-32000, 'Upstream RPC returned invalid logs', 'upstream_unavailable');
      if (logs.some(finalizes)) return;
      if (from === floor) break;
      to = from - 1n;
    }
    throw new RpcError(-32003, 'No escape of this note finalized within the retirement lookback', 'retirement_not_after_escape', {
      note_id: hex(BigInt(note)), lookback_blocks: hex(retirementLookbackBlocks),
    });
  }
  function retirementStatus() {
    const refusedRecently = lastRetirementRefusal !== null && lastRetirementRefusal > now() - RETIREMENT_WINDOW_MS;
    return {
      retirements_last_24h: retirementsInWindow(),
      retirement_refusals: retirementRefusals,
      last_retirement_refusal_at: lastRetirementRefusal === null ? null : Math.floor(lastRetirementRefusal / 1000),
      refused_recently: refusedRecently,
    };
  }

  // Bounded, de-duplicated audit trail: one line per refusal transition of a
  // nonce and one per signed hash. No raw transactions, upstream text or keys.
  const lastRefusal = new Map();
  const loggedHashes = new Set();
  const evictOldest = (collection, key) => {
    if (!collection.has(key) && collection.size >= 256) collection.delete(collection.keys().next().value);
  };
  // Logging must never change an RPC outcome, whether log throws or rejects.
  function audit(line) {
    try {
      const entry = line();
      if (entry) Promise.resolve(log(entry)).catch(() => {});
    } catch { /* ignored */ }
  }
  function signedLine(transaction, hash) {
    lastRefusal.delete(transaction.nonce);
    if (loggedHashes.has(hash)) return null;
    evictOldest(loggedHashes, hash); loggedHashes.add(hash);
    return {
      event: 'challenge_signed', nonce: transaction.nonce, transaction_hash: hash,
      max_fee_per_gas_wei: transaction.maxFeePerGas.toString(10),
      max_priority_fee_per_gas_wei: transaction.maxPriorityFeePerGas.toString(10),
    };
  }
  function refusalLine(tx, error) {
    const nonce = typeof tx?.nonce === 'string' && QUANTITY.test(tx.nonce) && BigInt(tx.nonce) <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(BigInt(tx.nonce)) : null;
    const known = error instanceof RpcError;
    const { reason = known ? 'invalid_request' : 'internal_error', ...details } = (known && error.data) || {};
    const code = known ? error.code : -32603;
    const message = known ? error.message : 'Signer request failed';
    const transition = `${code}|${reason}|${message}`;
    if (lastRefusal.get(nonce) === transition) return null;
    evictOldest(lastRefusal, nonce); lastRefusal.set(nonce, transition);
    const line = { event: 'challenge_refused', nonce, code, reason, message };
    for (const [name, value] of Object.entries(details)) {
      if (name === 'transaction_hash') line.transaction_hash = value;
      else line[weiDetails.has(name) ? `${name}_wei` : name] = BigInt(value).toString(10);
    }
    return line;
  }

  async function checkChain() {
    const upstream = upstreamQuantity(await rpc('eth_chainId', []), 'Upstream RPC returned an invalid chain ID');
    if (upstream !== chainId) throw new RpcError(-32000, 'Upstream RPC does not match the configured chain', 'upstream_chain_mismatch');
  }
  // There is no legacy pricing fallback: a block without a base fee fails closed.
  async function latestBaseFee() {
    const block = await rpc('eth_getBlockByNumber', ['latest', false]);
    if (!block || typeof block !== 'object') throw new RpcError(-32000, 'Upstream block lacks a base fee', 'base_fee_unavailable');
    return {
      number: upstreamQuantity(block.number, 'Upstream block lacks a number', 'base_fee_unavailable'),
      baseFee: upstreamQuantity(block.baseFeePerGas, 'Upstream block lacks a base fee', 'base_fee_unavailable'),
    };
  }
  async function senderBalance() {
    return upstreamQuantity(await rpc('eth_getBalance', [sender, 'latest']), 'Upstream RPC returned an invalid balance');
  }
  async function status() {
    await checkChain();
    const [{ number, baseFee }, balance] = await Promise.all([latestBaseFee(), senderBalance()]);
    const warnings = [];
    if (baseFee > maxFeePerGas) warnings.push('base_fee_above_cap');
    // The next base fee may be 12.5% higher; the cap must still leave the default tip.
    if (baseFee * 9n + priorityFeePerGas * 8n > maxFeePerGas * 8n) warnings.push('base_fee_near_cap');
    if (balance < maxGas * maxFeePerGas) warnings.push('balance_below_required');
    // Bids near the fee cap at a gas limit near MAX_GAS would be refused.
    if (maxGas * maxFeePerGas > txFeeCap) warnings.push('tx_fee_cap_below_fee_cap');
    const { refused_recently: refusedRecently, ...retirement } = retirementStatus();
    // A retirement after a real missed defeat waits for the budget.
    if (refusedRecently) warnings.push('retirement_budget_exhausted');
    return { chain_id: hex(chainId), ...policy, ...retirement, block_number: hex(number), base_fee_per_gas: hex(baseFee), balance: hex(balance), warnings };
  }

  // Both fee fields or neither. Absent fields bid (cap, default tip), which
  // keeps daemons that predate caller-proposed fees working unchanged.
  function requestedFees(tx) {
    const proposed = tx.maxFeePerGas !== undefined;
    requireValid(proposed === (tx.maxPriorityFeePerGas !== undefined), 'maxFeePerGas and maxPriorityFeePerGas must be supplied together', 'fee_out_of_bounds', feeBounds);
    if (!proposed) return { maxFee: maxFeePerGas, tip: priorityFeePerGas };
    const maxFee = quantity(tx.maxFeePerGas, 'max fee per gas');
    const tip = quantity(tx.maxPriorityFeePerGas, 'max priority fee per gas');
    requireValid(tip > 0n && tip <= maxFee && maxFee <= maxFeePerGas && tip <= maxPriorityFeePerGas, 'Requested fees are outside the configured bounds', 'fee_out_of_bounds', feeBounds);
    return { maxFee, tip };
  }

  function validateTransaction(tx) {
    requireValid(tx && typeof tx === 'object' && !Array.isArray(tx), 'Expected transaction object');
    requireValid(Object.keys(tx).every(key => transactionFields.has(key)), 'Unsupported transaction field');
    requireValid(address(tx.from) === sender, 'Sender is not authorized');
    requireValid(address(tx.to) === destination, 'Destination is not authorized');
    requireValid(tx.value === undefined || quantity(tx.value, 'value') === 0n, 'Value must be zero');
    requireValid(tx.chainId === undefined || quantity(tx.chainId, 'chain ID') === chainId, 'Chain ID does not match the configured chain');
    const gasLimit = quantity(tx.gas, 'gas');
    requireValid(gasLimit > 0n, 'Invalid gas');
    requireValid(gasLimit <= maxGas, 'Gas exceeds configured limit', 'gas_limit_exceeds_cap', { max_gas: hex(maxGas) });
    const nonce = quantity(tx.nonce, 'nonce');
    requireValid(nonce <= BigInt(Number.MAX_SAFE_INTEGER), 'Nonce is too large');
    const { maxFee, tip } = requestedFees(tx);
    requireValid(isHexString(tx.data) && tx.data.length <= 16_386, 'Invalid calldata');
    let call;
    try {
      call = vaultInterface.parseTransaction({ data: tx.data });
      if (!call || vaultInterface.encodeFunctionData(call.fragment, call.args).toLowerCase() !== tx.data.toLowerCase()) throw new Error();
    } catch { throw new RpcError(-32602, 'Only canonical challengeEscapeWithdrawal, raiseEscapeConcession and retireClosedLeaf calls are authorized'); }
    if (call.name !== 'retireClosedLeaf') {
      // A defeat or raise carries a request proof, which must be this deployment's.
      requireValid(call.args.inputs.protocolVersion === 2n && call.args.inputs.chainId === chainId && address(call.args.inputs.contractAddress) === destination, 'Challenge proof targets another deployment');
      requireValid(isHexString(call.args.proof, 256), 'Challenge requires a 256-byte Groth16 proof');
    }
    return { type: 2, to: destination, data: tx.data, value: 0n, chainId, gasLimit, nonce: Number(nonce), maxFeePerGas: maxFee, maxPriorityFeePerGas: tip, accessList: [] };
  }

  async function simulate(call) {
    try { return await call(); }
    catch (error) {
      // Includes provider errors such as rate limits: transient, never invalid evidence.
      if (error instanceof RpcError && error.data?.reason === 'upstream_rejected') throw new RpcError(-32000, 'Challenge simulation failed', 'simulation_failed');
      throw error;
    }
  }
  async function knownTransaction(hash) {
    try {
      const known = await rpc('eth_getTransactionByHash', [hash]);
      return !!known && typeof known === 'object' && typeof known.hash === 'string' && known.hash.toLowerCase() === hash;
    } catch { return false; }
  }

  // Every failure before eth_sendRawTransaction is a definite non-broadcast.
  // From the broadcast on, the only failures are broadcast_ambiguous with the
  // hash and upstream_tx_fee_cap, which the node answers before its pool.
  async function signAndSend(tx) {
    const transaction = validateTransaction(tx);
    const call = vaultInterface.parseTransaction({ data: transaction.data });
    const retiredNote = call.name === 'retireClosedLeaf' ? call.args.noteId.toString(10) : null;
    if (retiredNote !== null && !retireOnMiss) {
      throw new RpcError(-32003, 'Leaf retirements are off (ZKAPI_CHALLENGE_RETIRE_ON_MISS=false)', 'retirement_disabled');
    }
    const newRetirement = retiredNote !== null && requireRetirementBudget(retiredNote, transaction.nonce);
    // Nodes refuse a gas limit x maxFeePerGas above their RPC fee cap, so
    // neither a proposed nor the default bid above it is ever offered.
    if (transaction.gasLimit * transaction.maxFeePerGas > txFeeCap) {
      throw new RpcError(-32003, 'Gas limit times max fee per gas exceeds the transaction fee cap', 'tx_fee_above_cap', {
        gas_limit: hex(transaction.gasLimit), max_fee_per_gas: hex(transaction.maxFeePerGas),
        tx_fee_cap_wei: hex(txFeeCap), max_fee_per_gas_allowed: hex(txFeeCap / transaction.gasLimit),
      });
    }
    await checkChain();
    if (newRetirement) {
      await requireNoRetirementInFlight(retiredNote);
      await requireEscapeFinalized(retiredNote);
    }
    const simulation = { from: sender, to: destination, data: transaction.data, value: '0x0' };
    await simulate(() => rpc('eth_call', [simulation, 'latest']));
    const estimate = upstreamQuantity(await simulate(() => rpc('eth_estimateGas', [simulation])), 'Upstream RPC returned an invalid gas estimate');
    requireValid(estimate <= transaction.gasLimit, 'Gas limit is below current estimate', 'gas_estimate_exceeds_limit', { estimate: hex(estimate) });
    const [{ baseFee }, balance] = await Promise.all([latestBaseFee(), senderBalance()]);
    if (baseFee > transaction.maxFeePerGas) {
      throw new RpcError(-32003, 'Base fee exceeds the transaction max fee per gas', 'base_fee_above_max_fee', { base_fee_per_gas: hex(baseFee), max_fee_per_gas: hex(transaction.maxFeePerGas) });
    }
    // Pools reserve gas limit x maxFeePerGas up front, whatever is finally paid.
    const required = transaction.gasLimit * transaction.maxFeePerGas;
    if (balance < required) {
      throw new RpcError(-32003, 'Sender balance cannot cover gas limit times max fee per gas', 'insufficient_balance', { balance: hex(balance), required_balance: hex(required) });
    }
    let raw, signed;
    try {
      raw = await wallet.signTransaction(transaction);
      signed = Transaction.from(raw);
    } catch { throw new RpcError(-32603, 'Signer self-check failed'); }
    const hash = keccak256(raw);
    if (signed.type !== 2 || signed.hash !== hash || signed.from?.toLowerCase() !== sender || signed.to?.toLowerCase() !== destination
        || signed.data.toLowerCase() !== transaction.data.toLowerCase() || signed.value !== 0n || signed.chainId !== chainId
        || signed.nonce !== transaction.nonce || signed.gasLimit !== transaction.gasLimit
        || signed.maxFeePerGas !== transaction.maxFeePerGas || signed.maxPriorityFeePerGas !== transaction.maxPriorityFeePerGas
        || signed.accessList.length !== 0) {
      throw new RpcError(-32603, 'Signer self-check failed');
    }
    const ambiguous = () => new RpcError(-32000, 'Transaction broadcast outcome is unknown', 'broadcast_ambiguous', { transaction_hash: hash });
    // From here the retirement may be broadcast: its nonce takes its budget.
    const key = retiredNote === null ? null : retirementKey(retiredNote, transaction.nonce);
    const counted = key !== null && !retirements.has(key);
    if (counted) retirements.set(key, { note: retiredNote, nonce: transaction.nonce, at: now() });
    let returned;
    try { returned = await rpc('eth_sendRawTransaction', [raw]); }
    catch (error) {
      // Signing is deterministic, so an identical rebroadcast ("already known") is idempotent.
      if (await knownTransaction(hash)) return { hash, transaction };
      // The node's own fee-cap refusal: definitely not broadcast, so no hash.
      if (error instanceof RpcError && error.data?.reason === 'upstream_tx_fee_cap') {
        if (counted) retirements.delete(key);
        throw new RpcError(-32003, 'Upstream RPC refused the transaction fee', 'upstream_tx_fee_cap', { gas_limit: hex(transaction.gasLimit), max_fee_per_gas: hex(transaction.maxFeePerGas) });
      }
      throw ambiguous();
    }
    if (typeof returned !== 'string' || returned.toLowerCase() !== hash) throw ambiguous();
    return { hash, transaction };
  }

  return {
    sender, vault: destination, chainId, policy, checkChain, status,
    retirementStatus: () => {
      const { refused_recently: _, ...retirement } = retirementStatus();
      return retirement;
    },
    async handle(method, params) {
      requireValid(Array.isArray(params), 'Expected positional parameters');
      if (method === 'eth_sendTransaction') {
        requireValid(params.length === 1, 'Expected one transaction');
        // Preserve the caller's durable nonce; never allocate a new nonce on
        // ambiguous sends. Serialize signing so callers cannot race fee checks.
        const result = queue.then(() => signAndSend(params[0])).then(
          ({ hash, transaction }) => { audit(() => signedLine(transaction, hash)); return hash; },
          error => { audit(() => refusalLine(params[0], error)); throw error; });
        queue = result.catch(() => {});
        return result;
      }
      if (method === 'zkapi_signerStatus') {
        requireValid(params.length === 0, 'Expected no parameters');
        return status();
      }
      if (!readMethods.has(method)) throw new RpcError(-32601, 'RPC method is not allowed');
      return rpc(method, params);
    },
  };
}
