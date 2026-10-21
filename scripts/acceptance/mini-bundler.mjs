// A minimal ERC-4337 bundler for the Anvil acceptance (scripts/v2-acceptance.mjs),
// harness-only: it serves the bundler JSON-RPC the SDK and clientd speak
// (eth_chainId, eth_supportedEntryPoints, eth_estimateUserOperationGas,
// eth_sendUserOperation, eth_getUserOperationByHash,
// eth_getUserOperationReceipt) against the canonical EntryPoint v0.7.0
// etched on the chain, and bundles each accepted operation with
// handleOps([op], account) sent from an unlocked Anvil account.
//
// What a real bundler does and this one does not: the ERC-7562 validation
// rules (no debug_traceCall simulation: the opcode and storage audit of the
// paymaster's validation is the Forge suite's, test/gasless/Validation.t.sol),
// reputation, a public mempool and gas-price competition. Its checks are the
// operation's shape, the local hash against the EntryPoint's getUserOpHash and
// a dry run of handleOps (eth_call), whose FailedOp / FailedOpWithRevert it
// returns as the JSON-RPC error, as reference bundlers do.
//
// The drill knobs: hold() makes methods unreachable (HTTP 503, the
// transport failure clients call bundler_unavailable); drop() accepts the
// next operation and then loses it, refusing its identical bytes afterwards
// as underpriced (a mempool that dropped it for its fee); defer() keeps
// accepted operations in the mempool until flush() or bundle(); bundle(ops)
// sends one handleOps with several operations in order (a griefing bundle);
// forgetReceipts() answers every receipt query with null (the inclusion must
// then be found by the EntryPoint's logs); release() undoes hold, drop and
// defer. Every send is recorded in `sends`.
//
// The encoding helpers are pure (no ethers): the harness's unit tests run
// them before any dependency is installed.
import http from 'node:http';

import { hexToBytes, keccak256 } from '../expected-codehashes.mjs';

export const ENTRY_POINT_V070 = '0x0000000071727de22e5e9d8baf0edac6f37da032';
const strip = hex => String(hex).replace(/^0x/i, '').toLowerCase();
const word = value => BigInt(value).toString(16).padStart(64, '0');
const quantity = value => `0x${BigInt(value).toString(16)}`;
const selectorOf = signature => keccak256(new TextEncoder().encode(signature)).slice(0, 10);
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX = /^0x([0-9a-fA-F]{2})*$/;
const QUANTITY = /^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const PACKED_TUPLE = '(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)';
export const SELECTORS = Object.freeze({
    handleOps: selectorOf(`handleOps(${PACKED_TUPLE}[],address)`),
    getUserOpHash: selectorOf(`getUserOpHash(${PACKED_TUPLE})`),
    getNonce: selectorOf('getNonce(address,uint192)'),
    failedOp: selectorOf('FailedOp(uint256,string)'),
    failedOpWithRevert: selectorOf('FailedOpWithRevert(uint256,string,bytes)'),
    withdraw: selectorOf('withdraw(bytes)'),
    execute: selectorOf('execute(address,bytes)'),
});
export const TOPICS = Object.freeze({
    userOperationEvent: keccak256(new TextEncoder().encode('UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)')),
    userOperationRevertReason: keccak256(new TextEncoder().encode('UserOperationRevertReason(bytes32,address,uint256,bytes)')),
    beforeExecution: keccak256(new TextEncoder().encode('BeforeExecution()')),
});
// The gas fields of an unpacked v0.7 operation, each a JSON-RPC quantity.
const GAS_FIELDS = ['nonce', 'callGasLimit', 'verificationGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas'];
const PAYMASTER_GAS_FIELDS = ['paymasterVerificationGasLimit', 'paymasterPostOpGasLimit'];

// ---------------------------------------------------------------- the operation

/**
 * The unpacked v0.7 operation of eth_sendUserOperation, checked field by
 * field (addresses, hex bytes, canonical quantities, a factory with its data,
 * a paymaster with both gas limits, a 128-bit gas or fee field); throws a
 * message naming the first bad field.
 */
export function checkUserOperation(op) {
    if (!op || typeof op !== 'object' || Array.isArray(op)) throw new Error('the user operation is not an object');
    if (!ADDRESS.test(op.sender || '')) throw new Error('sender is not an address');
    for (const field of GAS_FIELDS) {
        if (!QUANTITY.test(op[field] || '')) throw new Error(`${field} is not a canonical hex quantity`);
        if (field !== 'nonce' && BigInt(op[field]) >= 1n << 128n) throw new Error(`${field} does not fit in 128 bits`);
    }
    for (const field of ['callData', 'signature']) if (!HEX.test(op[field] || '')) throw new Error(`${field} is not hex bytes`);
    if (op.factory != null) {
        if (!ADDRESS.test(op.factory)) throw new Error('factory is not an address');
        if (!HEX.test(op.factoryData || '')) throw new Error('factoryData is not hex bytes');
    } else if (op.factoryData != null && op.factoryData !== '0x') {
        throw new Error('factoryData without a factory');
    }
    if (op.paymaster != null) {
        if (!ADDRESS.test(op.paymaster)) throw new Error('paymaster is not an address');
        for (const field of PAYMASTER_GAS_FIELDS) {
            if (!QUANTITY.test(op[field] || '')) throw new Error(`${field} is not a canonical hex quantity`);
            if (BigInt(op[field]) >= 1n << 128n) throw new Error(`${field} does not fit in 128 bits`);
        }
        if (!HEX.test(op.paymasterData || '0x')) throw new Error('paymasterData is not hex bytes');
    }
    if (strip(op.signature).length !== 130) throw new Error('signature is not 65 bytes');
    return op;
}

/**
 * The PackedUserOperation of v0.7 (the form the EntryPoint hashes and
 * handleOps takes): initCode = factory ‖ factoryData, accountGasLimits =
 * verificationGasLimit ‖ callGasLimit (16 bytes each), gasFees =
 * maxPriorityFeePerGas ‖ maxFeePerGas, paymasterAndData = paymaster ‖
 * paymasterVerificationGasLimit (16) ‖ paymasterPostOpGasLimit (16) ‖ paymasterData.
 */
export function packUserOperation(op) {
    const u128 = value => BigInt(value).toString(16).padStart(32, '0');
    return {
        sender: `0x${strip(op.sender)}`,
        nonce: BigInt(op.nonce),
        initCode: op.factory ? `0x${strip(op.factory)}${strip(op.factoryData || '0x')}` : '0x',
        callData: `0x${strip(op.callData)}`,
        accountGasLimits: `0x${u128(op.verificationGasLimit)}${u128(op.callGasLimit)}`,
        preVerificationGas: BigInt(op.preVerificationGas),
        gasFees: `0x${u128(op.maxPriorityFeePerGas)}${u128(op.maxFeePerGas)}`,
        paymasterAndData: op.paymaster
            ? `0x${strip(op.paymaster)}${u128(op.paymasterVerificationGasLimit)}${u128(op.paymasterPostOpGasLimit)}${strip(op.paymasterData || '0x')}`
            : '0x',
        signature: `0x${strip(op.signature || '0x')}`,
    };
}

const hashBytes = hex => keccak256(hexToBytes(hex.startsWith('0x') ? hex : `0x${hex}`));

/**
 * UserOperationLib.hash and EntryPoint.getUserOpHash of v0.7.0:
 * keccak256(abi.encode(keccak256(abi.encode(sender, nonce, keccak(initCode),
 * keccak(callData), accountGasLimits, preVerificationGas, gasFees,
 * keccak(paymasterAndData))), entryPoint, chainId)).
 */
export function userOperationHash(packed, entryPoint, chainId) {
    const inner = hashBytes(`0x${word(packed.sender)}${word(packed.nonce)}${strip(hashBytes(packed.initCode))}`
        + `${strip(hashBytes(packed.callData))}${strip(packed.accountGasLimits)}${word(packed.preVerificationGas)}`
        + `${strip(packed.gasFees)}${strip(hashBytes(packed.paymasterAndData))}`);
    return hashBytes(`0x${strip(inner)}${word(entryPoint)}${word(chainId)}`);
}

function bytesTail(hex) {
    const data = strip(hex);
    return `${word(data.length / 2)}${data.padEnd(Math.ceil(data.length / 64) * 64, '0')}`;
}

/** The ABI encoding of one PackedUserOperation tuple (nine head words, four dynamic tails). */
export function encodePackedTuple(packed) {
    const tails = [packed.initCode, packed.callData, packed.paymasterAndData, packed.signature].map(bytesTail);
    const offsets = [];
    let offset = 9 * 32;
    for (const tail of tails) {
        offsets.push(offset);
        offset += tail.length / 2;
    }
    return `${word(packed.sender)}${word(packed.nonce)}${word(offsets[0])}${word(offsets[1])}${strip(packed.accountGasLimits)}`
        + `${word(packed.preVerificationGas)}${strip(packed.gasFees)}${word(offsets[2])}${word(offsets[3])}${tails.join('')}`;
}

/** handleOps(ops, beneficiary) calldata for packed operations, in order. */
export function encodeHandleOps(packedOps, beneficiary) {
    const tuples = packedOps.map(encodePackedTuple);
    const heads = [];
    let offset = tuples.length * 32;
    for (const tuple of tuples) {
        heads.push(word(offset));
        offset += tuple.length / 2;
    }
    return `${SELECTORS.handleOps}${word(0x40)}${word(beneficiary)}${word(tuples.length)}${heads.join('')}${tuples.join('')}`;
}

/** EntryPoint.getUserOpHash(op) calldata. */
export function encodeGetUserOpHash(packed) {
    return `${SELECTORS.getUserOpHash}${word(0x20)}${encodePackedTuple(packed)}`;
}

/** The vault call inside S.withdraw(bytes) callData (0x for a FORWARD), or null for another call. */
export function vaultCallOf(callData) {
    const data = strip(callData);
    if (`0x${data.slice(0, 8)}` !== SELECTORS.withdraw || data.length < 8 + 128) return null;
    if (BigInt(`0x${data.slice(8, 72)}`) !== 0x20n) return null;
    const length = Number(BigInt(`0x${data.slice(72, 136)}`));
    return `0x${data.slice(136, 136 + length * 2)}`;
}

// ---------------------------------------------------------------- EntryPoint answers

function abiString(body, offsetWord) {
    const offset = Number(BigInt(`0x${body.slice(offsetWord * 64, offsetWord * 64 + 64)}`)) * 2;
    const length = Number(BigInt(`0x${body.slice(offset, offset + 64)}`)) * 2;
    return body.slice(offset + 64, offset + 64 + length);
}

/**
 * The FailedOp(opIndex, reason) or FailedOpWithRevert(opIndex, reason, inner)
 * revert of handleOps, decoded ({ opIndex, reason, aa, inner }), or null for
 * any other revert data.
 */
export function decodeFailedOp(data) {
    const hex = typeof data === 'string' ? data.toLowerCase() : '';
    const selector = hex.slice(0, 10);
    if (selector !== SELECTORS.failedOp && selector !== SELECTORS.failedOpWithRevert) return null;
    const body = hex.slice(10);
    const reason = Buffer.from(abiString(body, 1), 'hex').toString('utf8');
    const inner = selector === SELECTORS.failedOpWithRevert ? `0x${abiString(body, 2)}` : null;
    return { opIndex: Number(BigInt(`0x${body.slice(0, 64)}`)), reason, aa: /^(AA\d\d)\b/.exec(reason)?.[1] ?? null, inner };
}

/**
 * The JSON-RPC error a reference bundler answers for a dry run's FailedOp
 * (ERC-7769: -32501 the paymaster refused, -32503 outside its time range,
 * -32500 any other validation failure), carrying the revert data.
 */
export function failedOpRpcError(data) {
    const failed = decodeFailedOp(data);
    if (!failed) return { code: -32500, message: 'handleOps reverted without a FailedOp', data };
    const time = ['AA22', 'AA32'].includes(failed.aa);
    const code = time ? -32503 : failed.aa?.startsWith('AA3') ? -32501 : -32500;
    const message = failed.inner && failed.inner !== '0x' ? `FailedOpWithRevert: ${failed.reason} ${failed.inner}` : `FailedOp: ${failed.reason}`;
    return { code, message, data };
}

const topicAddress = topic => `0x${strip(topic).slice(24)}`;

/**
 * The UserOperationEvent of `hash` in a bundle transaction's receipt and the
 * ERC-4337 receipt shape eth_getUserOperationReceipt answers: the
 * operation's own logs are those after the previous operation's event (or
 * the bundle's BeforeExecution) and up to its own event. null when the
 * receipt carries no event of `hash` from `entryPoint`.
 */
export function userOperationReceipt(receipt, { hash, entryPoint }) {
    const logs = receipt?.logs || [];
    const fromEntryPoint = log => strip(log.address) === strip(entryPoint);
    const index = logs.findIndex(log => fromEntryPoint(log) && strip(log.topics?.[0]) === strip(TOPICS.userOperationEvent)
        && strip(log.topics?.[1]) === strip(hash));
    if (index < 0) return null;
    const event = logs[index];
    let start = index - 1;
    while (start >= 0 && !(fromEntryPoint(logs[start]) && [TOPICS.userOperationEvent, TOPICS.beforeExecution]
        .some(topic => strip(logs[start].topics?.[0]) === strip(topic)))) start -= 1;
    const data = strip(event.data);
    const at = n => BigInt(`0x${data.slice(n * 64, n * 64 + 64)}`);
    const revert = logs.slice(start + 1, index).find(log => fromEntryPoint(log)
        && strip(log.topics?.[0]) === strip(TOPICS.userOperationRevertReason) && strip(log.topics?.[1]) === strip(hash));
    let reason = null;
    if (revert) reason = `0x${abiString(strip(revert.data), 1)}`;
    return {
        userOpHash: `0x${strip(hash)}`,
        entryPoint: `0x${strip(entryPoint)}`,
        sender: topicAddress(event.topics[2]),
        nonce: quantity(at(0)),
        paymaster: topicAddress(event.topics[3]),
        actualGasCost: quantity(at(2)),
        actualGasUsed: quantity(at(3)),
        success: at(1) === 1n,
        reason,
        logs: logs.slice(start + 1, index),
        receipt,
    };
}

/**
 * The gas a bundle transaction is sent with: every operation's limits
 * (verification, call, preVerification and both paymaster limits) plus
 * 300,000 for the EntryPoint around them.
 */
export function bundleGas(ops) {
    return ops.reduce((sum, op) => sum + BigInt(op.verificationGasLimit) + BigInt(op.callGasLimit) + BigInt(op.preVerificationGas)
        + BigInt(op.paymasterVerificationGasLimit ?? 0) + BigInt(op.paymasterPostOpGasLimit ?? 0), 0n) + 300_000n;
}

/** The kind of a sponsored withdraw(bytes) callData by its vault call: 1 close, 2 escape, 3 finalize, 4 forward. */
export function sponsoredKind(callData) {
    const call = vaultCallOf(callData);
    if (call == null) return null;
    if (call === '0x') return 4;
    const selector = call.slice(0, 10);
    if (selector === '0xff8f5585') return 3;
    if (selector === '0xa38d62aa') return 2;
    if (selector === '0x72cd2e44') return 1;
    return null;
}

/**
 * eth_estimateUserOperationGas from the profile's pinned gas policy (design
 * §3.1: clients sign the pinned defaults; an estimate is a cross-check): the
 * defaults of the operation's kind, the init default when it creates S, and
 * its own preVerificationGas (this bundler asks for no more).
 */
export function estimateFromPolicy(op, gasPolicy) {
    const kind = sponsoredKind(op.callData);
    const index = (kind ?? 1) - 1;
    return {
        preVerificationGas: quantity(op.preVerificationGas ?? gasPolicy.pvg_floor),
        verificationGasLimit: quantity(op.factory ? gasPolicy.verification_default_init : gasPolicy.verification_default),
        callGasLimit: quantity(gasPolicy.call_default[index]),
        paymasterVerificationGasLimit: quantity(gasPolicy.pm_verification_default),
        paymasterPostOpGasLimit: quantity(gasPolicy.postop_default),
    };
}

// ---------------------------------------------------------------- the service

function postJson(url, payload) {
    const target = new URL(url);
    return new Promise((resolve, reject) => {
        const outgoing = http.request(target, { method: 'POST', agent: new http.Agent({ keepAlive: false }),
            headers: { 'content-type': 'application/json' } }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('error', reject);
            incoming.on('end', () => {
                try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (error) { reject(error); }
            });
        });
        outgoing.setTimeout(60_000, () => outgoing.destroy(new Error('mini bundler: RPC timed out')));
        outgoing.on('error', reject);
        outgoing.end(JSON.stringify(payload));
    });
}

class RpcError extends Error {
    constructor(error) {
        super(error?.message || 'JSON-RPC error');
        this.rpc = error;
    }
}
const revertDataOf = error => [error?.data, error?.data?.data].find(value => typeof value === 'string' && value.startsWith('0x')) ?? null;

/**
 * Starts the bundler on a loopback port with the harness's `serve(handler)`.
 * `account` is an unlocked Anvil account: it sends every handleOps and is its
 * beneficiary. `gasPolicy` is the profile's `gasless.gas_policy`.
 */
export async function startMiniBundler({ rpcUrl, entryPoint = ENTRY_POINT_V070, account, serve, gasPolicy, chainId = null }) {
    let id = 0;
    const rpc = async (method, params = []) => {
        const reply = await postJson(rpcUrl, { jsonrpc: '2.0', id: ++id, method, params });
        if (reply.error) throw new RpcError(reply.error);
        return reply.result;
    };
    const chain = chainId ?? Number(BigInt(await rpc('eth_chainId')));
    const ops = new Map();
    const sends = [];
    const bundles = [];
    const state = { held: new Set(), dropNext: false, deferred: false, forgetReceipts: false };
    const requests = [];

    async function sendBundle(entries, label) {
        const data = encodeHandleOps(entries.map(entry => entry.packed), account);
        const gas = bundleGas(entries.map(entry => entry.json));
        const bundle = { label, at: Date.now(), hashes: entries.map(entry => entry.hash), gas: Number(gas) };
        bundles.push(bundle);
        let transactionHash;
        try {
            transactionHash = await rpc('eth_sendTransaction', [{ from: account, to: entryPoint, data, gas: quantity(gas) }]);
        } catch (error) {
            bundle.error = error.rpc ?? { message: error.message };
            for (const entry of entries) Object.assign(entry, { status: 'failed', error: bundle.error });
            return { bundle, receipt: null };
        }
        let receipt = null;
        for (let i = 0; i < 600 && !receipt; i++) {
            receipt = await rpc('eth_getTransactionReceipt', [transactionHash]);
            if (!receipt) await new Promise(resolve => setTimeout(resolve, 100));
        }
        if (!receipt) throw new Error(`mini bundler: no receipt for ${transactionHash}`);
        Object.assign(bundle, { transactionHash, status: Number(BigInt(receipt.status)), blockNumber: Number(BigInt(receipt.blockNumber)),
            gasUsed: Number(BigInt(receipt.gasUsed)) });
        for (const entry of entries) {
            const included = receipt.status === '0x1' && userOperationReceipt(receipt, { hash: entry.hash, entryPoint });
            Object.assign(entry, included ? { status: 'included', transactionHash, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash }
                : { status: 'failed', transactionHash });
        }
        return { bundle, receipt };
    }

    // An operation from JSON: checked, packed, hashed locally and by the EntryPoint.
    async function admit(json) {
        checkUserOperation(json);
        const packed = packUserOperation(json);
        const hash = userOperationHash(packed, entryPoint, chain);
        const onChain = await rpc('eth_call', [{ to: entryPoint, data: encodeGetUserOpHash(packed) }, 'latest']);
        if (onChain.toLowerCase() !== hash) throw new Error(`the local hash ${hash} is not the EntryPoint's ${onChain}`);
        return { json, packed, hash };
    }

    async function dryRun(entries) {
        try {
            await rpc('eth_call', [{ from: account, to: entryPoint, data: encodeHandleOps(entries.map(entry => entry.packed), account) }, 'latest']);
            return null;
        } catch (error) {
            if (!(error instanceof RpcError)) throw error;
            return failedOpRpcError(revertDataOf(error.rpc) ?? '0x');
        }
    }

    const methods = {
        eth_chainId: async () => quantity(chain),
        eth_supportedEntryPoints: async () => [entryPoint],
        eth_estimateUserOperationGas: async ([op, ep]) => {
            if (String(ep).toLowerCase() !== entryPoint.toLowerCase()) throw Object.assign(new Error('unsupported EntryPoint'), { rpcCode: -32602 });
            return estimateFromPolicy(op, gasPolicy);
        },
        eth_sendUserOperation: async ([op, ep]) => {
            const send = { at: Date.now(), sender: op?.sender?.toLowerCase() ?? null, nonce: op?.nonce ?? null, hash: null, outcome: null };
            sends.push(send);
            const refuse = (code, message, data) => {
                send.outcome = 'refused';
                send.error = { code, message, ...(data ? { data } : {}) };
                throw Object.assign(new Error(message), { rpcCode: code, rpcData: data });
            };
            if (String(ep).toLowerCase() !== entryPoint.toLowerCase()) refuse(-32602, `unsupported EntryPoint ${ep}`);
            let entry;
            try {
                entry = await admit(op);
            } catch (error) {
                refuse(-32602, `invalid UserOperation: ${error.message}`);
            }
            send.hash = entry.hash;
            send.kind = sponsoredKind(op.callData);
            const known = ops.get(entry.hash);
            if (known?.status === 'dropped') {
                refuse(-32602, 'replacement underpriced: maxFeePerGas and maxPriorityFeePerGas are too low for this mempool');
            }
            if (known && ['pending', 'included'].includes(known.status)) {
                send.outcome = 'already_known';
                return entry.hash;
            }
            const failure = await dryRun([entry]);
            if (failure) refuse(failure.code, failure.message, failure.data);
            entry.submittedAt = Date.now();
            ops.set(entry.hash, entry);
            if (state.dropNext) {
                state.dropNext = false;
                entry.status = 'dropped';
                send.outcome = 'accepted_then_dropped';
                return entry.hash;
            }
            if (state.deferred) {
                entry.status = 'pending';
                send.outcome = 'pending';
                return entry.hash;
            }
            entry.status = 'pending';
            const { bundle } = await sendBundle([entry], 'single');
            send.outcome = entry.status;
            send.transaction = bundle.transactionHash ?? null;
            return entry.hash;
        },
        eth_getUserOperationByHash: async ([hash]) => {
            const entry = ops.get(String(hash).toLowerCase());
            if (!entry || ['dropped', 'failed'].includes(entry.status)) return null;
            return { userOperation: entry.json, entryPoint, transactionHash: entry.transactionHash ?? null,
                blockNumber: entry.blockNumber ?? null, blockHash: entry.blockHash ?? null };
        },
        eth_getUserOperationReceipt: async ([hash]) => {
            if (state.forgetReceipts) return null;
            const entry = ops.get(String(hash).toLowerCase());
            if (!entry?.transactionHash || entry.status !== 'included') return null;
            const receipt = await rpc('eth_getTransactionReceipt', [entry.transactionHash]);
            return receipt ? userOperationReceipt(receipt, { hash: entry.hash, entryPoint }) : null;
        },
    };

    const url = await serve(async (req, res) => {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        let call;
        try { call = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { call = {}; }
        requests.push({ method: call.method ?? null, at: Date.now() });
        if (state.held.has('*') || state.held.has(call.method)) {
            res.writeHead(503, { 'content-type': 'application/json' });
            return res.end(JSON.stringify({ error: 'mini bundler held' }));
        }
        const answer = result => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: call.id ?? null, ...result }));
        };
        const handler = methods[call.method];
        if (!handler) return answer({ error: { code: -32601, message: `method ${call.method} not supported` } });
        try {
            return answer({ result: await handler(call.params ?? []) });
        } catch (error) {
            const code = error.rpcCode ?? -32603;
            return answer({ error: { code, message: error.message, ...(error.rpcData ? { data: error.rpcData } : {}) } });
        }
    });

    return {
        url,
        account,
        entryPoint,
        sends,
        bundles,
        requests,
        ops,
        /** Methods (default: eth_sendUserOperation; '*' for all) answer HTTP 503 until release(). */
        hold(held = ['eth_sendUserOperation']) { for (const method of held) state.held.add(method); },
        /** The next accepted operation is lost; its identical bytes are refused as underpriced afterwards. */
        drop() { state.dropNext = true; },
        /** Accepted operations stay in the mempool until flush() or bundle(). */
        defer(on = true) { state.deferred = on; },
        /** Every receipt query answers null (until forgetReceipts(false)). */
        forgetReceipts(on = true) { state.forgetReceipts = on; },
        release() { state.held.clear(); state.dropNext = false; state.deferred = false; state.forgetReceipts = false; },
        /** The mempool's operations not yet bundled. */
        pending() { return [...ops.values()].filter(entry => entry.status === 'pending' && !entry.transactionHash); },
        /** One handleOps with every pending operation, in arrival order. */
        async flush() {
            const pending = this.pending();
            return pending.length ? sendBundle(pending, 'flush') : null;
        },
        /**
         * One handleOps with `items` in order: unpacked JSON operations (any
         * sender, a self-funded account's included) or hashes of operations in
         * the mempool. No dry run: the bundle may fail on chain, as a
         * griefing bundler's would.
         */
        async bundle(items) {
            const entries = [];
            for (const item of items) {
                if (typeof item === 'string') {
                    const entry = ops.get(item.toLowerCase());
                    if (!entry) throw new Error(`mini bundler: unknown operation ${item}`);
                    entries.push(entry);
                } else {
                    const entry = await admit(item);
                    entry.status = 'pending';
                    entry.external = true;
                    ops.set(entry.hash, entry);
                    entries.push(entry);
                }
            }
            return sendBundle(entries, 'bundle');
        },
        summary() {
            return { url, account, sends: sends.map(send => ({ ...send })), bundles: bundles.map(bundle => ({ ...bundle })),
                requests: requests.length, operations: [...ops.values()].map(entry => ({ hash: entry.hash, sender: entry.json.sender,
                    nonce: entry.json.nonce, status: entry.status, transaction: entry.transactionHash ?? null, external: entry.external === true })) };
        },
    };
}
