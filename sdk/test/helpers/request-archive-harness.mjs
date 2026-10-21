import assert from 'node:assert/strict';
import { nativeFunding, nativeQuote } from './native-fixtures.mjs';

// Serial, copy-on-write transactions model IndexedDB's store locks and abort
// rollback, so the wallet store's atomic boundaries run as real code.
export function memoryIndexedDb() {
    const stores = new Map();
    const keys = new Map();
    const versions = [];
    let opened = false;
    let previous = Promise.resolve();
    const database = {
        close() {},
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) { stores.set(name, new Map()); keys.set(name, options.keyPath); },
        transaction(names) {
            const allowed = Array.isArray(names) ? names : [names];
            let release;
            const ready = previous;
            previous = new Promise(resolve => { release = resolve; });
            let pending = 0;
            let timer;
            let ended = false;
            let values;
            const start = ready.then(() => {
                values = new Map(allowed.map(name => [name, structuredClone(stores.get(name))]));
            });
            const schedule = () => {
                clearTimeout(timer);
                timer = setTimeout(() => {
                    if (ended || pending) return;
                    ended = true;
                    for (const [name, value] of values) stores.set(name, value);
                    transaction.oncomplete?.();
                    release();
                }, 0);
            };
            const transaction = {
                abort() {
                    if (ended) return;
                    ended = true;
                    clearTimeout(timer);
                    start.then(() => { transaction.onabort?.(); release(); });
                },
                objectStore(name) {
                    assert.ok(allowed.includes(name), `transaction does not cover ${name}`);
                    const request = operation => {
                        const result = {};
                        pending += 1;
                        start.then(() => {
                            if (ended) return;
                            try { result.result = structuredClone(operation(values.get(name))); result.onsuccess?.(); }
                            catch (error) { result.error = error; result.onerror?.(); }
                            finally { pending -= 1; schedule(); }
                        });
                        return result;
                    };
                    return {
                        get: key => request(store => store.get(key)),
                        getAll: () => request(store => [...store.values()]),
                        put: (value, key) => request(store => {
                            const identity = key ?? value[keys.get(name)];
                            store.set(identity, structuredClone(value)); return identity;
                        }),
                        delete: key => request(store => store.delete(key))
                    };
                }
            };
            return transaction;
        }
    };
    return {
        stores,
        versions,
        clear: () => { for (const store of stores.values()) store.clear(); },
        open(_name, version) {
            versions.push(version);
            const result = {};
            queueMicrotask(() => {
                result.result = database;
                if (!opened) { opened = true; result.onupgradeneeded?.(); }
                result.onsuccess?.();
            });
            return result;
        }
    };
}

// A compact Keccak-256 (Ethereum's pre-standard padding), used only to derive
// selectors and topics from their signatures inside tests.
const KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];
const KECCAK_ROTATIONS = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const LANE = (1n << 64n) - 1n;
const rotateLeft = (value, bits) => bits === 0 ? value
    : ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & LANE;

function keccakPermutation(state) {
    for (const constant of KECCAK_ROUND_CONSTANTS) {
        const parity = [0, 1, 2, 3, 4].map(x =>
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
        for (let index = 0; index < 25; index += 1) {
            const x = index % 5;
            state[index] ^= parity[(x + 4) % 5] ^ rotateLeft(parity[(x + 1) % 5], 1);
        }
        const rotated = new Array(25);
        for (let x = 0; x < 5; x += 1) {
            for (let y = 0; y < 5; y += 1) {
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLeft(state[x + 5 * y], KECCAK_ROTATIONS[x][y]);
            }
        }
        for (let x = 0; x < 5; x += 1) {
            for (let y = 0; y < 5; y += 1) {
                state[x + 5 * y] = rotated[x + 5 * y]
                    ^ ((~rotated[(x + 1) % 5 + 5 * y] & LANE) & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
}

export function keccak256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const rate = 136;
    const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
    padded.set(bytes);
    padded[bytes.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    const state = new Array(25).fill(0n);
    for (let offset = 0; offset < padded.length; offset += rate) {
        for (let lane = 0; lane < rate / 8; lane += 1) {
            let value = 0n;
            for (let byte = 7; byte >= 0; byte -= 1) value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]);
            state[lane] ^= value;
        }
        keccakPermutation(state);
    }
    let digest = '';
    for (let lane = 0; lane < 4; lane += 1) {
        let value = state[lane];
        for (let byte = 0; byte < 8; byte += 1) {
            digest += Number(value & 0xffn).toString(16).padStart(2, '0');
            value >>= 8n;
        }
    }
    return `0x${digest}`;
}

export const selectorOf = signature => keccak256Hex(signature).slice(0, 10);

export const DEPLOYMENT = 'request-archive-test';
export const VAULT = `0x${'22'.repeat(20)}`;
export const DESTINATION = `0x${'34'.repeat(20)}`;
export const SERVER = 'https://protocol.example';
export const KEYS = Object.freeze({
    state_signing_key: { x: '0x111', y: '0x112' },
    clearance_signing_key: { x: '0x113', y: '0x114' }
});
export const GENESIS_ANCHOR = '0x1234';
export const nullifierFor = anchor => `0x${(BigInt(anchor) + 0x5000n).toString(16)}`;
// N⁺ of a state, as the fake escape proof publishes it.
export const successorFor = anchor => `0x5${BigInt(nullifierFor(anchor)).toString(16)}`;
export const destinationBytes = address => [...Buffer.from(address.slice(2), 'hex')];
export const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;

/** The harness's next_anchor(N). */
export const derivedAnchor = nullifier => `0x${(BigInt(nullifier) + 0x9000n).toString(16)}`;

export function noteState(changes = {}) {
    return {
        protocol_version: 2,
        chain_id: 11155111,
        contract_address: VAULT,
        note_id: 7,
        deposit_amount: 5_000_000,
        expiry_ts: 2_000_000_000,
        current_balance: 5_000_000,
        current_anchor: GENESIS_ANCHOR,
        is_genesis: true,
        ...changes
    };
}

// The fields of the WebAssembly's BrowserNoteState (zkapi-browser lib.rs).
// Serde drops every other field of a state that passes through it, so the
// fake worker returns only these: host-side fields such as deposit_path
// survive only where the runtime carries them over itself.
export const BROWSER_NOTE_STATE_FIELDS = Object.freeze(['protocol_version', 'chain_id', 'contract_address', 'note_id',
    'secret_s', 'deposit_amount', 'expiry_ts', 'current_balance', 'balance_blinding', 'current_commitment_x',
    'current_commitment_y', 'current_anchor', 'is_genesis', 'state_signature', 'prev_anchor', 'bound_at_state']);

/** A note state as the WebAssembly returns it. */
export function wasmNoteState(state) {
    return Object.fromEntries(BROWSER_NOTE_STATE_FIELDS.filter(field => state?.[field] !== undefined)
        .map(field => [field, structuredClone(state[field])]));
}

/** The deposit-time path a note saves (Amendment A1). */
export const depositPath = (root = '0x51') => ({ active_root: root, siblings: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`) });

/**
 * `promise`, or a failed assertion once `ms` passes: a property broken into
 * a hang fails its test instead of stalling the suite.
 */
export function within(ms, promise, label) {
    let timer;
    const deadline = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new assert.AssertionError({ message: `${label} did not end within ${ms} ms` })), ms);
    });
    return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

export class HttpError extends Error {
    constructor(message, status, code, data = {}) {
        super(message);
        this.status = status;
        this.code = code;
        this.data = { error_code: code, error_message: message, ...data };
    }
}

/**
 * A fake protocol server, vault chain and proof worker around a real runtime
 * and the real IndexedDB-backed store. Only external observations are faked.
 */
export function createHarness(BrowserWalletRuntime, {
    vaultRevision = null,
    clearanceOwnershipProof = null,
    graceSeconds = null
} = {}) {
    const funding = nativeFunding({ contract_address: VAULT, protocol_server_url: SERVER });
    const quote = nativeQuote(funding);
    const chain = {
        root: '0x77',
        challenged: new Set(),
        effectiveExpiry: 2_000_000_000n,
        challengePeriod: 86_400n,
        reads: [],
        failRoot: false,
        // E6 reads: the note's status and the finalized block's timestamp.
        noteStatus: 'active',
        finalizedTimestamp: null
    };
    const worker = { calls: [], completions: [], proofs: 0, failWithdrawal: null, mutate: null,
        // The stale-device pre-check's verifier: true for a proof that verifies.
        verify: () => false };
    const server = {
        calls: [],
        leasePost: () => { throw new HttpError('Lease issuance is not configured.', 500, 'internal_error'); },
        leaseStatus: () => { throw new HttpError('Not found', 404, 'not_found'); },
        nullifier: () => ({ status: 'not_found', nullifier_status: 'unknown' }),
        requests: () => { throw new HttpError('Not found', 404, 'not_found'); },
        clearance: () => { throw new HttpError('Clearance is not configured.', 500, 'internal_error'); },
        expire: () => { throw new HttpError('The request may still be accepted.', 409, 'lease_pending'); },
        // GET /v2/nullifiers/{N⁺}/evidence (design §5.2): none by default.
        evidence: () => { throw new HttpError('No evidence.', 404, 'not_found'); }
    };
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: DEPLOYMENT };
    runtime.browserConfig = {
        trusted_deployment: {
            ...(vaultRevision != null ? { vault_revision: vaultRevision } : {}),
            ...(clearanceOwnershipProof != null ? { clearance_ownership_proof: clearanceOwnershipProof } : {})
        },
        ...(graceSeconds != null ? { unsettled_request_escape_after_seconds: graceSeconds } : {})
    };
    runtime.config = {
        funding,
        request_charge_cap: 1_000,
        policy_enabled: false,
        wallet_core: {
            protocol_version: 2,
            chain_id: funding.chain_id,
            contract_address: VAULT,
            request_charge_cap: 1_000,
            policy_charge_cap: 1_000,
            policy_enabled: false,
            ...structuredClone(KEYS)
        },
        proving_keys: { request: { url: 'request.pk' }, withdrawal: { url: 'withdrawal.pk' } },
        openrouter: { inference_base: 'https://openrouter.ai/api/v1', require_oa_key_source: false }
    };
    runtime.ownerId = 'this-tab';
    runtime.init = async () => {};
    runtime.exitChainStatus = async () => ({ noteStatus: chain.noteStatus,
        finalizedTimestamp: chain.finalizedTimestamp ?? Math.floor(Date.now() / 1000) });
    runtime.scheduleSettlement = () => {};
    runtime.nativeBillingQuote = async () => quote;
    runtime.verifyLease = async () => {};
    runtime.treePath = async noteId => ({
        active_root: chain.root,
        note_id: noteId,
        siblings: Array.from({ length: 32 }, (_, index) => `${chain.root}${index.toString(16)}`)
    });
    runtime.vaultWord = async data => {
        chain.reads.push(data);
        if (data === '0xfdab463d') {
            if (chain.failRoot) throw new Error('RPC unavailable');
            return BigInt(chain.root);
        }
        if (data === '0xf3f480d9') return chain.challengePeriod;
        if (data.startsWith('0x7cb4a03c')) return chain.effectiveExpiry;
        if (data.startsWith('0x6cda756a')) return chain.challenged.has(BigInt(`0x${data.slice(10)}`)) ? 1n : 0n;
        throw new Error(`Unexpected vault read ${data}`);
    };
    runtime.remoteJson = async (url, init = {}) => {
        const method = init.method || 'GET';
        assert.ok(url.startsWith(SERVER), `unexpected URL ${url}`);
        const path = url.slice(SERVER.length);
        const body = init.body == null ? null : JSON.parse(init.body);
        server.calls.push({ method, path, body, raw: init.body ?? null });
        if (method === 'POST' && path === '/v2/openrouter/leases') return server.leasePost(body, init.body);
        if (method === 'POST' && /^\/v2\/openrouter\/leases\/[^/]+\/expire$/.test(path)) return server.expire(body);
        if (method === 'POST' && /^\/v2\/openrouter\/leases\/[^/]+$/.test(path)) {
            return { status: 'finalized' };
        }
        if (method === 'GET' && path.startsWith('/v2/openrouter/leases/')) {
            return server.leaseStatus(decodeURIComponent(path.split('/').pop()));
        }
        if (method === 'GET' && /^\/v2\/nullifiers\/[^/]+\/evidence$/.test(path)) {
            return server.evidence(decodeURIComponent(path.split('/')[3]));
        }
        if (method === 'GET' && path.startsWith('/v2/nullifiers/')) {
            return server.nullifier(decodeURIComponent(path.split('/').pop()));
        }
        if (method === 'GET' && path.startsWith('/v2/requests/')) {
            return server.requests(decodeURIComponent(path.split('/').pop()));
        }
        if (method === 'POST' && path === '/v2/withdraw/clearance') return server.clearance(body);
        throw new Error(`Unexpected protocol call ${method} ${path}`);
    };
    runtime.worker = {
        async call(operation, payload) {
            if (operation === 'preloadRequestProver') return { status: 'ready' };
            worker.calls.push({ operation, payload: structuredClone(payload) });
            if (operation === 'walletStatus') {
                return { has_note: Boolean(payload.state), pending_request: Boolean(payload.journal?.exists),
                    note: payload.state ? { note_id: payload.state.note_id,
                        current_balance: payload.state.current_balance } : null };
            }
            if (operation === 'withdrawalNullifier') return nullifierFor(payload.state.current_anchor);
            if (operation === 'successorNullifier') return successorFor(payload.state.current_anchor);
            if (operation === 'verifyRequest') return worker.verify(payload);
            if (operation === 'notePathMatches') return worker.pathMatches ? worker.pathMatches(payload) : true;
            if (operation === 'rebuildTreePath') {
                // The rebuilt path at the last event's root (per-event checks
                // run in the real worker: zkapi-tree-rebuild tests).
                worker.rebuilds = (worker.rebuilds || 0) + 1;
                const root = payload.events.at(-1).root;
                return { active_root: root, note_id: payload.noteId,
                    siblings: Array.from({ length: 32 }, (_, index) => `${root}${index.toString(16)}`) };
            }
            if (operation === 'checkUnrecoverableResponse') {
                // S1, S2, S4 and S6 as the WebAssembly checks them, in the
                // harness's terms: this state's nullifier, a signed response
                // at the derived anchor.
                const { state, response } = payload;
                if (BigInt(response.request_nullifier) !== BigInt(nullifierFor(state.current_anchor))) {
                    throw new Error('response_identity_mismatch: another nullifier');
                }
                if (response.next_state_signature !== 'valid-state-signature') {
                    throw new Error('successor_signature_invalid: unsigned');
                }
                if (BigInt(response.next_anchor) !== BigInt(derivedAnchor(nullifierFor(state.current_anchor)))) {
                    throw new Error('invalid_successor: S4: not the derived anchor');
                }
                return { charge_applied: Number(response.charge_applied), next_anchor: response.next_anchor };
            }
            if (operation === 'prepareRequest') {
                const { state, args, config } = payload;
                const nullifier = nullifierFor(state.current_anchor);
                // C2, as the WebAssembly enforces it: one bound per state.
                const bound = Number(state.bound_at_state || 0);
                if (bound && bound !== Number(config.request_charge_cap)) {
                    throw new Error(`bound_fixed_at_state: request proofs at this state use the bound ${bound}`);
                }
                worker.proofs += 1;
                const request = {
                    client_request_id: args.client_request_id,
                    payload: args.payload,
                    payload_hash: `0x${(0xabc00 + worker.proofs).toString(16)}`,
                    public_inputs: {
                        protocol_version: 2, chain_id: funding.chain_id, contract_address: VAULT,
                        active_root: args.active_root, state_signing_key_x: KEYS.state_signing_key.x,
                        state_signing_key_y: KEYS.state_signing_key.y, request_time: args.request_time,
                        solvency_bound: config.request_charge_cap, request_nullifier: nullifier,
                        authorization_tag: '0xa', anonymous_commitment_x: '0xb', anonymous_commitment_y: '0xc'
                    },
                    proof: { backend: 'groth16_bn254', proof: `request-proof-${args.client_request_id}` }
                };
                return {
                    request: structuredClone(request),
                    state: { ...wasmNoteState(state), bound_at_state: Number(config.request_charge_cap) },
                    journal: {
                        exists: true,
                        client_request_id: args.client_request_id,
                        nullifier,
                        payload_hash: request.payload_hash,
                        user_rerandomization: `0x${(0xfeed00 + worker.proofs).toString(16)}`,
                        created_at_ms: args.created_at_ms,
                        prepared_request: request
                    }
                };
            }
            if (operation === 'completeResponse') {
                const { state, journal, response } = payload.args;
                worker.completions.push({ journal: structuredClone(journal), response: structuredClone(response) });
                if (!journal?.exists || response.client_request_id !== journal.client_request_id
                    || BigInt(response.request_nullifier) !== BigInt(journal.nullifier)) {
                    throw new Error('response request identity mismatch');
                }
                if (BigInt(response.charge_applied) > BigInt(journal.prepared_request.public_inputs.solvency_bound)
                    || BigInt(response.next_anchor) === 0n || !journal.user_rerandomization) {
                    throw new Error('invalid charge or next anchor');
                }
                if (worker.deriveAnchors && BigInt(response.next_anchor) !== BigInt(derivedAnchor(journal.nullifier))) {
                    throw new Error('invalid_successor: S4: the successor is not at the derived anchor next_anchor(N)');
                }
                if (response.next_state_signature !== 'valid-state-signature') {
                    throw new Error('successor_signature_invalid: the successor is not signed by the pinned state key');
                }
                if (state.bound_at_state && (BigInt(response.charge_applied) > BigInt(state.bound_at_state)
                    || BigInt(journal.prepared_request.public_inputs.solvency_bound) !== BigInt(state.bound_at_state))) {
                    throw new Error('invalid_successor: S3: charge or journal bound differs from the state bound');
                }
                return { ...wasmNoteState(state), current_balance: state.current_balance - Number(response.charge_applied),
                    current_anchor: response.next_anchor, is_genesis: false, state_signature: 'signed',
                    prev_anchor: state.current_anchor, bound_at_state: 0 };
            }
            if (operation === 'prepareWithdrawal') {
                const { state, args } = payload;
                if (worker.failWithdrawal) throw worker.failWithdrawal;
                const nullifier = nullifierFor(state.current_anchor);
                if (args.mode !== 'mutual' && args.clearance) throw new Error(`invalid_withdrawal_args: a ${args.mode} proof takes no clearance`);
                if (!args.valid_until) throw new Error('invalid_withdrawal_args: valid_until must be set');
                if (args.mode === 'mutual' && (!args.clearance?.signature
                    || BigInt(args.clearance.withdrawal_nullifier) !== BigInt(nullifier))) {
                    throw new Error('mutual withdrawal requires server clearance');
                }
                worker.proofs += 1;
                const plan = {
                    mode: args.mode,
                    public_inputs: {
                        protocol_version: 2, chain_id: funding.chain_id, contract_address: VAULT,
                        active_root: args.active_root,
                        state_signing_key_x: KEYS.state_signing_key.x, state_signing_key_y: KEYS.state_signing_key.y,
                        clearance_signing_key_x: KEYS.clearance_signing_key.x,
                        clearance_signing_key_y: KEYS.clearance_signing_key.y,
                        note_id: state.note_id, final_balance: state.current_balance - Number(args.conceded || 0),
                        destination: args.mode === 'ownership' ? Array(20).fill(0) : destinationBytes(args.destination),
                        withdrawal_nullifier: nullifier,
                        kind: { escape: 0, mutual: 1, ownership: 2 }[args.mode],
                        next_nullifier: args.mode === 'escape' ? `0x5${BigInt(nullifier).toString(16)}` : '0x0',
                        conceded: Number(args.conceded || 0),
                        valid_until: args.valid_until
                    },
                    proof: { backend: 'groth16_bn254', proof: Buffer.from(`${args.mode}-proof-${worker.proofs}`).toString('base64') }
                };
                worker.mutate?.(plan, payload);
                return plan;
            }
            throw new Error(`Unexpected worker operation ${operation}`);
        }
    };
    const workerOperations = name => worker.calls.filter(call => call.operation === name);
    const serverCalls = (method, prefix) => server.calls.filter(call => call.method === method && call.path.startsWith(prefix));
    const activeLease = (body, overrides = {}) => ({
        status: 'active',
        client_request_id: body.client_request_id,
        api_key: `key-${body.client_request_id}`,
        expires_at: Math.floor(Date.now() / 1000) + 300,
        settle_after: Math.floor(Date.now() / 1000) + 360,
        spending_limit_usd: 1,
        billing_quote: quote,
        ...overrides
    });
    // A finalized, signed receipt for exactly one saved request journal.
    const receiptFor = (journal, { charge = 25_000, nextAnchor = '0x9999', billingQuote = null, payload = {} } = {}) => ({
        status: 'ok',
        client_request_id: journal.client_request_id,
        request_nullifier: journal.nullifier,
        response_code: 200,
        response_payload: JSON.stringify({ type: 'openrouter_ephemeral_lease_settlement',
            billing_quote: billingQuote || JSON.parse(journal.prepared_request.payload).billing_quote, ...payload }),
        response_hash: '0x1',
        charge_applied: charge,
        next_commitment: { x: '0x1', y: '0x2' },
        next_anchor: nextAnchor,
        blind_delta_srv: '0x3',
        next_state_signature: 'valid-state-signature'
    });
    return { runtime, funding, quote, chain, worker, server, workerOperations, serverCalls, activeLease, receiptFor };
}
