#!/usr/bin/env node
// The browser SDK (sdk/: zkapiClient, browserWalletRuntime and the proof
// worker over sdk/wasm) in Node, for scripts/v2-acceptance.mjs. One wallet
// per process: the harness starts it with the host's browser-config URL and
// drives it over JSON lines on stdin/stdout (logs go to stderr).
//
// Only what a browser provides is substituted: an in-memory IndexedDB
// (sdk/test/helpers), localStorage, location and window, the proof worker
// run in this thread (the real zkapiWasmWorker.js `execute`), file:// fetches
// of the WebAssembly, and an EIP-1193 wallet that signs with an unlocked
// Anvil account. The device clock is shiftable (`clock`), so an exit decision
// can be taken at the settlement time T without waiting for it.
//
// Drill hooks, each off until the harness turns it on:
// - `wallet_reject`: the wallet refuses to send calls to the listed
//   selectors, as a user who rejects the wallet prompt;
// - `hold_successors`: the operator's signed successor reaches the SDK only
//   once an exit proof was released (a late successor, E4.6): until then
//   every recovery answer reads as still reserved;
// - `drop_deposit_path`: the saved deposit-time path is lost, so an exit
//   takes its path from the indexer or the vault's logs.
//
// Gasless withdrawals (ERC-4337, `fees: 'payout'`): `withdraw` and `finalize`
// pass `fees` and the other sponsored options through; `collect`
// (collectTransitBalance), `sweep` (sweepTransit), `claim_credit`
// (claimGaslessCredit), `quote` (gaslessWithdrawalQuote), `availability`
// (gaslessAvailability), `set_bundler` (setBundlerUrl) and `gasless_timing`
// (shortens the submission loop's waits, as the SDK's own tests do). The
// wallet answers `personal_sign` with the Anvil account (recorded in
// `signatures`), so a sponsored operation is signed and never sent by it.
import path from 'node:path';
import readline from 'node:readline';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sdk = file => pathToFileURL(path.join(ROOT, 'sdk', file)).href;

// ---- the device clock ----
let clockOffsetMs = 0;
const RealDate = Date;
class DeviceDate extends RealDate {
    constructor(...args) {
        if (args.length === 0) super(RealDate.now() + clockOffsetMs);
        else super(...args);
    }
    static now() { return RealDate.now() + clockOffsetMs; }
}
globalThis.Date = DeviceDate;

// ---- browser globals ----
const { memoryIndexedDb } = await import(sdk('test/helpers/request-archive-harness.mjs'));
globalThis.indexedDB = memoryIndexedDb();
const storage = new Map();
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key),
};
globalThis.sessionStorage = globalThis.localStorage;
// One tab: no cross-tab notices (an open channel would keep Node alive).
delete globalThis.BroadcastChannel;
const realFetch = globalThis.fetch;
const fetchLog = [];
// `hold_successors`: answers that would deliver a successor read as still
// reserved until this wallet's exit lock holds a released escape or close.
let holdSuccessors = false;
let heldReadings = 0;
const exitProofReleased = () => (runtime?.runtime?.exitLock?.released || []).some(entry => Number(entry.kind) <= 1);
const SUCCESSOR_ROUTES = /^\/v2\/(?:requests|nullifiers|openrouter\/leases)\/[^/]+$/;
globalThis.fetch = async (input, init = {}) => {
    const url = new URL(String(input?.url ?? input));
    if (url.protocol === 'file:') {
        return new Response(await readFile(fileURLToPath(url)), { headers: { 'content-type': 'application/wasm' } });
    }
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') throw new TypeError(`the acceptance SDK only reaches loopback (${url.origin})`);
    fetchLog.push({ method: init.method || 'GET', path: url.pathname, origin: url.origin });
    const response = await realFetch(url, init);
    if (!holdSuccessors || !SUCCESSOR_ROUTES.test(url.pathname) || exitProofReleased()) return response;
    const text = await response.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* Not JSON: passed on unchanged. */ }
    if (body && typeof body === 'object' && (body.request_response || body.nullifier_status === 'finalized')) {
        delete body.request_response;
        if (body.nullifier_status === 'finalized') body.nullifier_status = 'reserved';
        heldReadings += 1;
        return new Response(JSON.stringify(body), { status: response.status, headers: { 'content-type': 'application/json' } });
    }
    return new Response(text, { status: response.status, headers: { 'content-type': response.headers.get('content-type') || 'application/json' } });
};
const { execute } = await import(sdk('services/zkapiWasmWorker.js'));
const workerOperations = [];
globalThis.Worker = class {
    constructor() { this.listeners = {}; }
    addEventListener(type, listener) { this.listeners[type] = listener; }
    removeEventListener(type) { delete this.listeners[type]; }
    terminate() {}
    postMessage({ id, operation, payload }) {
        workerOperations.push(operation);
        execute(operation, payload).then(result => this.listeners.message?.({ data: { id, result } }),
            error => this.listeners.message?.({ data: { id, error: error?.message || String(error) } }));
    }
};

// ---- the session, set by `start` ----
let client;
let runtime;
let walletRpcUrl;
let account;
let rpcId = 0;
const sent = [];
// Every personal_sign the wallet answered (a sponsored operation's hash).
const signatures = [];
// `wallet_reject`: selectors whose calls the wallet refuses to send.
const rejectSelectors = new Set();
const rejected = [];
async function walletRpc(method, params = []) {
    const response = await realFetch(walletRpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
    const body = await response.json();
    if (body.error) throw Object.assign(new Error(body.error.message), { code: body.error.code, data: body.error.data });
    return body.result;
}
// An EIP-1193 wallet holding one Anvil account; it reads through the user's
// own chain view (the Anvil node itself).
const provider = {
    async request({ method, params = [] }) {
        switch (method) {
            case 'eth_requestAccounts':
            case 'eth_accounts': return [account];
            case 'wallet_switchEthereumChain':
            case 'wallet_addEthereumChain': return null;
            case 'eth_sendTransaction': {
                const tx = { ...params[0] };
                delete tx.zkapiRecovery;
                const selector = String(tx.data || '').slice(0, 10).toLowerCase();
                if (rejectSelectors.has(selector)) {
                    rejected.push({ to: tx.to, data: selector });
                    throw Object.assign(new Error('User rejected the request.'), { code: 4001 });
                }
                const hash = await walletRpc('eth_sendTransaction', [tx]);
                sent.push({ hash, to: tx.to, data: tx.data?.slice(0, 10), value: tx.value ?? '0x0' });
                return hash;
            }
            case 'personal_sign': {
                const signature = await walletRpc('personal_sign', params);
                signatures.push({ message: params[0], account: params[1], signature });
                return signature;
            }
            default: return walletRpc(method, params);
        }
    },
    on() {}, removeListener() {},
};

const pick = error => ({ message: error?.shortMessage || error?.message || String(error), code: error?.code ?? null,
    data: summarize(error?.data ?? null), status: error?.status ?? null, user_op_sent: error?.userOpSent === true,
    statuses: error?.statuses ?? null, amounts: error?.amounts ?? null });

async function handle(command) {
    switch (command.command) {
        case 'start': {
            const host = new URL(command.hostUrl);
            globalThis.location = new URL('/app/', host);
            // The WebAssembly's getrandom reads `window.crypto` when a window
            // exists, as in a browser.
            globalThis.window = Object.assign(new EventTarget(), { location: globalThis.location, crypto: globalThis.crypto,
                setInterval: (...args) => setInterval(...args), clearInterval: id => clearInterval(id),
                setTimeout: (...args) => setTimeout(...args), clearTimeout: id => clearTimeout(id) });
            walletRpcUrl = command.walletRpcUrl;
            account = command.account;
            const { configureBrowserSdk } = await import(sdk('configure.js'));
            configureBrowserSdk({ configUrl: command.configUrl, workerUrl: new URL('/zkapi/v2c/assets/zkapiWasmWorker.js', host).href });
            globalThis.zkapiWallet = (await import(sdk('wallet.js'))).default;
            ({ default: runtime } = await import(sdk('services/browserWalletRuntime.js')));
            ({ default: client } = await import(sdk('services/zkapiClient.js')));
            client.setWalletProvider(provider);
            return { started: true };
        }
        case 'clock':
            clockOffsetMs = Math.round(Number(command.offsetSeconds) * 1000);
            return { offset_seconds: clockOffsetMs / 1000, now: Date.now() };
        case 'init': {
            await client.init();
            return state();
        }
        case 'deposit': {
            const statuses = [];
            const result = await client.deposit(command.amount, message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'chat': {
            const access = await client.acquireInferenceAccess(command.sessionId, { spendingLimitUsd: command.spendingLimitUsd ?? 1 });
            try {
                const answer = await realFetch(`${access.baseUrl}/chat/completions`, { method: 'POST', headers: access.headers,
                    body: JSON.stringify({ model: command.model, messages: [{ role: 'user', content: command.prompt }], max_tokens: 8, stream: false }) });
                return { status: answer.status, body: await answer.json(), base_url: access.baseUrl, spending_limit_usd: access.spendingLimitUsd };
            } finally {
                access.release();
            }
        }
        case 'settle': {
            const statuses = [];
            const result = await client.settleActiveLease(message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'withdraw': {
            const statuses = [];
            const amounts = [];
            const options = { destination: command.destination, concede: command.concede ?? 'zero' };
            for (const key of ['fees', 'feeCapWei', 'bundlerUrl', 'allowExpensiveGas', 'selfBundle']) {
                if (command[key] !== undefined) options[key] = command[key];
            }
            try {
                const result = await client.withdraw(command.mode, (message, detail) => {
                    statuses.push(message);
                    if (detail?.amounts) amounts.push(summarize(detail.amounts));
                }, options);
                return { result: summarize(result), statuses, amounts, ...state() };
            } catch (error) {
                throw Object.assign(error, { statuses, amounts });
            }
        }
        case 'sync': {
            const statuses = [];
            await client.syncEscapeWithdrawals(message => statuses.push(message));
            await client.refresh({ quiet: true });
            return { statuses, ...state() };
        }
        case 'finalize': {
            const statuses = [];
            const options = {};
            for (const key of ['fees', 'feeCapWei', 'bundlerUrl', 'allowExpensiveGas', 'selfBundle']) {
                if (command[key] !== undefined) options[key] = command[key];
            }
            const result = await client.finalizeEscape(command.recordId ?? null, message => statuses.push(message), options);
            return { result: summarize(result), statuses, ...state() };
        }
        case 'collect': {
            const statuses = [];
            const result = await client.collectTransitBalance(command.recordId, message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'sweep': {
            const statuses = [];
            const result = await client.sweepTransit(command.recordId, message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'claim_credit': {
            const statuses = [];
            const result = await client.claimGaslessCredit(command.payee, message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'quote':
            return { result: summarize(await client.gaslessWithdrawalQuote(command.mode ?? 'mutual', { destination: command.destination ?? null,
                feeCapWei: command.feeCapWei ?? null, allowExpensiveGas: command.allowExpensiveGas ?? false })), ...state() };
        case 'availability':
            return { result: summarize(await client.gaslessAvailability({ mode: command.mode ?? 'mutual', destination: command.destination ?? null })),
                ...state() };
        case 'set_bundler':
            return { bundler_url: client.setBundlerUrl(command.url ?? null), effective: client.getBundlerUrl() };
        case 'gasless_timing':
            client.gaslessTimingOverrides = { ...(command.timing || {}) };
            return { timing: client.gaslessTiming };
        case 'claim': {
            const statuses = [];
            const result = await client.claimEscapePayout(command.recordId, message => statuses.push(message));
            return { result: summarize(result), statuses, ...state() };
        }
        case 'snapshot':
            await client.refresh({ quiet: true });
            return state();
        case 'cancel': {
            const statuses = [];
            const result = await client.cancelPreparedWithdrawal(message => statuses.push(message));
            return { result, statuses, ...state() };
        }
        case 'wallet_reject':
            rejectSelectors.clear();
            for (const selector of command.selectors || []) rejectSelectors.add(String(selector).toLowerCase());
            return { rejecting: [...rejectSelectors] };
        case 'hold_successors':
            holdSuccessors = command.on !== false;
            return { holding: holdSuccessors, held_readings: heldReadings };
        case 'drop_deposit_path': {
            await client.refresh({ quiet: true });
            const current = runtime.runtime;
            const { deposit_path: dropped, ...kept } = current.state;
            await runtime.commit({ ...current, state: kept });
            await client.refresh({ quiet: true });
            return { dropped: Boolean(dropped), ...state() };
        }
        case 'close':
            setTimeout(() => process.exit(0), 10);
            return { closed: true };
        default:
            throw new Error(`unsupported command ${command.command}`);
    }
}

// What the harness asserts on; never the note secret or blindings.
function summarize(value) {
    if (typeof value === 'bigint') return value.toString();
    if (value == null || typeof value !== 'object') return value ?? null;
    const { secret, secret_s: secretS, balance_blinding: blinding, ...rest } = value;
    return JSON.parse(JSON.stringify(rest, (_, v) => typeof v === 'bigint' ? v.toString() : v));
}
const PLAN_FIELDS = ['mode', 'phase', 'noteId', 'decision', 'pathSource', 'concededAtInit', 'boundAtState', 'stateBalance',
    'validUntil', 'withdrawalNullifier', 'destination', 'warnings'];
function state() {
    const snapshot = client.snapshot();
    const exit = snapshot.config?.exit ?? null;
    const durable = runtime.runtime ?? {};
    const plan = durable.preparedWithdrawal;
    return {
        prepared: plan ? Object.fromEntries(PLAN_FIELDS.filter(key => key in plan).map(key => [key, summarize(plan[key])])) : null,
        exit_lock: durable.exitLock ? summarize({ mode: durable.exitLock.mode, released: durable.exitLock.released?.map(entry =>
            ({ kind: entry.kind, conceded: entry.conceded, valid_until: entry.valid_until ?? entry.validUntil })) }) : null,
        // The state's bound (C2) as the wallet holds it, and the request
        // its journal holds.
        bound_at_state: durable.state ? String(durable.state.bound_at_state ?? 0) : null,
        journal_request_id: durable.journal?.client_request_id || durable.journal?.prepared_request?.client_request_id || null,
        request_archive: (runtime.requestArchive ?? []).filter(record => record.type === 'request_journal').map(record => ({
            disposition: record.disposition, client_request_id: record.clientRequestId ?? null,
            observations: (record.observations ?? []).map(observation => observation.status) })),
        wallet: snapshot.wallet ? { note: summarize(snapshot.wallet.note ?? null), pending_request: snapshot.wallet.pending_request ?? null,
            has_note: snapshot.wallet.has_note ?? null } : null,
        note: summarize(client.note ?? null),
        withdrawal: summarize(snapshot.withdrawal),
        withdrawals: snapshot.withdrawals.map(summarize),
        deposits: snapshot.deposits.map(summarize),
        service: snapshot.config?.service ?? null,
        exit: summarize(exit),
        last_error: snapshot.lastError ? pick(snapshot.lastError) : null,
        sent,
        signatures,
        rejected,
        // The prepared plan's gasless journal and the sponsored-path status.
        prepared_gasless: plan && plan.feePayer === 'payout' ? summarize({ payout: plan.payout, transit: plan.transit, destination: plan.destination,
            userOpHash: plan.userOpHash ?? null, userOpHashes: plan.userOpHashes ?? null, userOpPhase: plan.userOpPhase ?? null,
            transactionHash: plan.transactionHash ?? null }) : null,
        gasless: summarize(snapshot.gasless ?? snapshot.config?.gasless ?? null),
        held_readings: heldReadings,
        deposit_path_saved: Boolean(durable.state?.deposit_path),
        worker_operations: [...new Set(workerOperations)],
        device_clock_offset_seconds: clockOffsetMs / 1000,
    };
}

const lines = readline.createInterface({ input: process.stdin });
for await (const line of lines) {
    let command;
    try { command = JSON.parse(line); } catch { continue; }
    try {
        const result = await handle(command);
        process.stdout.write(`${JSON.stringify({ id: command.id, ok: true, result })}\n`);
    } catch (error) {
        console.error(error?.stack || error);
        process.stdout.write(`${JSON.stringify({ id: command.id, ok: false, error: pick(error) })}\n`);
    }
}
