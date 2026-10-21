import init, {
    BrowserNoteTree,
    BrowserRequestProver,
    browser_check_unrecoverable_response,
    browser_circuit_id,
    browser_complete_response,
    browser_confirm_deposit,
    browser_generate_deposit,
    browser_note_path_matches,
    browser_prepare_withdrawal,
    browser_setup_id,
    browser_successor_nullifier,
    browser_tree_path,
    browser_tree_path_from_leaves,
    browser_verify_request,
    browser_wallet_status,
    browser_withdrawal_nullifier
} from '../wasm/zkapi_browser.js';

// The statement this worker proves; the setup comes from the bundle and must
// equal the build-pinned profile's setup_id (checked by the runtime through
// the 'identity' operation).
export const WORKER_CIRCUIT_ID = 'zkapi-v2-concession-v1';
const KNOWN_SETUP_IDS = ['dev', 'mpc-1'];

let initialized = null;
const keyBytes = new Map();
const requestProvers = new Map();

function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function ensureInitialized() {
    if (!initialized) {
        initialized = init({ module_or_path: new URL('../wasm/zkapi_browser_bg.wasm', import.meta.url) }).then(result => {
            if (browser_circuit_id() !== WORKER_CIRCUIT_ID) {
                throw new Error('The loaded proof WASM uses an incompatible circuit revision.');
            }
            if (!KNOWN_SETUP_IDS.includes(browser_setup_id())) {
                throw new Error('The loaded proof WASM is built for an unknown proof setup.');
            }
            return result;
        });
        // A failed initialization must not poison every later operation.
        initialized.catch(() => { initialized = null; });
    }
    return initialized;
}

/**
 * Fetch a key file and check it against its SHA-256 pin. Every key is pinned
 * by the build profile: a descriptor without a pin is refused.
 */
async function loadKeyFile(descriptor) {
    if (!descriptor?.url || !/^[0-9a-fA-F]{64}$/.test(descriptor.sha256 || '')) {
        throw new Error('A proof key must be loaded with its pinned SHA-256.');
    }
    const cacheKey = `${descriptor.url}|${descriptor.sha256.toLowerCase()}`;
    if (keyBytes.has(cacheKey)) return keyBytes.get(cacheKey);
    const promise = (async () => {
        const response = await fetch(descriptor.url, { cache: 'force-cache', credentials: 'same-origin' });
        if (!response.ok) throw new Error(`Unable to load proof key (${response.status}).`);
        const bytes = new Uint8Array(await response.arrayBuffer());
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
        if (bytesToHex(digest) !== descriptor.sha256.toLowerCase()) {
            throw new Error('The downloaded proof key failed its SHA-256 integrity check.');
        }
        return bytes;
    })();
    keyBytes.set(cacheKey, promise);
    try {
        return await promise;
    } catch (error) {
        // Do not retain a rejected fetch or integrity-check promise. A later
        // preload/Send must be able to retry after a transient failure.
        if (keyBytes.get(cacheKey) === promise) keyBytes.delete(cacheKey);
        throw error;
    }
}

async function loadRequestProver(descriptor) {
    const cacheKey = `${descriptor?.url}|${descriptor?.sha256 || ''}`;
    if (requestProvers.has(cacheKey)) return requestProvers.get(cacheKey);
    const promise = (async () => {
        const bytes = await loadKeyFile(descriptor);
        try {
            return new BrowserRequestProver(bytes);
        } finally {
            // The decoded Rust object now owns the key material it needs.
            // Do not retain a second 6 MB JavaScript copy.
            keyBytes.delete(`${descriptor.url}|${descriptor.sha256.toLowerCase()}`);
        }
    })();
    requestProvers.set(cacheKey, promise);
    try {
        return await promise;
    } catch (error) {
        // A failed fetch or decode must not poison every later retry for the
        // lifetime of the worker.
        if (requestProvers.get(cacheKey) === promise) requestProvers.delete(cacheKey);
        throw error;
    }
}

function parse(result) {
    return JSON.parse(result);
}

function sameFelt(left, right) {
    try {
        return BigInt(left) === BigInt(right);
    } catch {
        return false;
    }
}

/**
 * Rebuild the vault's note tree from its logs (design §6.6): apply each
 * leaf-changing event in log order and require the computed root to equal
 * the event's own root; every other root-bearing event ('root_check') must
 * report the current computed root. Returns the note's path at the last root.
 */
function rebuildTreePath(events, noteId) {
    if (!Array.isArray(events) || !events.length) throw new Error('The tree rebuild needs the vault logs.');
    const tree = new BrowserNoteTree();
    try {
        events.forEach((entry, index) => {
            const { root, name: _name, ...event } = entry || {};
            const computed = event.event === 'root_check'
                ? parse(tree.root())
                : parse(tree.apply(JSON.stringify(event)));
            if (!sameFelt(computed, root)) {
                throw new Error(`tree_root_mismatch: the vault log ${index} reports root ${root}; the rebuilt tree has ${computed}.`);
            }
        });
        return parse(tree.path(Number(noteId)));
    } finally {
        tree.free();
    }
}

export async function execute(operation, payload) {
    await ensureInitialized();
    switch (operation) {
        case 'identity':
            return { circuit_id: browser_circuit_id(), setup_id: browser_setup_id() };
        case 'generateDeposit':
            return parse(browser_generate_deposit());
        case 'confirmDeposit':
            return parse(browser_confirm_deposit(JSON.stringify(payload.config), JSON.stringify(payload.args)));
        case 'walletStatus':
            return parse(browser_wallet_status(
                payload.state ? JSON.stringify(payload.state) : undefined,
                payload.journal ? JSON.stringify(payload.journal) : undefined
            ));
        case 'treePath':
            return parse(browser_tree_path(
                JSON.stringify(payload.snapshot),
                Number(payload.noteId),
                Boolean(payload.requireExisting)
            ));
        case 'treePathFromLeaves':
            return parse(browser_tree_path_from_leaves(JSON.stringify(payload.leaves), Number(payload.noteId)));
        case 'rebuildTreePath':
            return rebuildTreePath(payload.events, payload.noteId);
        case 'preloadRequestProver':
            await loadRequestProver(payload.provingKey);
            return { status: 'ready' };
        case 'prepareRequest': {
            // Returns { request, journal, state }: commit `state` (which
            // records the request's bound, bound_at_state) with the journal.
            const prover = await loadRequestProver(payload.provingKey);
            return parse(prover.prepare_request(
                JSON.stringify(payload.config),
                JSON.stringify(payload.state),
                JSON.stringify(payload.args)
            ));
        }
        case 'completeResponse':
            return parse(browser_complete_response(
                JSON.stringify(payload.config),
                JSON.stringify(payload.args)
            ));
        case 'checkUnrecoverableResponse':
            // Lost ε (design §6.4 E3): S1, S2, S4 and S6 of a finalized
            // response whose journal is gone; returns its charge.
            return parse(browser_check_unrecoverable_response(
                JSON.stringify(payload.config),
                JSON.stringify(payload.state),
                JSON.stringify(payload.response)
            ));
        case 'notePathMatches':
            // A saved deposit-time path is kept only if it reaches its root.
            return browser_note_path_matches(JSON.stringify(payload.state), JSON.stringify({
                active_root: payload.path?.active_root,
                siblings: payload.path?.siblings
            }));
        case 'withdrawalNullifier':
            return parse(browser_withdrawal_nullifier(JSON.stringify(payload.state)));
        case 'successorNullifier':
            return parse(browser_successor_nullifier(JSON.stringify(payload.state)));
        case 'prepareWithdrawal': {
            const key = await loadKeyFile(payload.provingKey);
            return parse(browser_prepare_withdrawal(
                JSON.stringify(payload.config),
                JSON.stringify(payload.state),
                JSON.stringify(payload.args),
                key
            ));
        }
        case 'verifyRequest': {
            // The stale-device pre-check: an answer verifies only under the
            // pinned request.vk of this bundle's setup.
            const key = await loadKeyFile(payload.verifyingKey);
            return browser_verify_request(JSON.stringify(payload.publicInputs), String(payload.proof || ''), key);
        }
        default:
            throw new Error(`Unknown zkAPI worker operation: ${operation}`);
    }
}

if (typeof self !== 'undefined' && typeof self.addEventListener === 'function') {
    self.addEventListener('message', async (event) => {
        const { id, operation, payload } = event.data || {};
        try {
            self.postMessage({ id, result: await execute(operation, payload || {}) });
        } catch (error) {
            self.postMessage({
                id,
                error: error instanceof Error ? error.message : String(error)
            });
        }
    });
}
