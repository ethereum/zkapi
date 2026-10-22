// A request's Merkle path without the operator's indexer (vault revision 4).
//
// Only a private request proves membership in the vault's note tree: exits
// are bound to the note's leaf, which the vault stored at deposit, and need
// no path, root or chain read at all. The tree a request proves against is
// rebuilt here from the vault's own state, pinned to one recent block hash
// (EIP-1898, requireCanonical): nextNoteId() first (noteLeaves reverts for a
// range past it), then noteLeaves in pages of NOTE_LEAVES_PAGE, then
// currentRoot(), which the rebuilt tree must reproduce. When the state reads
// fail (an RPC that caps eth_call gas, or refuses block-hash calls), the
// vault's logs up to the same block are the fallback, checked against
// currentRoot() at that block hash. No event carries a root since revision 4.
// A rebuild ends by its deadline, so a slow RPC cannot hold a request (and the
// wallet lock) indefinitely.

import { ABI, decodeNoteLeaves, decodeVaultEvent, encodeNoteLeaves } from '../wallet.js';

/** Leaves per noteLeaves(start, count) call (≈5.2M gas of eth_call each). */
export const NOTE_LEAVES_PAGE = 2_048;
export const REBUILD_CHUNK_BLOCKS = Object.freeze({ initial: 2_000, minimum: 100 });
// After this many accepted ranges in a row, the range doubles again (up to
// the initial size): one dense stretch of history does not slow the rest.
export const REBUILD_REGROW_AFTER = 4;

// The leaf-changing events, the only ones a rebuild needs.
const TREE_TOPICS = Object.freeze([ABI.noteDeposited, ABI.closedLeafRetiredEvent]);
// Failures of the state reads after which the log rebuild is tried.
const STATE_READ_FAILURES = Object.freeze(['tree_state_unavailable', 'tree_state_invalid']);

export function sameFelt(left, right) {
    try {
        return BigInt(left) === BigInt(right);
    } catch {
        return false;
    }
}

function rebuildError(message, code = 'tree_rebuild_failed', data = undefined) {
    return Object.assign(new Error(message), { code, ...(data ? { data } : {}) });
}

function quantity(value) {
    return `0x${BigInt(value).toString(16)}`;
}

function blockNumber(value, label) {
    if (!/^0x[0-9a-fA-F]+$/.test(String(value ?? ''))) throw rebuildError(`The RPC returned an invalid ${label}.`);
    return Number(BigInt(value));
}

function throwIfAborted(signal) {
    if (signal?.aborted) {
        throw Object.assign(new Error('The tree rebuild was aborted.'), { name: 'AbortError' });
    }
}

function feltHex(value) {
    return `0x${BigInt(value).toString(16).padStart(64, '0')}`;
}

function timeoutError() {
    return rebuildError('The vault state could not be read in time.', 'tree_rebuild_timeout');
}

function stopping(error, signal) {
    return signal?.aborted || error?.name === 'AbortError' || error?.code === 'tree_rebuild_timeout';
}

/** The refusal code of an error the proof worker raised ("code: detail"), or null. */
export function workerRefusalCode(error) {
    return error?.code || /^(?:Error: )?([a-z_]+):/.exec(String(error?.message || ''))?.[1] || null;
}

/**
 * One RPC call that ends by `deadline` (ms since the epoch), whatever the RPC
 * does: a call still running then fails the rebuild with tree_rebuild_timeout.
 */
async function callBy(request, payload, deadline, signal) {
    throwIfAborted(signal);
    if (deadline == null) return request(payload);
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw timeoutError();
    let timer;
    let onAbort;
    const stop = new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(timeoutError()), remaining);
        onAbort = () => reject(Object.assign(new Error('The tree rebuild was aborted.'), { name: 'AbortError' }));
        signal?.addEventListener('abort', onAbort, { once: true });
    });
    try {
        return await Promise.race([request(payload), stop]);
    } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
    }
}

/** The EIP-1898 block parameter of a pinned block: by hash, refused once it is no longer canonical. */
export function blockParam(block) {
    return { blockHash: block.hash, requireCanonical: true };
}

/**
 * The block `tag` names now ('latest' or 'safe'; 'finalized' lags by minutes
 * and stalls with finality, and a request needs a root the server read
 * recently): { number, hash }.
 */
export async function pinBlock({ request, tag = 'latest', deadline = null, signal = null }) {
    let block;
    try {
        block = await callBy(request, { method: 'eth_getBlockByNumber', params: [tag, false] }, deadline, signal);
    } catch (error) {
        if (stopping(error, signal)) throw error;
        throw rebuildError(`The RPC returned no ${tag} block: ${error?.message || error}`, 'tree_state_unavailable');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(block?.hash || ''))) {
        throw rebuildError(`The RPC returned no ${tag} block hash.`, 'tree_state_invalid');
    }
    return { number: blockNumber(block.number, `${tag} block number`), hash: String(block.hash).toLowerCase() };
}

async function callAt({ request, vault, block, data, deadline, signal, label }) {
    let result;
    try {
        result = await callBy(request, { method: 'eth_call', params: [{ to: vault, data }, blockParam(block)] }, deadline, signal);
    } catch (error) {
        if (stopping(error, signal)) throw error;
        throw rebuildError(`The RPC did not answer ${label} at block ${block.hash}: ${error?.message || error}`,
            'tree_state_unavailable');
    }
    if (!/^0x(?:[0-9a-fA-F]{64})+$/.test(String(result || ''))) {
        throw rebuildError(`The RPC returned a malformed ${label}.`, 'tree_state_invalid');
    }
    return result;
}

function oneWord(result, label) {
    if (result.length !== 66) throw rebuildError(`${label} is not one word.`, 'tree_state_invalid');
    return BigInt(result);
}

/** The vault's currentRoot() at `block` (bigint). */
export async function currentRootAt({ request, vault, block, deadline = null, signal = null }) {
    return oneWord(await callAt({ request, vault, block, data: `0x${ABI.currentRoot}`, deadline, signal,
        label: 'currentRoot()' }), 'currentRoot()');
}

/**
 * The vault's state at `block`: nextNoteId() FIRST (noteLeaves reverts for a
 * range past it), then every leaf in noteLeaves pages of `pageSize`, then
 * currentRoot(), every call pinned to `block.hash`. Returns the worker's
 * snapshot { root, next_note_id, leaves } (hex felts; 0 is a retired leaf).
 */
export async function readTreeState({ request, vault, block, deadline = null, signal = null, pageSize = NOTE_LEAVES_PAGE }) {
    const next = oneWord(await callAt({ request, vault, block, data: `0x${ABI.nextNoteId}`, deadline, signal,
        label: 'nextNoteId()' }), 'nextNoteId()');
    if (next >= 1n << 32n) throw rebuildError('nextNoteId() exceeds uint32.', 'tree_state_invalid');
    const count = Number(next);
    const leaves = [];
    for (let start = 0; start < count; start += pageSize) {
        const size = Math.min(pageSize, count - start);
        const result = await callAt({ request, vault, block, data: encodeNoteLeaves(start, size), deadline, signal,
            label: `noteLeaves(${start}, ${size})` });
        let page;
        try {
            page = decodeNoteLeaves(result, size);
        } catch (error) {
            throw rebuildError(`noteLeaves(${start}, ${size}) is malformed: ${error.message}`, 'tree_state_invalid');
        }
        leaves.push(...page.map(feltHex));
    }
    const root = await currentRootAt({ request, vault, block, deadline, signal });
    return { root: feltHex(root), next_note_id: count, leaves };
}

/**
 * The vault's tree logs between two blocks (inclusive), in (blockNumber,
 * logIndex) order. Ranges start at 2,000 blocks; a failed range (an RPC
 * range or result-size limit) is halved down to 100 blocks and retried, and
 * the range doubles again after REBUILD_REGROW_AFTER accepted ranges. A range
 * that still fails at 100 blocks fails the rebuild (tree_logs_unavailable),
 * and so does reaching `deadline` (ms since the epoch; tree_rebuild_timeout).
 */
export async function fetchVaultTreeLogs({ request, vault, fromBlock, toBlock, signal = null, deadline = null,
    initialChunk = REBUILD_CHUNK_BLOCKS.initial, minimumChunk = REBUILD_CHUNK_BLOCKS.minimum, onProgress = () => {} }) {
    if (typeof request !== 'function') throw rebuildError('The tree rebuild needs an RPC.');
    const logs = [];
    let chunk = initialChunk;
    let accepted = 0;
    let start = Number(fromBlock);
    const end = Number(toBlock);
    const ranges = [];
    while (start <= end) {
        throwIfAborted(signal);
        const stop = Math.min(end, start + chunk - 1);
        let result;
        try {
            result = await callBy(request, {
                method: 'eth_getLogs',
                params: [{ address: vault, topics: [[...TREE_TOPICS]], fromBlock: quantity(start), toBlock: quantity(stop) }]
            }, deadline, signal);
        } catch (error) {
            if (stopping(error, signal)) throw error;
            if (chunk <= minimumChunk) {
                throw rebuildError(`The RPC refused the vault logs of blocks ${start}–${stop}: ${error?.message || error}`,
                    'tree_logs_unavailable');
            }
            chunk = Math.max(minimumChunk, Math.floor(chunk / 2));
            accepted = 0;
            continue;
        }
        if (!Array.isArray(result)) throw rebuildError('The RPC returned no log list.', 'tree_logs_unavailable');
        logs.push(...result);
        ranges.push([start, stop]);
        onProgress({ fromBlock: start, toBlock: stop, chunk, logs: logs.length });
        start = stop + 1;
        accepted += 1;
        if (accepted >= REBUILD_REGROW_AFTER && chunk < initialChunk) {
            chunk = Math.min(initialChunk, chunk * 2);
            accepted = 0;
        }
    }
    return {
        ranges,
        logs: logs.filter(log => log?.removed !== true).sort((left, right) => {
            const block = blockNumber(left.blockNumber, 'log block') - blockNumber(right.blockNumber, 'log block');
            return block || blockNumber(left.logIndex, 'log index') - blockNumber(right.logIndex, 'log index');
        })
    };
}

/**
 * Tree events for the worker's log rebuild, in log order: NoteDeposited sets
 * a leaf (note_leaf of its id, commitment, amount and expiry), and
 * ClosedLeafRetired zeroes one. No event carries a root.
 */
export function treeEventsFromLogs(logs, vault) {
    const events = [];
    for (const log of logs) {
        const event = decodeVaultEvent(log, vault);
        if (event?.event === 'NoteDeposited') {
            events.push({ event: 'note_deposited', note_id: Number(event.noteId), commitment: feltHex(event.commitment),
                amount: event.amount.toString(), expiry_ts: Number(event.expiryTs) });
        } else if (event?.event === 'ClosedLeafRetired') {
            events.push({ event: 'closed_leaf_retired', note_id: Number(event.noteId) });
        }
    }
    return events;
}

/**
 * The tree rebuilt from the vault's logs, from `deployBlock` to `block`
 * (pinned), then checked against currentRoot() at `block.hash`: the path of
 * `noteId` ({ active_root, note_id, siblings }).
 */
export async function rebuildPathFromLogs({ request, vault, deployBlock, block, noteId, worker, signal = null, deadline = null,
    initialChunk, minimumChunk, onProgress }) {
    const fromBlock = Number.isSafeInteger(Number(deployBlock)) && Number(deployBlock) >= 0 ? Number(deployBlock) : 0;
    if (block.number < fromBlock) throw rebuildError('The pinned block precedes the vault deployment.');
    const { logs } = await fetchVaultTreeLogs({ request, vault, fromBlock, toBlock: block.number, signal, deadline,
        initialChunk, minimumChunk, onProgress });
    const events = treeEventsFromLogs(logs, vault);
    if (!events.some(event => event.event === 'note_deposited' && event.note_id === Number(noteId))) {
        throw rebuildError(`The vault logs up to block ${block.number} hold no deposit of note ${noteId}.`, 'tree_note_missing');
    }
    throwIfAborted(signal);
    const path = await worker.call('treePathFromEvents', { events, noteId: Number(noteId) });
    const vaultRoot = await currentRootAt({ request, vault, block, deadline, signal });
    if (!sameFelt(path.active_root, vaultRoot)) {
        throw rebuildError(`tree_root_mismatch: the vault logs up to block ${block.number} give root ${path.active_root}; the vault reports ${feltHex(vaultRoot)}.`,
            'tree_root_mismatch');
    }
    return path;
}

/**
 * A request path of `noteId` at a root the vault holds at a recent block,
 * read through `request`, by `deadline` (ms since the epoch) when one is
 * given: pin the `tag` block, rebuild from the vault's state, and fall back
 * to its logs at the same block when the state reads fail. A root mismatch
 * is not retried: the RPC answered inconsistently for one block hash.
 * `worker` runs the Poseidon tree ('treePathFromState', 'treePathFromEvents').
 * Returns { active_root, note_id, siblings, source: 'state' | 'logs', block }.
 */
export async function rebuildRequestPath({ request, vault, deployBlock, noteId, chainId = null, worker, tag = 'latest',
    signal = null, deadline = null, pageSize = NOTE_LEAVES_PAGE, initialChunk, minimumChunk, onProgress }) {
    if (typeof request !== 'function') throw rebuildError('The tree rebuild needs an RPC.');
    if (chainId != null) {
        const chain = await callBy(request, { method: 'eth_chainId', params: [] }, deadline, signal);
        if (BigInt(chain) !== BigInt(chainId)) throw rebuildError('The rebuild RPC is on another chain.', 'wrong_network');
    }
    const block = await pinBlock({ request, tag, deadline, signal });
    let snapshot;
    try {
        snapshot = await readTreeState({ request, vault, block, deadline, signal, pageSize });
    } catch (stateError) {
        if (stopping(stateError, signal) || !STATE_READ_FAILURES.includes(stateError?.code)) throw stateError;
        try {
            const path = await rebuildPathFromLogs({ request, vault, deployBlock, block, noteId, worker, signal, deadline,
                initialChunk, minimumChunk, onProgress });
            return { ...path, source: 'logs', block };
        } catch (logError) {
            if (stopping(logError, signal) || logError?.code === 'tree_root_mismatch') throw logError;
            throw rebuildError(`The vault state could not be read (${stateError.message}), nor its logs (${logError?.message || logError}).`,
                logError?.code || 'tree_rebuild_failed');
        }
    }
    throwIfAborted(signal);
    const path = await worker.call('treePathFromState', { snapshot, noteId: Number(noteId) });
    return { ...path, source: 'state', block };
}
