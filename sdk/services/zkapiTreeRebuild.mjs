// A note's Merkle path without the operator (design §6.6): rebuild the vault's
// append-only note tree from its own logs, checking every root the logs
// report, and take the path at the last event's root.
//
// The path is only the fallback of Amendment A1: the vault accepts any root it
// ever held, so a client exits with the path it saved at deposit. A client
// without that path (an older backup, another device) rebuilds it here, from
// the user's exit RPC, wallet provider or the pinned RPC, never from the
// operator's indexer. A rebuild ends by its deadline, so a slow RPC cannot
// hold an exit (and the wallet lock) indefinitely.

import { ABI, decodeVaultEvent } from '../wallet.js';

export const REBUILD_CHUNK_BLOCKS = Object.freeze({ initial: 2_000, minimum: 100 });
// After this many accepted ranges in a row, the range doubles again (up to
// the initial size): one dense stretch of history does not slow the rest.
export const REBUILD_REGROW_AFTER = 4;

// Leaf-changing events, and every other event that reports the root.
const TREE_TOPICS = Object.freeze([
    ABI.noteDeposited,
    ABI.closedLeafRetiredEvent,
    ABI.escapeInitiatedEvent,
    ABI.escapeChallengedEvent,
    ABI.expiredClaimedEvent
]);

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
    return rebuildError('The vault logs could not be read in time.', 'tree_rebuild_timeout');
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
            if (signal?.aborted || error?.name === 'AbortError' || error?.code === 'tree_rebuild_timeout') throw error;
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
 * Tree events for the worker's rebuild, each with the root its log reports:
 * NoteDeposited sets a leaf, ClosedLeafRetired zeroes one, and every other
 * root-bearing event must report the current computed root ('root_check').
 */
export function treeEventsFromLogs(logs, vault) {
    const events = [];
    for (const log of logs) {
        const event = decodeVaultEvent(log, vault);
        if (!event) continue;
        switch (event.event) {
            case 'NoteDeposited':
                events.push({ event: 'note_deposited', note_id: Number(event.noteId), commitment: feltHex(event.commitment),
                    amount: event.amount.toString(), expiry_ts: Number(event.expiryTs), root: feltHex(event.newRoot) });
                break;
            case 'ClosedLeafRetired':
                events.push({ event: 'closed_leaf_retired', note_id: Number(event.noteId), root: feltHex(event.newRoot) });
                break;
            case 'EscapeWithdrawalInitiated':
            case 'EscapeWithdrawalChallenged':
            case 'ExpiredClaimed':
                events.push({ event: 'root_check', name: event.event, root: feltHex(event.root) });
                break;
            default:
                break;
        }
    }
    return events;
}

/**
 * Rebuild `noteId`'s path from the vault's logs, from `deployBlock` to the
 * finalized block of `request`'s chain (§6.6 steps 1–4), by `deadline` (ms
 * since the epoch) when one is given. `worker` runs the Poseidon tree
 * (operation 'rebuildTreePath'), which refuses as soon as an event's root
 * differs from the rebuilt one. Returns { active_root, note_id, siblings,
 * finalizedBlock, events }.
 */
export async function rebuildNotePath({ request, vault, deployBlock, noteId, chainId = null, worker, signal = null,
    deadline = null, initialChunk, minimumChunk, onProgress }) {
    if (chainId != null) {
        const chain = await callBy(request, { method: 'eth_chainId', params: [] }, deadline, signal);
        if (BigInt(chain) !== BigInt(chainId)) throw rebuildError('The rebuild RPC is on another chain.', 'wrong_network');
    }
    const finalized = await callBy(request, { method: 'eth_getBlockByNumber', params: ['finalized', false] }, deadline, signal);
    const toBlock = blockNumber(finalized?.number, 'finalized block');
    const fromBlock = Number.isSafeInteger(Number(deployBlock)) && Number(deployBlock) >= 0 ? Number(deployBlock) : 0;
    if (toBlock < fromBlock) throw rebuildError('The finalized block precedes the vault deployment.');
    const { logs } = await fetchVaultTreeLogs({ request, vault, fromBlock, toBlock, signal, deadline, initialChunk,
        minimumChunk, onProgress });
    const events = treeEventsFromLogs(logs, vault);
    if (!events.some(event => event.event === 'note_deposited' && event.note_id === Number(noteId))) {
        throw rebuildError(`The vault logs up to the finalized block ${toBlock} hold no deposit of note ${noteId}.`,
            'tree_note_missing');
    }
    throwIfAborted(signal);
    const path = await worker.call('rebuildTreePath', { events, noteId: Number(noteId) });
    return { ...path, finalizedBlock: toBlock, events: events.length };
}
