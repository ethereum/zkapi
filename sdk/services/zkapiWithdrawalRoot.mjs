export function sameFelt(left, right) {
    try {
        return BigInt(left) === BigInt(right);
    } catch {
        return false;
    }
}

export async function waitForExpectedActiveRoot(loadPath, expectedActiveRoot, {
    attempts = 20,
    delayMs = 500,
    sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
} = {}) {
    const limit = expectedActiveRoot == null ? 1 : attempts;
    for (let attempt = 0; attempt < limit; attempt += 1) {
        const path = await loadPath();
        if (expectedActiveRoot == null || sameFelt(path.active_root, expectedActiveRoot)) return path;
        if (attempt + 1 < limit) await sleep(delayMs);
    }
    const error = new Error('The zkAPI indexer is still catching up with the latest vault root. Try again in a few seconds.');
    error.code = 'indexer_root_lag';
    throw error;
}

/**
 * The indexer's snapshot once it holds note `noteId`. The wallet installs a
 * note from its deposit's receipt, and the indexer applies that block a few
 * seconds later, so a snapshot read right after a deposit may end before
 * the note: it is read again, with the same budget as a lagging root, until
 * its next_note_id passes the note. A null `noteId` (a deposit's empty slot)
 * and a snapshot without a readable next_note_id (the worker refuses it)
 * return the first snapshot.
 */
export async function waitForIndexedNote(loadSnapshot, noteId, {
    attempts = 20,
    delayMs = 500,
    sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
} = {}) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        const snapshot = await loadSnapshot();
        if (noteId == null) return snapshot;
        let next;
        try {
            next = BigInt(snapshot?.next_note_id);
        } catch {
            return snapshot;
        }
        if (next > BigInt(noteId)) return snapshot;
        if (attempt + 1 < attempts) await sleep(delayMs);
    }
    const error = new Error('The zkAPI indexer has not indexed this note yet. Try again in a few seconds.');
    error.code = 'indexer_root_lag';
    throw error;
}
