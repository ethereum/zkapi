// Pure helpers for the browser wallet's append-only transmitted-request archive.
//
// A proved request leaves the device the moment it is POSTed. Its write-ahead
// journal may later be discarded from the selected runtime slot (a corroborated
// stale root, an unaccepted quote, a clearance reservation, or an escape from
// a state with an unsettled request), but the knowledge that this note state
// was transmitted must never be. These typed records live in the existing
// IndexedDB 'archives' object store beside note archives. They never contain a
// note state, secret, ownership proof or clearance, and older builds ignore
// them. The exit rules classify them (zkapiExitPolicy.mjs, design §6.4).

export const REQUEST_ARCHIVE_SCHEMA = 1;
export const REQUEST_JOURNAL_TYPE = 'request_journal';
export const REQUEST_EVIDENCE_TYPE = 'request_evidence';
export const REQUEST_JOURNAL_PREFIX = 'request-journal:';
export const REQUEST_EVIDENCE_PREFIX = 'request-evidence:';
// unresolvedPerAnchor counts the unresolved journals at one note state that
// are not evicted. retainedPerAnchor is the hard ceiling on all unresolved
// journals kept there, evicted ones included: about 3 KB each, so at most
// ~200 KB per note state. Reaching it takes 48 evictions, each needing a
// corroborated discard read at least 20 minutes after its request, so at
// least an hour of failed chats at one state. Past it, new requests are
// refused before proving and nothing is dropped. Chats at that state resume
// only if the server settles one of its requests; one it never accepted never
// settles, so the balance then has to be withdrawn. observationsPerRecord is
// how many of its newest observations a record keeps; older than those, it
// keeps only its newest receipt claim or contradicting reading in save order.
export const REQUEST_ARCHIVE_LIMITS = Object.freeze({
    unresolvedPerAnchor: 16,
    retainedPerAnchor: 64,
    terminalPerDeployment: 256,
    observationsPerRecord: 8
});
// The server never newly accepts a request whose proof-bound request_time is
// older than MAX_REQUEST_AGE_SECONDS (processor_v2.rs). Only a corroborated
// discard read well after that window may be evicted. The reading is an
// unauthenticated server answer, so eviction only sets the record aside from
// the per-state cap and never deletes anything.
export const REQUEST_ACCEPTANCE_WINDOW_SECONDS = 300;
export const REQUEST_EVICTION_SKEW_SECONDS = 900;

// installed and superseded records can never install again. A signed
// successor that failed S3, S4 or S5 is archived as invalid_successor: the
// client treats it exactly like a withheld successor (design §6.1), and it
// never installs either. All three are compacted.
export const TERMINAL_DISPOSITIONS = new Set(['installed', 'superseded', 'invalid_successor']);
// Not terminal: an evicted record keeps its full journal, still marks its
// state as transmitted and still installs a later receipt, until the state
// advances or the note closes.
export const EVICTED_DISPOSITION = 'evicted';
// A valid successor that arrived after an exit proof from its state was
// released (design §6.4 E4.6). It keeps its journal and response so that it
// installs once the exit lock is released (E6); it is never compacted before.
export const LATE_SUCCESSOR_DISPOSITION = 'late_successor';
export const INVALID_SUCCESSOR_DISPOSITION = 'invalid_successor';
const DISCARDED_DISPOSITIONS = new Set([
    'discarded_stale_root',
    'discarded_expired_unaccepted',
    'discarded_clearance_reserved',
    'abandoned_for_escape'
]);
const EVICTABLE_DISPOSITIONS = new Set([
    'discarded_stale_root',
    'discarded_expired_unaccepted',
    'discarded_clearance_reserved'
]);
const JOURNAL_DISPOSITION_RANK = new Map([
    ['pending', 0],
    ...[...DISCARDED_DISPOSITIONS].map(disposition => [disposition, 1]),
    [EVICTED_DISPOSITION, 2],
    [LATE_SUCCESSOR_DISPOSITION, 2.5],
    ['installed', 3],
    ['superseded', 3],
    [INVALID_SUCCESSOR_DISPOSITION, 3]
]);
const EVIDENCE_DISPOSITION_RANK = new Map([['evidence', 0], ['superseded', 2]]);
// GET /v2/nullifiers readings of the state's nullifier. 'unavailable' is a
// failed read. 'unaccepted' is POST .../expire answering expired_unaccepted
// or superseded_unaccepted for one request; it only echoes values this wallet
// sent, so it is never a nullifier reading.
// exit_deferred and exited_unsigned (design §5.2) are the server's readings
// of a reserved nullifier that an exit consumed on chain: it signs a
// successor only if that exit is defeated.
const NULLIFIER_READINGS = new Set(['unknown', 'reserved', 'finalized', 'clearance_reserved', 'exit_deferred',
    'exited_unsigned']);
// The readings that say the nullifier is not finalized, so they contradict an
// earlier receipt claim.
const CONTRADICTING_READINGS = new Set(['unknown', 'clearance_reserved']);
const OBSERVATION_STATUSES = new Set([...NULLIFIER_READINGS, 'unavailable', 'unaccepted']);
// 'exit' is a bounded E1 recovery pass; 'override' is only kept so records an
// older build saved still load.
const OBSERVATION_CONTEXTS = new Set(['stale_root', 'recovery', 'escape', 'clearance', 'override', 'exit']);
const JOURNAL_SOURCES = new Set(['prepared', 'migrated_runtime_journal']);
const EVIDENCE_SOURCES = new Set(['escape_challenged']);
const IDENTITY_FIELDS = ['type', 'deploymentId', 'noteId', 'anchor', 'nullifier', 'clientRequestId'];

function archiveError(message, code = 'request_archive_invalid') {
    return Object.assign(new Error(message), { code });
}

/** Canonical 32-byte hex for a field element, so equal felts compare equal. */
export function feltKey(value) {
    if (value == null || value === '') throw archiveError('A request archive field element is missing.');
    let parsed;
    try {
        parsed = BigInt(value);
    } catch {
        throw archiveError('A request archive field element is invalid.');
    }
    if (parsed < 0n || parsed >= (1n << 256n)) {
        throw archiveError('A request archive field element is out of range.');
    }
    return `0x${parsed.toString(16).padStart(64, '0')}`;
}

function noteIdentity(value) {
    const noteId = Number(value);
    if (!Number.isSafeInteger(noteId) || noteId < 0 || noteId > 0xffffffff) {
        throw archiveError('A request archive note id is invalid.');
    }
    return noteId;
}

export function requestJournalArchiveId(deploymentId, noteId, clientRequestId) {
    if (typeof deploymentId !== 'string' || !deploymentId || typeof clientRequestId !== 'string' || !clientRequestId) {
        throw archiveError('A request archive identity is incomplete.');
    }
    return `${REQUEST_JOURNAL_PREFIX}${deploymentId}:${noteIdentity(noteId)}:${clientRequestId}`;
}

export function requestEvidenceArchiveId(deploymentId, noteId, nullifier) {
    if (typeof deploymentId !== 'string' || !deploymentId) {
        throw archiveError('A request archive identity is incomplete.');
    }
    return `${REQUEST_EVIDENCE_PREFIX}${deploymentId}:${noteIdentity(noteId)}:${feltKey(nullifier)}`;
}

export function isRequestArchiveRecord(record) {
    const archiveId = String(record?.archiveId || '');
    return (record?.type === REQUEST_JOURNAL_TYPE && archiveId.startsWith(REQUEST_JOURNAL_PREFIX))
        || (record?.type === REQUEST_EVIDENCE_TYPE && archiveId.startsWith(REQUEST_EVIDENCE_PREFIX));
}

export function journalClientRequestId(journal) {
    const value = journal?.client_request_id || journal?.prepared_request?.client_request_id;
    return typeof value === 'string' && value ? value : null;
}

/** An unresolved record can still be installed or still marks a challenged anchor. */
export function isUnresolved(record) {
    if (record?.type === REQUEST_JOURNAL_TYPE) return !TERMINAL_DISPOSITIONS.has(record.disposition);
    if (record?.type === REQUEST_EVIDENCE_TYPE) return record.disposition === 'evidence';
    return false;
}

export function lastObservation(record) {
    const observations = Array.isArray(record?.serverObservations) ? record.serverObservations : [];
    return observations.length ? observations[observations.length - 1] : null;
}

/** The newest nullifier reading: never an unavailable server or an /expire answer. */
export function lastDefinitiveObservation(record) {
    const observations = Array.isArray(record?.serverObservations) ? record.serverObservations : [];
    for (let index = observations.length - 1; index >= 0; index -= 1) {
        if (NULLIFIER_READINGS.has(observations[index]?.status)) return observations[index];
    }
    return null;
}

/**
 * A 'finalized' reading that carried a receipt: fresh ({ status, response })
 * or saved ({ status, receipt, clientRequestId }). A receipt that installs
 * resolves every record at its state, so on an unresolved record this is the
 * server's claim of a finalized receipt this wallet could not apply.
 */
export function isReceiptClaim(observation) {
    return observation?.status === 'finalized'
        && Boolean(observation.response || observation.receipt === true || observation.clientRequestId);
}

/** An observation's save-order stamp, or null when an older build saved it. */
function observationSeq(observation) {
    const seq = Number(observation?.seq);
    return Number.isSafeInteger(seq) && seq > 0 ? seq : null;
}

/**
 * Save order, never the device clock: stamped observations by `seq`, which
 * the store assigns inside its write transaction (sequenceObservationUpdates).
 * Observations an older build saved carry no `seq`; they come before every
 * stamped one, by time among themselves. `at` is only the local time of the
 * save, and a clock that ran fast or stepped back would misorder it.
 */
function saveOrder(left, right) {
    const leftSeq = observationSeq(left);
    const rightSeq = observationSeq(right);
    if (leftSeq != null && rightSeq != null) return leftSeq - rightSeq;
    if (leftSeq != null || rightSeq != null) return leftSeq != null ? 1 : -1;
    return Number(left.at) - Number(right.at);
}

/**
 * The newest receipt claim or contradicting reading ('unknown',
 * 'clearance_reserved') among observations, in save order, or null. Equal
 * unstamped times keep their order, so the later of two wins.
 */
function newestClaimReading(observations) {
    const relevant = observations
        .filter(observation => isReceiptClaim(observation) || CONTRADICTING_READINGS.has(observation?.status))
        // Stable: equal unstamped times keep each record's own order.
        .sort(saveOrder);
    return relevant.length ? relevant[relevant.length - 1] : null;
}

/** The highest save-order stamp among the records' observations, or 0. */
export function highestObservationSeq(records) {
    let highest = 0;
    for (const record of records || []) {
        for (const observation of Array.isArray(record?.serverObservations) ? record.serverObservations : []) {
            const seq = observationSeq(observation);
            if (seq != null && seq > highest) highest = seq;
        }
    }
    return highest;
}

/**
 * Stamp every observation the updates append with its save order: the next
 * `seq` above every one saved in `records`, in update and array order. The
 * store calls this inside its write transaction with every record it holds,
 * so a later save always orders after an earlier one, also across the records
 * of a state and whatever the device clock says. A `seq` an update already
 * carries is replaced; `at` is kept.
 */
export function sequenceObservationUpdates(records, updates) {
    let seq = highestObservationSeq(records);
    return (Array.isArray(updates) ? updates : []).map(update =>
        Array.isArray(update?.serverObservations) && update.serverObservations.length
            ? { ...update, serverObservations: update.serverObservations.map(observation => ({ ...observation, seq: ++seq })) }
            : update);
}

/**
 * The newest receipt claim saved at a note state (its unresolved records)
 * that no 'unknown' or 'clearance_reserved' reading saved after it
 * contradicts, or null. "After" is save order, not the device clock. The
 * contradicting reading may be saved on another record of the state. A failed
 * read, 'reserved' or 'finalized' without a receipt leaves the claim
 * standing. Advisory: it never allows anything, it only makes the escape
 * override ask for that claim's own acknowledgement.
 */
export function standingReceiptClaim(records) {
    const newest = newestClaimReading((records || [])
        .flatMap(record => Array.isArray(record?.serverObservations) ? record.serverObservations : []));
    return isReceiptClaim(newest) ? newest : null;
}

/**
 * One server status reading for a transmitted nullifier. A finalized reading
 * that carried a receipt says so (`receipt`) and may name the receipt's client
 * request id; both are advisory, never evidence. `at` is the local time; a
 * saved observation also carries `seq`, its save order, which only the store
 * assigns (an invalid one is dropped).
 */
export function requestObservation(status, context, at = Date.now(), {
    clientRequestId = null,
    receipt = false,
    seq = null
} = {}) {
    if (!OBSERVATION_STATUSES.has(status) || !OBSERVATION_CONTEXTS.has(context)
        || !Number.isSafeInteger(Number(at)) || Number(at) <= 0) {
        throw archiveError('A request archive observation is invalid.');
    }
    const named = status === 'finalized' && typeof clientRequestId === 'string' && clientRequestId;
    const stamp = observationSeq({ seq });
    return {
        status,
        context,
        at: Number(at),
        ...(named ? { clientRequestId } : {}),
        ...(status === 'finalized' && (named || receipt === true) ? { receipt: true } : {}),
        ...(stamp != null ? { seq: stamp } : {})
    };
}

/** Build the complete record for a proved request journal at its note state. */
export function buildRequestJournalRecord({
    deploymentId,
    state,
    journal,
    source = 'prepared',
    disposition = 'pending',
    observations = [],
    now = Date.now()
} = {}) {
    const clientRequestId = journalClientRequestId(journal);
    if (typeof deploymentId !== 'string' || !deploymentId || state?.note_id == null
        || state.current_anchor == null || journal?.nullifier == null || !clientRequestId
        || !JOURNAL_SOURCES.has(source) || !JOURNAL_DISPOSITION_RANK.has(disposition)) {
        throw archiveError('The prepared request journal is incomplete.', 'request_journal_incomplete');
    }
    const createdAt = Number(journal.created_at_ms);
    const record = {
        archiveId: requestJournalArchiveId(deploymentId, state.note_id, clientRequestId),
        type: REQUEST_JOURNAL_TYPE,
        schema: REQUEST_ARCHIVE_SCHEMA,
        deploymentId,
        noteId: noteIdentity(state.note_id),
        anchor: feltKey(state.current_anchor),
        nullifier: feltKey(journal.nullifier),
        clientRequestId,
        source,
        journal: structuredClone(journal),
        disposition,
        serverObservations: appendObservations([], observations),
        createdAt: Number.isSafeInteger(createdAt) && createdAt > 0 ? createdAt : Number(now),
        updatedAt: Number(now)
    };
    return TERMINAL_DISPOSITIONS.has(disposition) ? compactRequestArchiveRecord(record) : record;
}

/** Evidence that the vault finalized a challenge of an escape at this anchor. */
export function buildRequestEvidenceRecord({
    deploymentId,
    noteId,
    anchor,
    nullifier,
    source = 'escape_challenged',
    evidence = {},
    now = Date.now()
} = {}) {
    if (!EVIDENCE_SOURCES.has(source) || anchor == null) {
        throw archiveError('Escape challenge evidence is incomplete.');
    }
    return {
        archiveId: requestEvidenceArchiveId(deploymentId, noteId, nullifier),
        type: REQUEST_EVIDENCE_TYPE,
        schema: REQUEST_ARCHIVE_SCHEMA,
        deploymentId,
        noteId: noteIdentity(noteId),
        anchor: feltKey(anchor),
        nullifier: feltKey(nullifier),
        sources: [source],
        evidence: {
            transactionHash: /^0x[0-9a-fA-F]{64}$/.test(evidence.transactionHash || '')
                ? evidence.transactionHash.toLowerCase() : null,
            blockNumber: Number.isSafeInteger(Number(evidence.blockNumber)) && Number(evidence.blockNumber) > 0
                ? Number(evidence.blockNumber) : null,
            observedAt: Number(evidence.observedAt || now)
        },
        disposition: 'evidence',
        serverObservations: [],
        createdAt: Number(now),
        updatedAt: Number(now)
    };
}

/**
 * A resolved record keeps only the identity of its request. The request proof,
 * payload and private rerandomization are never needed again.
 */
export function compactRequestArchiveRecord(record) {
    if (!record?.journal) return { ...record };
    const journal = record.journal;
    const { lateResponse: _lateResponse, ...kept } = record;
    return {
        ...kept,
        compacted: true,
        journal: {
            client_request_id: journalClientRequestId(journal),
            nullifier: journal.nullifier ?? null,
            payload_hash: journal.payload_hash ?? journal.prepared_request?.payload_hash ?? null,
            created_at_ms: journal.created_at_ms ?? null
        }
    };
}

function sameIdentityValue(field, left, right) {
    if (field === 'noteId') return Number(left) === Number(right);
    if (field === 'anchor' || field === 'nullifier') {
        try {
            return feltKey(left) === feltKey(right);
        } catch {
            return false;
        }
    }
    return left === right;
}

function dispositionRank(type, disposition) {
    const ranks = type === REQUEST_EVIDENCE_TYPE ? EVIDENCE_DISPOSITION_RANK : JOURNAL_DISPOSITION_RANK;
    if (!ranks.has(disposition)) throw archiveError(`Unknown request archive disposition: ${disposition}.`);
    return ranks.get(disposition);
}

function isCompleteRecord(record) {
    if (!isRequestArchiveRecord(record) || typeof record.deploymentId !== 'string' || !record.deploymentId
        || record.noteId == null || record.anchor == null || record.nullifier == null) return false;
    return record.type === REQUEST_EVIDENCE_TYPE
        || (typeof record.clientRequestId === 'string' && record.clientRequestId && record.journal);
}

// The newest eight observations, plus the record's newest receipt claim or
// contradicting reading in save order when it is older than those. The
// state's standing claim is decided by the newest such observation across its
// records, which is always the newest on its own record, so trimming any
// record can neither erase a claim nor revive one that a reading on another
// record ended. The kept observations stay in order and the newest eight are
// never displaced. Saved stamps (`seq`) are kept; additions are stamped by the
// store before they get here.
function appendObservations(previous, additions) {
    const limit = REQUEST_ARCHIVE_LIMITS.observationsPerRecord;
    const observations = [...(Array.isArray(previous) ? previous : []), ...(Array.isArray(additions) ? additions : [])]
        .map(entry => requestObservation(entry.status, entry.context, entry.at, entry));
    const newest = observations.slice(-limit);
    const decisive = observations.length > limit ? newestClaimReading(observations) : null;
    return decisive && !newest.includes(decisive) ? [decisive, ...newest] : newest;
}

/**
 * Merge a full record or a partial patch ({archiveId, disposition,
 * serverObservations, ...}) into the stored record. Identity fields are
 * compared only when both sides carry them; a conflict aborts the caller's
 * transaction. The original source and createdAt are kept, evidence sources
 * accumulate as a set, observations append (the newest eight retained, plus
 * the newest receipt claim or contradicting reading in save order), and a
 * disposition only moves forward. A partial patch for a missing record is
 * ignored (null), because it cannot establish the record's identity. The
 * store stamps appended observations first (sequenceObservationUpdates).
 */
export function mergeRequestArchiveRecord(previous, update, now = Date.now()) {
    if (!update?.archiveId || (previous && previous.archiveId !== update.archiveId)) {
        throw archiveError('A request archive update has no matching identity.');
    }
    if (!previous) {
        if (!isCompleteRecord(update)) return null;
        const created = {
            ...structuredClone(update),
            schema: REQUEST_ARCHIVE_SCHEMA,
            noteId: noteIdentity(update.noteId),
            anchor: feltKey(update.anchor),
            nullifier: feltKey(update.nullifier),
            serverObservations: appendObservations([], update.serverObservations),
            createdAt: Number(update.createdAt || now),
            updatedAt: Number(now)
        };
        dispositionRank(created.type, created.disposition);
        return TERMINAL_DISPOSITIONS.has(created.disposition) ? compactRequestArchiveRecord(created) : created;
    }
    for (const field of IDENTITY_FIELDS) {
        if (update[field] != null && previous[field] != null
            && !sameIdentityValue(field, previous[field], update[field])) {
            throw archiveError('A request archive update conflicts with the saved request identity.',
                'request_archive_conflict');
        }
    }
    if (update.journal && previous.journal) {
        const updateId = journalClientRequestId(update.journal);
        const previousId = journalClientRequestId(previous.journal);
        if ((updateId && previousId && updateId !== previousId)
            || (update.journal.nullifier != null && previous.journal.nullifier != null
                && !sameIdentityValue('nullifier', update.journal.nullifier, previous.journal.nullifier))) {
            throw archiveError('A request archive update conflicts with the saved request journal.',
                'request_archive_conflict');
        }
    }
    const next = { ...previous };
    if (!next.journal && update.journal) next.journal = structuredClone(update.journal);
    if (update.disposition != null) {
        const currentRank = dispositionRank(previous.type, previous.disposition);
        if (dispositionRank(previous.type, update.disposition) > currentRank) {
            next.disposition = update.disposition;
        }
    }
    if (Array.isArray(update.serverObservations) && update.serverObservations.length) {
        next.serverObservations = appendObservations(previous.serverObservations, update.serverObservations);
    }
    if (previous.type === REQUEST_EVIDENCE_TYPE) {
        const sources = new Set([...(previous.sources || []), ...(update.sources || [])]);
        for (const source of sources) {
            if (!EVIDENCE_SOURCES.has(source)) throw archiveError('Escape challenge evidence has an invalid source.');
        }
        next.sources = [...sources];
        if (!next.evidence && update.evidence) next.evidence = structuredClone(update.evidence);
    }
    if (next.disposition === 'installed' && previous.disposition !== 'installed') {
        for (const field of ['installedNextAnchor', 'chargeApplied', 'chargeBasis', 'settlementReason', 'installedAt']) {
            if (update[field] != null) next[field] = update[field];
        }
    }
    if (next.disposition === LATE_SUCCESSOR_DISPOSITION && previous.disposition !== LATE_SUCCESSOR_DISPOSITION
        && update.lateResponse) {
        next.lateResponse = structuredClone(update.lateResponse);
        next.lateAt = Number(update.lateAt || now);
    }
    if (next.disposition === INVALID_SUCCESSOR_DISPOSITION && previous.disposition !== INVALID_SUCCESSOR_DISPOSITION) {
        for (const field of ['invalidCheck', 'invalidReason', 'chargeApplied', 'invalidAt']) {
            if (update[field] != null) next[field] = update[field];
        }
    }
    const changed = JSON.stringify(next) !== JSON.stringify(previous);
    if (!changed) return previous;
    next.updatedAt = Number(now);
    return TERMINAL_DISPOSITIONS.has(next.disposition) && !next.compacted
        ? compactRequestArchiveRecord(next)
        : next;
}

function sameAnchorKey(record, { deploymentId, noteId, anchor }) {
    if (record.deploymentId !== deploymentId || Number(record.noteId) !== Number(noteId)) return false;
    try {
        return feltKey(record.anchor) === feltKey(anchor);
    } catch {
        return false;
    }
}

/** Unresolved request journals and challenge evidence at one note state. */
export function unresolvedRequestArchiveAt(records, { deploymentId, noteId, anchor }) {
    if (!deploymentId || noteId == null || anchor == null) return [];
    return (records || []).filter(record => isRequestArchiveRecord(record) && isUnresolved(record)
        && sameAnchorKey(record, { deploymentId, noteId, anchor }));
}

/** Local transmission time: request journals only, never evidence timestamps. */
export function earliestLocalTransmission(entries) {
    const times = (entries || [])
        .filter(entry => entry.type === REQUEST_JOURNAL_TYPE)
        .map(entry => Number(entry.journal?.created_at_ms || entry.createdAt))
        .filter(value => Number.isSafeInteger(value) && value > 0);
    return times.length ? Math.min(...times) : null;
}

function requestTimeMilliseconds(record) {
    const requestTime = Number(record.journal?.prepared_request?.public_inputs?.request_time);
    if (Number.isSafeInteger(requestTime) && requestTime > 0) return requestTime * 1_000;
    return Number(record.journal?.created_at_ms || record.createdAt || 0);
}

// Only a nullifier reading counts here: an /expire answer never does.
function evictable(record) {
    if (record.type !== REQUEST_JOURNAL_TYPE || !EVICTABLE_DISPOSITIONS.has(record.disposition)) return false;
    const closedAt = requestTimeMilliseconds(record)
        + (REQUEST_ACCEPTANCE_WINDOW_SECONDS + REQUEST_EVICTION_SKEW_SECONDS) * 1_000;
    return (record.serverObservations || []).some(entry =>
        ['unknown', 'clearance_reserved'].includes(entry.status) && Number(entry.at) >= closedAt);
}

/**
 * Decide whether one more unresolved request may be archived at an anchor.
 * Unresolved records are never dropped. Past the per-state cap, the oldest
 * corroborated discards whose server acceptance window has provably closed
 * are evicted: set aside from the cap with their journals intact. At the hard
 * ceiling of retained records nothing is evicted and the request is refused.
 */
export function anchorArchiveCapacity(records, key) {
    const retained = unresolvedRequestArchiveAt(records, key)
        .filter(record => record.type === REQUEST_JOURNAL_TYPE);
    if (retained.length >= REQUEST_ARCHIVE_LIMITS.retainedPerAnchor) return { available: false, evict: [] };
    const counted = retained.filter(record => record.disposition !== EVICTED_DISPOSITION);
    const limit = REQUEST_ARCHIVE_LIMITS.unresolvedPerAnchor;
    if (counted.length < limit) return { available: true, evict: [] };
    const needed = counted.length - limit + 1;
    const candidates = counted.filter(evictable)
        .sort((left, right) => Number(left.createdAt || 0) - Number(right.createdAt || 0));
    if (candidates.length < needed) return { available: false, evict: [] };
    return { available: true, evict: candidates.slice(0, needed).map(record => record.archiveId) };
}

/** Terminal records beyond the newest N per deployment (never note archives). */
export function terminalRequestArchiveToPrune(records, deploymentId) {
    return (records || [])
        .filter(record => isRequestArchiveRecord(record) && record.deploymentId === deploymentId
            && !isUnresolved(record))
        .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0))
        .slice(REQUEST_ARCHIVE_LIMITS.terminalPerDeployment)
        .map(record => record.archiveId);
}
