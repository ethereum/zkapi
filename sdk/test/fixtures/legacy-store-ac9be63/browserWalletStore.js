import { isUnsubmittedParkedMutualWithdrawal } from './zkapiWithdrawalRecovery.mjs';
import {
    EVICTED_DISPOSITION,
    REQUEST_JOURNAL_TYPE,
    anchorArchiveCapacity,
    buildRequestEvidenceRecord,
    buildRequestJournalRecord,
    feltKey,
    isRequestArchiveRecord,
    isUnresolved,
    journalClientRequestId,
    mergeRequestArchiveRecord,
    requestJournalArchiveId,
    sequenceObservationUpdates,
    terminalRequestArchiveToPrune
} from './zkapiRequestArchive.mjs';

const DB_NAME = 'zkapi-browser-wallet-v1';
// Never bump: older builds must keep opening this shared same-origin database
// (they are the legacy exit route for notes in an older immutable vault).
// Request-archive records reuse the existing 'archives' store instead.
const DB_VERSION = 3;
const RUNTIME_STORE = 'runtime';
const ARCHIVE_STORE = 'archives';
const WITHDRAWAL_STORE = 'withdrawals';
const DEPOSIT_STORE = 'deposits';
const RUNTIME_KEY = 'active';
const LATE_WITHDRAWAL_TERMINAL_STATUSES = new Set([
    'closed',
    'detached',
    'reverted',
    'challenged',
    'superseded',
    'quarantined'
]);

const LATE_DEPOSIT_TERMINAL_STATUSES = new Set(['confirmed', 'reverted', 'superseded']);

const EMPTY_RUNTIME = Object.freeze({
    version: 1,
    deploymentId: null,
    state: null,
    journal: null,
    pendingDeposit: null,
    depositQuote: null,
    preparedWithdrawal: null,
    lease: null,
    lateWithdrawalAttempts: [],
    lateDepositAttempts: [],
    updatedAt: 0
});

let databasePromise = null;
let fallbackLock = Promise.resolve();

function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed.'));
    });
}

function transactionDone(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted.'));
        transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed.'));
    });
}

function openDatabase() {
    if (databasePromise) return databasePromise;
    let opening;
    opening = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            const database = request.result;
            if (!database.objectStoreNames.contains(RUNTIME_STORE)) {
                database.createObjectStore(RUNTIME_STORE);
            }
            if (!database.objectStoreNames.contains(ARCHIVE_STORE)) {
                database.createObjectStore(ARCHIVE_STORE, { keyPath: 'archiveId' });
            }
            if (!database.objectStoreNames.contains(WITHDRAWAL_STORE)) {
                database.createObjectStore(WITHDRAWAL_STORE, { keyPath: 'recordId' });
            }
            if (!database.objectStoreNames.contains(DEPOSIT_STORE)) {
                database.createObjectStore(DEPOSIT_STORE, { keyPath: 'recordId' });
            }
        };
        request.onsuccess = () => {
            const database = request.result;
            // A second browser tab may load newer wallet code while this tab is
            // still open. Closing here lets the upgrader proceed instead of
            // stranding durable withdrawal recovery behind a blocked DB.
            database.onversionchange = () => {
                if (databasePromise === opening) databasePromise = null;
                database.close();
            };
            resolve(database);
        };
        request.onerror = () => {
            if (databasePromise === opening) databasePromise = null;
            reject(request.error || new Error('Unable to open the browser wallet database.'));
        };
        request.onblocked = () => {
            if (databasePromise === opening) databasePromise = null;
            reject(new Error('A different tab is blocking the browser wallet upgrade.'));
        };
    });
    databasePromise = opening;
    return opening;
}

function normalizeRuntime(value) {
    return {
        ...EMPTY_RUNTIME,
        ...(value || {}),
        version: 1
    };
}

function durableTransaction(database, stores) {
    try {
        return database.transaction(stores, 'readwrite', { durability: 'strict' });
    } catch {
        return database.transaction(stores, 'readwrite');
    }
}

function positiveTimestamp(value) {
    return Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
}

function sanitizedExpiryClaim(claim, amount, expiryTs) {
    if (!claim || !expiryTs || Number(claim.amount) !== amount
        || !/^0x[0-9a-fA-F]{64}$/.test(claim.transactionHash || '')
        || !/^0x[0-9a-fA-F]{64}$/.test(claim.blockHash || '')
        || !positiveTimestamp(claim.blockNumber)
        || !positiveTimestamp(claim.claimedAt)
        || Number(claim.claimedAt) < expiryTs * 1000) return null;
    return {
        transactionHash: claim.transactionHash.toLowerCase(),
        blockHash: claim.blockHash.toLowerCase(),
        blockNumber: Number(claim.blockNumber),
        claimedAt: Number(claim.claimedAt),
        amount
    };
}

function sanitizedDepositFee(metadata) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(metadata.transactionHash || '')
        || !/^0x[0-9a-fA-F]{40}$/.test(metadata.fundingAddress || '')
        || !/^0x[0-9a-fA-F]{64}$/.test(metadata.receiptBlockHash || '')
        || !positiveTimestamp(metadata.receiptBlockNumber)
        || !['feeWei', 'gasUsed', 'effectiveGasPrice'].every(key =>
            typeof metadata[key] === 'string' && /^[1-9][0-9]{0,77}$/.test(metadata[key]))) return null;
    if (BigInt(metadata.feeWei) !== BigInt(metadata.gasUsed) * BigInt(metadata.effectiveGasPrice)) return null;
    return { feeWei: metadata.feeWei, gasUsed: metadata.gasUsed, effectiveGasPrice: metadata.effectiveGasPrice,
        fundingAddress: metadata.fundingAddress.toLowerCase(), receiptBlockNumber: Number(metadata.receiptBlockNumber),
        receiptBlockHash: metadata.receiptBlockHash.toLowerCase() };
}

function depositRecord(state, deploymentId, metadata = {}) {
    const noteId = Number(state?.note_id);
    const amount = Number(state?.deposit_amount);
    if (!deploymentId || state?.note_id == null || !Number.isSafeInteger(noteId) || noteId < 0
        || !Number.isSafeInteger(amount) || amount <= 0) return null;
    const expiryTs = positiveTimestamp(state?.expiry_ts ?? metadata.expiryTs);
    const expiryClaim = sanitizedExpiryClaim(metadata.expiryClaim, amount, expiryTs);
    // This explicit allowlist is also the public payment-history shape. Never
    // copy a private state, commitment, secret, proof, or recovery plan here.
    return {
        recordId: `${deploymentId}:deposit:${noteId}`,
        type: 'deposit',
        deploymentId,
        operationId: typeof metadata.operationId === 'string' ? metadata.operationId : null,
        noteId,
        amount,
        expiryTs,
        status: 'confirmed',
        createdAt: positiveTimestamp(metadata.createdAt),
        confirmedAt: positiveTimestamp(metadata.confirmedAt),
        transactionHash: /^0x[0-9a-fA-F]{64}$/.test(metadata.transactionHash || '')
            ? metadata.transactionHash.toLowerCase() : null,
        ...(expiryClaim ? { expiryClaim } : {}),
        ...(sanitizedDepositFee(metadata) || {})
    };
}

function mergeDepositRecord(records, candidate, store) {
    if (!candidate) return;
    const previous = records.get(candidate.recordId);
    const next = previous ? {
        ...candidate,
        // A migration has no date/hash evidence. It must not replace a receipt
        // recorded by a newer client, or pretend the withdrawal date was the
        // deposit date. A later verified receipt may fill missing metadata.
        createdAt: previous.createdAt || candidate.createdAt,
        confirmedAt: previous.confirmedAt || candidate.confirmedAt,
        transactionHash: previous.transactionHash || candidate.transactionHash,
        operationId: previous.operationId || candidate.operationId,
        expiryTs: previous.expiryTs || candidate.expiryTs,
        ...(previous.expiryClaim ? { expiryClaim: previous.expiryClaim } : {}),
        ...(sanitizedDepositFee(previous) || {})
    } : candidate;
    // Do not pair a newer candidate's fee with an older retained receipt hash.
    if (previous?.transactionHash && previous.transactionHash !== candidate.transactionHash
        && !sanitizedDepositFee(previous)) {
        for (const key of ['feeWei', 'gasUsed', 'effectiveGasPrice', 'fundingAddress', 'receiptBlockNumber', 'receiptBlockHash']) delete next[key];
    }
    if (JSON.stringify(previous) !== JSON.stringify(next)) store?.put(next);
    records.set(next.recordId, next);
}

function archiveDeploymentId(archive) {
    if (archive.deploymentId) return archive.deploymentId;
    // Older clients made separate clock reads for archiveId and archivedAt.
    const parts = String(archive.archiveId || '').split(':');
    const timestamp = parts.pop();
    const noteId = parts.pop();
    return /^\d+$/.test(timestamp || '') && String(archive.state?.note_id) === noteId
        ? parts.join(':') || null : null;
}

function depositRecordMap(records) {
    return new Map(records.map(record => depositRecord({
        note_id: record.noteId, deposit_amount: record.amount, expiry_ts: record.expiryTs
    }, record.deploymentId, record)).filter(Boolean).map(record => [record.recordId, record]));
}

function pendingDepositRecords(runtime, deploymentId) {
    const pending = !deploymentId || runtime.deploymentId === deploymentId ? runtime.pendingDeposit : null;
    const candidates = [
        ...(pending && (pending.phase !== 'prepared' || pending.submissionId
            || pending.transactionHash || pending.transactionHashes?.length) ? [{
                ...pending,
                noteId: pending.next_note_id,
                deploymentId: runtime.deploymentId,
                status: 'pending',
                pendingPhase: pending.phase || (pending.transactionHash ? 'submitted' : 'ambiguous'),
                createdAt: pending.createdAt || pending.submissionStartedAt
            }] : []),
        ...(runtime.lateDepositAttempts || []).filter(attempt =>
            (!deploymentId || attempt.deploymentId === deploymentId)
            && !['confirmed', 'superseded'].includes(attempt.status)
        ).map(attempt => ({ ...attempt,
            status: attempt.status === 'reverted' ? 'failed' : 'pending',
            pendingPhase: attempt.status,
            createdAt: attempt.observedAt
        }))
    ];
    const records = new Map();
    for (const candidate of candidates) {
        const record = depositRecord({ note_id: candidate.noteId, deposit_amount: candidate.amount },
            candidate.deploymentId, candidate);
        if (!record) continue;
        const key = `${record.deploymentId}:deposit-pending:${record.operationId
            || `${record.noteId}:${record.amount}:${record.transactionHash || 'legacy'}`}`;
        // Several replacement hashes belong to one attempted deposit. Retain
        // its unresolved state even when another attempt has reverted.
        // The selected operation appears first, so a late callback for its old
        // vault slot cannot overwrite the current amount or recovery action.
        if (records.get(key)?.status === 'pending') continue;
        records.set(key, { ...record, recordId: key, status: candidate.status,
            pendingPhase: candidate.pendingPhase, confirmedAt: null });
    }
    return [...records.values()];
}

function requestArchiveMap(archives) {
    return new Map((archives || []).filter(isRequestArchiveRecord)
        .map(record => [record.archiveId, record]));
}

function requestArchiveRecords(archive, deploymentId) {
    return [...archive.values()]
        .filter(record => !deploymentId || record.deploymentId === deploymentId)
        .map(record => structuredClone(record));
}

function sameFeltValue(left, right) {
    try {
        return feltKey(left) === feltKey(right);
    } catch {
        return false;
    }
}

function requestArchiveError(message, code, status = null) {
    return Object.assign(new Error(message), { code, ...(status ? { status } : {}) });
}

/**
 * Merge request-archive updates into an in-memory snapshot of the store.
 * Throws on an identity conflict or when a new unresolved request would exceed
 * its anchor's bound. Eviction is non-terminal and keeps every journal intact.
 * Every appended observation is stamped with its save order here, inside the
 * write transaction that holds every record. Returns the ids that must be
 * written.
 */
function mergeRequestArchiveUpdates(archive, updates, now, { enforceCapacity = true } = {}) {
    const changed = new Set();
    for (const update of sequenceObservationUpdates([...archive.values()], updates)) {
        const previous = archive.get(update?.archiveId) || null;
        if (!previous && enforceCapacity && update?.type === REQUEST_JOURNAL_TYPE && isUnresolved(update)) {
            const capacity = anchorArchiveCapacity([...archive.values()], update);
            if (!capacity.available) {
                throw requestArchiveError(
                    'Too many unsettled private requests are recorded for this balance state, so no new chat can start from it. Chats resume only if the server settles one of them; otherwise withdraw this balance.',
                    'request_archive_limit',
                    409
                );
            }
            for (const archiveId of capacity.evict) {
                const evicted = mergeRequestArchiveRecord(archive.get(archiveId),
                    { archiveId, disposition: EVICTED_DISPOSITION }, now);
                archive.set(archiveId, evicted);
                changed.add(archiveId);
            }
        }
        const merged = mergeRequestArchiveRecord(previous, update, now);
        if (merged && merged !== previous) {
            archive.set(merged.archiveId, merged);
            changed.add(merged.archiveId);
        }
    }
    return changed;
}

function writeRequestArchiveChanges(store, archive, changed) {
    if (!changed.size) return;
    for (const archiveId of changed) store.put(archive.get(archiveId));
    const deployments = new Set([...changed].map(archiveId => archive.get(archiveId)?.deploymentId).filter(Boolean));
    for (const deploymentId of deployments) {
        for (const archiveId of terminalRequestArchiveToPrune([...archive.values()], deploymentId)) {
            // Prune filters by request type and prefix, so note archives are untouched.
            archive.delete(archiveId);
            store.delete(archiveId);
        }
    }
}

/** Supersede every unresolved request record of a closed or sanitized note. */
function supersedeNoteRequestArchive(archive, deploymentId, noteId, now) {
    if (!deploymentId || noteId == null) return new Set();
    const updates = [...archive.values()]
        .filter(record => record.deploymentId === deploymentId && Number(record.noteId) === Number(noteId)
            && isUnresolved(record))
        .map(record => ({ archiveId: record.archiveId, disposition: 'superseded' }));
    return mergeRequestArchiveUpdates(archive, updates, now, { enforceCapacity: false });
}

/**
 * The archive record an existing transmitted journal needs before this write
 * may drop it: null when the journal is kept, has no request identity (legacy),
 * or the write installs a different note or a later anchor (a verified receipt).
 */
function journalDropArchiveId(current, next) {
    const clientRequestId = journalClientRequestId(current?.journal);
    if (!clientRequestId || !current?.deploymentId || current.state?.note_id == null
        || current.state.current_anchor == null) return null;
    if (journalClientRequestId(next?.journal) === clientRequestId) return null;
    if (next?.state && (Number(next.state.note_id) !== Number(current.state.note_id)
        || !sameFeltValue(next.state.current_anchor, current.state.current_anchor))) return null;
    try {
        return requestJournalArchiveId(current.deploymentId, current.state.note_id, clientRequestId);
    } catch {
        return null;
    }
}

/** A durable request journal written by an older build becomes archive-covered on first read. */
function migratedRuntimeJournal(runtime, archive) {
    if (!runtime.deploymentId || !runtime.state || runtime.state.current_anchor == null
        || runtime.journal?.nullifier == null || !journalClientRequestId(runtime.journal)) return null;
    let record;
    try {
        record = buildRequestJournalRecord({
            deploymentId: runtime.deploymentId,
            state: runtime.state,
            journal: runtime.journal,
            source: 'migrated_runtime_journal'
        });
    } catch {
        return null;
    }
    return archive.has(record.archiveId) ? null : record;
}

/** Project public rows without another fallible storage operation after commit. */
export function projectBrowserDeposits(runtime, records, deploymentId, depositConfirmation = {}) {
    const history = depositRecordMap((records || []).filter(record => record.status === 'confirmed'));
    mergeDepositRecord(history, depositRecord(runtime.state, runtime.deploymentId, depositConfirmation));
    const confirmed = [...history.values()].filter(record => !deploymentId || record.deploymentId === deploymentId);
    const pending = pendingDepositRecords(runtime, deploymentId).filter(record => !confirmed.some(deposit =>
        deposit.deploymentId === record.deploymentId
        && (deposit.operationId && record.operationId
            ? deposit.operationId === record.operationId
            : deposit.noteId === record.noteId && deposit.amount === record.amount)));
    return [...confirmed, ...pending].sort((left, right) =>
        Number(right.createdAt || right.confirmedAt || 0) - Number(left.createdAt || left.confirmedAt || 0));
}

/**
 * Whether a stored runtime slot holds durable wallet state: a note, journal,
 * lease, pending deposit, deposit draft, prepared withdrawal or unfinished late
 * attempt. A runtime for another deployment refuses to load over such a slot.
 */
export function browserRuntimeHoldsState(runtime) {
    const value = runtime || {};
    return Boolean(
        value.state
        || value.journal
        || value.pendingDeposit
        || value.depositQuote
        || value.preparedWithdrawal
        || value.lease
        || (Array.isArray(value.lateWithdrawalAttempts)
            && value.lateWithdrawalAttempts.some(attempt => !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt?.status)))
        || (Array.isArray(value.lateDepositAttempts)
            && value.lateDepositAttempts.some(attempt => !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt?.status)))
    );
}

/**
 * Whether a withdrawal record can still hold, return or pay out a note: every
 * record except a finalized close (phase 'closed' with no finalization in
 * flight). That covers set-aside mutual closes, pending and challenged
 * escapes, closes awaiting finality and finalizations in flight. Only its own
 * deployment's runtime can act on it.
 */
export function isOpenBrowserWithdrawal(record) {
    if (!record || record.phase !== 'closed') return Boolean(record);
    const hashes = Array.isArray(record.finalizeTransactionHashes)
        ? record.finalizeTransactionHashes
        : record.finalizeTransactionHash ? [record.finalizeTransactionHash] : [];
    return Boolean(record.finalizeSubmissionId || hashes.length);
}

/** The public identity of an open withdrawal record: no note state or proof. */
function withdrawalHolding(record) {
    return {
        recordId: record.recordId,
        noteId: record.noteId == null ? null : Number(record.noteId),
        mode: record.mode || null,
        phase: record.phase || null
    };
}

/**
 * The deployments this browser still holds funds or unfinished recovery for,
 * from one readBrowserWalletSnapshot(): the runtime slot's deployment while
 * browserRuntimeHoldsState(runtime), and every deployment with an open
 * withdrawal record (isOpenBrowserWithdrawal). Returns
 * [{ deploymentId, runtime, withdrawals: [{ recordId, noteId, mode, phase }] }],
 * the runtime slot's deployment first: only that one can load while its slot
 * holds state. Hosts select a deployment's profile while it is listed.
 */
export function browserWalletHoldings(snapshot) {
    const holdings = new Map();
    const entry = deploymentId => {
        if (!holdings.has(deploymentId)) holdings.set(deploymentId, { deploymentId, runtime: false, withdrawals: [] });
        return holdings.get(deploymentId);
    };
    const runtime = snapshot?.runtime;
    if (browserRuntimeHoldsState(runtime)) entry(runtime.deploymentId || null).runtime = true;
    for (const record of snapshot?.withdrawals || []) {
        if (isOpenBrowserWithdrawal(record)) entry(record.deploymentId || null).withdrawals.push(withdrawalHolding(record));
    }
    return [...holdings.values()].sort((left, right) => Number(right.runtime) - Number(left.runtime)
        || String(left.deploymentId).localeCompare(String(right.deploymentId)));
}

/** browserWalletHoldings of the current stored wallet (every deployment). */
export async function readBrowserWalletHoldings() {
    return browserWalletHoldings(await readBrowserWalletSnapshot());
}

/**
 * Whether a withdrawal record is a closed escape whose payout the vault only
 * credited (EscapePayoutDeferred) and that this browser has not seen
 * delivered. Once its close is final it holds no note, so it does not keep its
 * deployment in browserWalletHoldings and does not block a deposit elsewhere;
 * what remains is claimEscapePayout(destination) on its vault.
 */
export function isUnclaimedPayoutCredit(record) {
    return record?.payoutCredited === true && record.payoutClaimed !== true
        && ['closed_unconfirmed', 'closed'].includes(record.phase);
}

/** The public identity of an unclaimed payout credit: where it can be claimed. */
function payoutCreditHolding(record) {
    return {
        deploymentId: record.deploymentId || null,
        recordId: record.recordId,
        noteId: record.noteId == null ? null : Number(record.noteId),
        chainId: record.chainId == null ? null : Number(record.chainId),
        contractAddress: record.contractAddress || null,
        destination: record.destination || null,
        creditedAmount: record.creditedAmount ?? null
    };
}

/**
 * The unclaimed escape payout credits of every deployment in one
 * readBrowserWalletSnapshot(), newest first:
 * [{ deploymentId, recordId, noteId, chainId, contractAddress, destination,
 * creditedAmount }]. creditedAmount (vault units) is null when the credit was
 * read from the vault's balance rather than from the finalization receipt.
 */
export function browserWalletPayoutCredits(snapshot) {
    return (snapshot?.withdrawals || []).filter(isUnclaimedPayoutCredit)
        .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0))
        .map(payoutCreditHolding);
}

/** browserWalletPayoutCredits of the current stored wallet (every deployment). */
export async function readBrowserWalletPayoutCredits() {
    return browserWalletPayoutCredits(await readBrowserWalletSnapshot());
}

export async function readBrowserWallet() {
    const database = await openDatabase();
    const transaction = database.transaction(RUNTIME_STORE, 'readonly');
    const value = await requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY));
    await transactionDone(transaction);
    return normalizeRuntime(value);
}

/** Read recovery state and payment history from one consistent snapshot. */
export async function readBrowserWalletSnapshot(deploymentId = null) {
    const database = await openDatabase();
    const transaction = durableTransaction(database,
        [RUNTIME_STORE, WITHDRAWAL_STORE, ARCHIVE_STORE, DEPOSIT_STORE]);
    const [runtimeValue, records, archives, deposits] = await Promise.all([
        requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY)),
        requestResult(transaction.objectStore(WITHDRAWAL_STORE).getAll()),
        requestResult(transaction.objectStore(ARCHIVE_STORE).getAll()),
        requestResult(transaction.objectStore(DEPOSIT_STORE).getAll())
    ]);
    const runtime = normalizeRuntime(runtimeValue);
    const depositStore = transaction.objectStore(DEPOSIT_STORE);
    const history = depositRecordMap(deposits);
    mergeDepositRecord(history, depositRecord(runtime.state, runtime.deploymentId), depositStore);
    for (const record of records) {
        mergeDepositRecord(history, depositRecord(record.state, record.deploymentId), depositStore);
    }
    // Request-archive records carry no note state, so older builds running
    // this same loop derive no deposit row from them.
    for (const archive of archives) {
        mergeDepositRecord(history, depositRecord(archive.state, archiveDeploymentId(archive)), depositStore);
    }
    const requestArchive = requestArchiveMap(archives);
    // Lazy, cap-exempt migration: an in-flight journal from an older build
    // becomes a transmitted-anchor record without touching the runtime slot.
    const migrated = migratedRuntimeJournal(runtime, requestArchive);
    if (migrated) {
        requestArchive.set(migrated.archiveId, migrated);
        transaction.objectStore(ARCHIVE_STORE).put(migrated);
    }
    await transactionDone(transaction);
    return {
        runtime,
        deposits: projectBrowserDeposits(runtime, [...history.values()], deploymentId),
        withdrawals: records
            .filter(record => !deploymentId || record.deploymentId === deploymentId)
            .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0)),
        // Open withdrawals of other deployments, which this deployment's
        // runtime can neither see nor act on (empty without a filter).
        otherDeploymentWithdrawals: deploymentId
            ? records.filter(record => record.deploymentId !== deploymentId && isOpenBrowserWithdrawal(record))
                .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0))
                .map(record => ({ deploymentId: record.deploymentId || null, ...withdrawalHolding(record) }))
            : [],
        // Unclaimed escape payout credits of other deployments. They hold no
        // note, but only their own deployment's runtime offers the claim.
        otherDeploymentCredits: deploymentId
            ? browserWalletPayoutCredits({
                withdrawals: records.filter(record => record.deploymentId !== deploymentId)
            })
            : [],
        requestArchive: requestArchiveRecords(requestArchive, deploymentId)
    };
}

/**
 * Commit the entire private wallet snapshot in one IndexedDB write, together
 * with any transmitted-request archive records. The caller must put a
 * write-ahead journal and its archive record here before transmitting a proved
 * request. This boundary enforces that a transmitted journal leaves the
 * runtime only in the same write that installs a verified next note state
 * (a later anchor or a different note) or records a non-pending archive
 * disposition for it. Returns the runtime and, when the archive was read, the
 * deployment's merged request records (no fallible read after commit).
 */
export async function commitBrowserWallet(next, { depositConfirmation = null, requestArchive = [] } = {}) {
    const updates = (Array.isArray(requestArchive) ? requestArchive : []).filter(Boolean);
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, DEPOSIT_STORE, ARCHIVE_STORE]);
    const value = normalizeRuntime({ ...next, updatedAt: Date.now() });
    const depositStore = transaction.objectStore(DEPOSIT_STORE);
    const archiveStore = transaction.objectStore(ARCHIVE_STORE);
    const [current, deposits] = await Promise.all([
        requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY)),
        requestResult(depositStore.getAll())
    ]);
    const requiredArchiveId = journalDropArchiveId(normalizeRuntime(current), value);
    let archive = null;
    let changed = new Set();
    // Validate before any put: a rejected write must leave every store unchanged.
    try {
        if (updates.length || requiredArchiveId) {
            archive = requestArchiveMap(await requestResult(archiveStore.getAll()));
            changed = mergeRequestArchiveUpdates(archive, updates, value.updatedAt);
            const record = requiredArchiveId ? archive.get(requiredArchiveId) : null;
            if (requiredArchiveId && (!record || record.disposition === 'pending')) {
                throw requestArchiveError(
                    'A transmitted request journal can only be cleared after the archive records its outcome.',
                    'request_journal_unarchived'
                );
            }
        }
    } catch (error) {
        try { transaction.abort(); } catch { /* Preserve the validation failure. */ }
        throw error;
    }
    const history = depositRecordMap(deposits);
    mergeDepositRecord(history, depositRecord(current?.state, current?.deploymentId), depositStore);
    mergeDepositRecord(history, depositRecord(value.state, value.deploymentId, depositConfirmation || {}), depositStore);
    transaction.objectStore(RUNTIME_STORE).put(value, RUNTIME_KEY);
    if (archive) writeRequestArchiveChanges(archiveStore, archive, changed);
    await transactionDone(transaction);
    return {
        runtime: value,
        requestArchive: archive ? requestArchiveRecords(archive, value.deploymentId) : null
    };
}

/** Commit the wallet snapshot; see commitBrowserWallet for the journal invariant. */
export async function writeBrowserWallet(next, options = {}) {
    return (await commitBrowserWallet(next, options)).runtime;
}

/** Read the deployment's transmitted-request archive records. */
export async function listBrowserRequestArchive(deploymentId = null) {
    const database = await openDatabase();
    const transaction = database.transaction(ARCHIVE_STORE, 'readonly');
    const archives = await requestResult(transaction.objectStore(ARCHIVE_STORE).getAll());
    await transactionDone(transaction);
    return requestArchiveRecords(requestArchiveMap(archives), deploymentId);
}

/**
 * Durably merge request-archive records or patches (observations, evidence,
 * dispositions) without touching the runtime slot. Returns the merged records
 * of the given deployment.
 */
export async function putBrowserRequestArchive(records, { deploymentId = null } = {}) {
    const updates = (Array.isArray(records) ? records : [records]).filter(Boolean);
    const database = await openDatabase();
    const transaction = durableTransaction(database, ARCHIVE_STORE);
    const store = transaction.objectStore(ARCHIVE_STORE);
    const archive = requestArchiveMap(await requestResult(store.getAll()));
    let changed;
    try {
        changed = mergeRequestArchiveUpdates(archive, updates, Date.now());
    } catch (error) {
        try { transaction.abort(); } catch { /* Preserve the validation failure. */ }
        throw error;
    }
    writeRequestArchiveChanges(store, archive, changed);
    await transactionDone(transaction);
    return requestArchiveRecords(archive, deploymentId);
}

/**
 * Save verified, finalized ExpiredClaimed observations as payment metadata.
 * The caller verifies canonical chain evidence; this boundary independently
 * enforces deployment/note identity and known amount/expiry. It cannot close a
 * note, discard a pending request, or change any private recovery material.
 */
export async function recordBrowserExpiryClaims(deploymentId, claims) {
    if (typeof deploymentId !== 'string' || !deploymentId.trim() || !Array.isArray(claims)) {
        throw new Error('Expiry history requires a deployment and claim records.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, DEPOSIT_STORE);
    const store = transaction.objectStore(DEPOSIT_STORE);
    const stored = await requestResult(store.getAll());
    const history = depositRecordMap(stored.filter(record =>
        record.deploymentId === deploymentId && record.status === 'confirmed'));
    const updates = new Map();
    try {
        for (const claim of claims) {
            if (!claim || (claim.deploymentId != null && claim.deploymentId !== deploymentId)
                || claim.noteId == null || !Number.isSafeInteger(Number(claim.noteId))
                || Number(claim.noteId) < 0 || Number(claim.noteId) > 0xffffffff) {
                throw new Error('An expiry claim has an invalid deployment or note identity.');
            }
            const recordId = `${deploymentId}:deposit:${Number(claim.noteId)}`;
            const record = history.get(recordId);
            // Older fully sanitized history may have neither original expiry
            // nor note state. Do not infer an expiry or invent an owned deposit.
            if (!record || !record.expiryTs) continue;
            const expiryClaim = sanitizedExpiryClaim(claim, record.amount, record.expiryTs);
            if (!expiryClaim) throw new Error('An expiry claim does not match its saved deposit.');
            if (record.expiryClaim && JSON.stringify(record.expiryClaim) !== JSON.stringify(expiryClaim)) {
                throw new Error('A different finalized expiry claim is already saved for this deposit.');
            }
            const next = { ...record, expiryClaim };
            history.set(recordId, next);
            if (!record.expiryClaim) updates.set(recordId, next);
        }
        for (const record of updates.values()) store.put(record);
        await transactionDone(transaction);
        return [...updates.values()].map(record => ({ ...record, expiryClaim: { ...record.expiryClaim } }));
    } catch (error) {
        try { transaction.abort(); } catch { /* Preserve the original validation/storage failure. */ }
        throw error;
    }
}

export async function archiveBrowserWallet(reason = 'closed', expectedNoteId = null) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, ARCHIVE_STORE, DEPOSIT_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (expectedNoteId != null
        && Number(current.state?.note_id) !== Number(expectedNoteId)) {
        transaction.abort();
        throw new Error('The selected private note changed before it could be archived.');
    }
    if (reason === 'expiry-claimed') {
        const stored = current.state && await requestResult(transaction.objectStore(DEPOSIT_STORE)
            .get(`${current.deploymentId}:deposit:${current.state.note_id}`));
        const record = stored?.status === 'confirmed' && stored.deploymentId === current.deploymentId
            ? depositRecordMap([stored]).get(`${current.deploymentId}:deposit:${current.state.note_id}`) : null;
        if (expectedNoteId == null || !record?.expiryClaim
            || record.noteId !== Number(current.state?.note_id)
            || record.amount !== Number(current.state?.deposit_amount)
            || record.expiryTs !== positiveTimestamp(current.state?.expiry_ts)) {
            transaction.abort();
            throw new Error('This private note has no matching confirmed expiry claim.');
        }
    }
    const archiveStore = transaction.objectStore(ARCHIVE_STORE);
    // A closed note's transmitted requests can never install again. Compact
    // them so their proofs and rerandomization do not outlive the note.
    const requestArchive = current.state
        ? requestArchiveMap(await requestResult(archiveStore.getAll()))
        : new Map();
    const supersededRequests = current.state
        ? supersedeNoteRequestArchive(requestArchive, current.deploymentId, current.state.note_id, Date.now())
        : new Set();
    if (current.state) {
        transaction.objectStore(ARCHIVE_STORE).put({
            archiveId: `${current.deploymentId || 'deployment'}:${current.state.note_id}:${Date.now()}`,
            reason,
            archivedAt: Date.now(),
            deploymentId: current.deploymentId,
            state: current.state,
            ...(reason === 'expiry-claimed' ? {
                // Explicitly moving a claimed note out of the selected slot
                // must not destroy an unfinished key's private recovery data.
                journal: current.journal,
                lease: current.lease,
                preparedWithdrawal: current.preparedWithdrawal,
                pendingDeposit: current.pendingDeposit
            } : {})
        });
    }
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        lateWithdrawalAttempts: current.lateWithdrawalAttempts || [],
        lateDepositAttempts: current.lateDepositAttempts || [],
        updatedAt: Date.now()
    });
    runtimeStore.put(next, RUNTIME_KEY);
    writeRequestArchiveChanges(archiveStore, requestArchive, supersededRequests);
    await transactionDone(transaction);
    return next;
}

export async function listBrowserWithdrawals(deploymentId = null) {
    const database = await openDatabase();
    const transaction = database.transaction(WITHDRAWAL_STORE, 'readonly');
    const records = await requestResult(transaction.objectStore(WITHDRAWAL_STORE).getAll());
    await transactionDone(transaction);
    return records
        .filter(record => !deploymentId || record.deploymentId === deploymentId)
        .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0));
}

export async function putBrowserWithdrawal(record) {
    if (!record?.recordId) throw new Error('A durable withdrawal record requires an ID.');
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const value = { ...record, revision: Number(record.revision || 0) + 1, updatedAt: Date.now() };
    transaction.objectStore(WITHDRAWAL_STORE).put(value);
    await transactionDone(transaction);
    return value;
}

/**
 * Move a chain-confirmed escape out of the selected wallet slot atomically.
 * The complete private state stays in the recovery record because a challenge
 * can reactivate this note before the safety deadline.
 */
export async function detachBrowserEscapeWithdrawal(record) {
    if (!record?.recordId || record.noteId == null) {
        throw new Error('A pending escape requires a durable note identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (!current.state || Number(current.state.note_id) !== Number(record.noteId)) {
        transaction.abort();
        throw new Error('The selected private note changed before the escape could be saved.');
    }
    if (current.journal || current.lease || current.pendingDeposit) {
        transaction.abort();
        throw new Error('Finish the other private-balance operation before saving this escape.');
    }
    const now = Date.now();
    const durableRecord = {
        ...record,
        deploymentId: record.deploymentId || current.deploymentId,
        state: current.state,
        preparedWithdrawal: current.preparedWithdrawal,
        clearanceReserved: current.preparedWithdrawal?.clearanceReserved === true
            || record.clearanceReserved === true,
        withdrawalNullifier: current.preparedWithdrawal?.withdrawalNullifier
            || current.preparedWithdrawal?.public_inputs?.withdrawal_nullifier
            || record.withdrawalNullifier
            || null,
        revision: 1,
        createdAt: Number(record.createdAt || now),
        updatedAt: now
    };
    transaction.objectStore(WITHDRAWAL_STORE).put(durableRecord);
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        pendingDeposit: current.pendingDeposit,
        lateWithdrawalAttempts: current.lateWithdrawalAttempts || [],
        lateDepositAttempts: current.lateDepositAttempts || [],
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord };
}

/**
 * Move a chain-closed selected note into the background without deleting its
 * recovery material. The record is sanitized only after the close block is
 * finalized, so a short reorg can safely restore the note.
 */
export async function detachBrowserClosedWithdrawal(record) {
    if (!record?.recordId || record.noteId == null || !record.closeBlockNumber) {
        throw new Error('A closing withdrawal requires a durable note and block identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (!current.state || Number(current.state.note_id) !== Number(record.noteId)) {
        transaction.abort();
        throw new Error('The selected private note changed before its close could be saved.');
    }
    if (current.journal || current.lease || current.pendingDeposit) {
        transaction.abort();
        throw new Error('Finish the other private-balance operation before saving this close.');
    }
    const now = Date.now();
    const durableRecord = {
        ...record,
        deploymentId: record.deploymentId || current.deploymentId,
        phase: 'closed_unconfirmed',
        state: current.state,
        preparedWithdrawal: current.preparedWithdrawal,
        clearanceReserved: current.preparedWithdrawal?.clearanceReserved === true
            || current.preparedWithdrawal?.mode === 'mutual'
            || record.clearanceReserved === true,
        withdrawalNullifier: current.preparedWithdrawal?.withdrawalNullifier
            || current.preparedWithdrawal?.public_inputs?.withdrawal_nullifier
            || record.withdrawalNullifier
            || null,
        revision: 1,
        createdAt: Number(record.createdAt || now),
        closedAt: Number(record.closedAt || now),
        updatedAt: now
    };
    transaction.objectStore(WITHDRAWAL_STORE).put(durableRecord);
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        pendingDeposit: current.pendingDeposit,
        lateWithdrawalAttempts: current.lateWithdrawalAttempts || [],
        lateDepositAttempts: current.lateDepositAttempts || [],
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord };
}

/**
 * Transfer a late wallet broadcast to a durable background record and retire
 * the runtime attempt in the same transaction. This is the crash boundary for
 * a MetaMask window that returns after another tab changed the selected plan.
 */
export async function transferBrowserLateWithdrawalAttempt(identity, record) {
    if (!identity?.operationId || !/^0x[0-9a-fA-F]{64}$/.test(identity.transactionHash || '')
        || !record?.recordId
        || ![
            'pending',
            'submitted_unconfirmed',
            'challenged_unconfirmed',
            'closed_unconfirmed'
        ].includes(record.phase)) {
        throw new Error('The late withdrawal transfer is missing its durable identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const withdrawalStore = transaction.objectStore(WITHDRAWAL_STORE);
    const [current, existing] = await Promise.all([
        requestResult(runtimeStore.get(RUNTIME_KEY)).then(normalizeRuntime),
        requestResult(withdrawalStore.get(record.recordId))
    ]);
    const normalizedHash = identity.transactionHash.toLowerCase();
    const attempts = Array.isArray(current.lateWithdrawalAttempts)
        ? current.lateWithdrawalAttempts
        : [];
    const attemptIndex = attempts.findIndex(attempt =>
        attempt.operationId === identity.operationId
        && String(attempt.transactionHash || '').toLowerCase() === normalizedHash
        && attempt.deploymentId === identity.deploymentId
        && Number(attempt.chainId) === Number(identity.chainId)
        && String(attempt.contractAddress || '').toLowerCase()
            === String(identity.contractAddress || '').toLowerCase()
        && Number(attempt.noteId) === Number(identity.noteId));
    if (attemptIndex < 0) {
        transaction.abort();
        throw new Error('The late withdrawal changed before it could be transferred.');
    }
    const attempt = attempts[attemptIndex];
    if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)) {
        await transactionDone(transaction);
        return { runtime: current, withdrawal: existing || null, attempt };
    }
    const selectedOwns = current.state
        && Number(current.state.note_id) === Number(identity.noteId);
    const backgroundOwns = existing?.state
        && Number(existing.state.note_id) === Number(identity.noteId);
    if (!selectedOwns && !backgroundOwns) {
        transaction.abort();
        throw new Error('The private note recovery material is not available for this late withdrawal.');
    }
    if (selectedOwns && (current.journal || current.lease || current.pendingDeposit)) {
        transaction.abort();
        throw new Error('An in-flight private-balance operation must finish before this withdrawal can move to the background.');
    }

    const now = Date.now();
    const preparedSource = existing?.preparedWithdrawal || current.preparedWithdrawal || null;
    const preparedWithdrawal = preparedSource ? structuredClone(preparedSource) : null;
    const resolvesStartClaim = Boolean(existing?.startSubmissionId
        && existing.startSubmissionId === attempt.submissionId
        && (existing.startOperationId || preparedWithdrawal?.operationId)
            === attempt.operationId);
    if (resolvesStartClaim && preparedWithdrawal?.submissionId === attempt.submissionId) {
        const preparedHashes = [...new Set([
            ...(Array.isArray(preparedWithdrawal.transactionHashes)
                ? preparedWithdrawal.transactionHashes
                : preparedWithdrawal.transactionHash
                    ? [preparedWithdrawal.transactionHash]
                    : []),
            normalizedHash
        ].map(hash => String(hash).toLowerCase()))];
        preparedWithdrawal.phase = 'submitted';
        preparedWithdrawal.submissionOutcome = 'submitted';
        preparedWithdrawal.transactionHash = preparedHashes[0];
        preparedWithdrawal.transactionHashes = preparedHashes;
        preparedWithdrawal.transactionAttempts = [
            ...(Array.isArray(preparedWithdrawal.transactionAttempts)
                ? preparedWithdrawal.transactionAttempts.filter(entry =>
                    String(entry.hash || '').toLowerCase() !== normalizedHash)
                : []),
            {
                hash: normalizedHash,
                operationId: attempt.operationId,
                submissionId: attempt.submissionId || null,
                from: /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    ? attempt.from.toLowerCase()
                    : null,
                nonce: Number.isSafeInteger(Number(attempt.nonce))
                    ? Number(attempt.nonce)
                    : null,
                observedAt: Number(attempt.observedAt || now)
            }
        ];
        delete preparedWithdrawal.submissionId;
        delete preparedWithdrawal.submissionOwner;
        delete preparedWithdrawal.submissionStartedAt;
        delete preparedWithdrawal.submissionFrom;
        delete preparedWithdrawal.submissionNonce;
        delete preparedWithdrawal.submissionNonceJournalRequired;
        delete preparedWithdrawal.submissionError;
    }
    const aggregatesUnconfirmedStarts = record.phase === 'submitted_unconfirmed'
        || selectedOwns
        || existing?.startRecoveryPending === true;
    // The nonce journal is the last write before eth_sendTransaction. If a
    // cross-tab transfer wins while the selected claim still has no durable
    // {from, nonce}, its pending onPrepared callback will fail after reloading
    // the now-empty selected slot and the wallet request cannot be sent. Retire
    // that exact pre-broadcast claim in this same transaction instead of
    // preserving a hashless background lock that no tab can ever complete.
    const migratedPreNonceClaim = aggregatesUnconfirmedStarts
        && preparedWithdrawal?.submissionId
        && preparedWithdrawal.submissionNonceJournalRequired === true
        && (!/^0x[0-9a-fA-F]{40}$/.test(preparedWithdrawal.submissionFrom || '')
            || !Number.isSafeInteger(Number(preparedWithdrawal.submissionNonce))
            || Number(preparedWithdrawal.submissionNonce) < 0)
        ? {
            submissionId: preparedWithdrawal.submissionId,
            operationId: preparedWithdrawal.operationId || null,
            owner: preparedWithdrawal.submissionOwner || null,
            startedAt: preparedWithdrawal.submissionStartedAt || null,
            dismissedAt: now,
            reason: 'migrated_before_nonce_journal'
        }
        : null;
    if (migratedPreNonceClaim) {
        const preparedHashes = Array.isArray(preparedWithdrawal.transactionHashes)
            ? preparedWithdrawal.transactionHashes
            : preparedWithdrawal.transactionHash
                ? [preparedWithdrawal.transactionHash]
                : [];
        preparedWithdrawal.phase = preparedHashes.length ? 'submitted' : 'prepared';
        preparedWithdrawal.submissionOutcome = 'rejected_before_broadcast';
        delete preparedWithdrawal.submissionId;
        delete preparedWithdrawal.submissionOwner;
        delete preparedWithdrawal.submissionStartedAt;
        delete preparedWithdrawal.submissionFrom;
        delete preparedWithdrawal.submissionNonce;
        delete preparedWithdrawal.submissionNonceJournalRequired;
        delete preparedWithdrawal.submissionError;
    }
    const sameLateNote = entry => entry.deploymentId === identity.deploymentId
        && Number(entry.chainId) === Number(identity.chainId)
        && String(entry.contractAddress || '').toLowerCase()
            === String(identity.contractAddress || '').toLowerCase()
        && Number(entry.noteId) === Number(identity.noteId);
    const relatedLateAttempts = aggregatesUnconfirmedStarts
        ? attempts.filter(entry => sameLateNote(entry)
            && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status))
        : [attempt];
    const transactionHashes = [...new Set([
        ...(Array.isArray(existing?.transactionHashes)
            ? existing.transactionHashes
            : existing?.transactionHash ? [existing.transactionHash] : []),
        ...(aggregatesUnconfirmedStarts
            ? (Array.isArray(preparedWithdrawal?.transactionHashes)
                ? preparedWithdrawal.transactionHashes
                : preparedWithdrawal?.transactionHash
                    ? [preparedWithdrawal.transactionHash]
                    : [])
            : []),
        ...relatedLateAttempts.map(entry => entry.transactionHash).filter(Boolean),
        normalizedHash
    ].map(value => value.toLowerCase()))];
    const transactionAttempts = [...new Map([
        ...(Array.isArray(existing?.transactionAttempts)
            ? existing.transactionAttempts
            : []),
        ...(aggregatesUnconfirmedStarts && Array.isArray(preparedWithdrawal?.transactionAttempts)
            ? preparedWithdrawal.transactionAttempts
            : []),
        ...relatedLateAttempts.map(entry => ({
            hash: String(entry.transactionHash || '').toLowerCase(),
            operationId: entry.operationId,
            submissionId: entry.submissionId || null,
            from: /^0x[0-9a-fA-F]{40}$/.test(entry.from || '')
                ? entry.from.toLowerCase()
                : null,
            nonce: Number.isSafeInteger(Number(entry.nonce))
                ? Number(entry.nonce)
                : null,
            observedAt: Number(entry.observedAt || now)
        }))
    ].filter(entry => /^0x[0-9a-fA-F]{64}$/.test(entry.hash || ''))
        .map(entry => [String(entry.hash).toLowerCase(), {
            ...entry,
            hash: String(entry.hash).toLowerCase()
        }])).values()];
    const durableRecord = {
        ...(existing || {}),
        ...record,
        deploymentId: identity.deploymentId,
        chainId: Number(identity.chainId),
        contractAddress: identity.contractAddress,
        noteId: Number(identity.noteId),
        state: existing?.state || current.state,
        preparedWithdrawal,
        clearanceReserved: existing?.clearanceReserved === true
            || preparedWithdrawal?.clearanceReserved === true
            || preparedWithdrawal?.mode === 'mutual'
            || attempt.clearanceReserved === true
            || record.clearanceReserved === true,
        withdrawalNullifier: existing?.withdrawalNullifier
            || preparedWithdrawal?.withdrawalNullifier
            || preparedWithdrawal?.public_inputs?.withdrawal_nullifier
            || attempt.withdrawalNullifier
            || record.withdrawalNullifier
            || null,
        // A canonical-state recovery can discover that MetaMask replaced the
        // saved hash. Keep that hash in the audit list, but do not later treat
        // its unrelated receipt as the receipt that moved this note.
        transactionHash: record.canonicalRecovery
            ? existing?.transactionHash || null
            : existing?.transactionHash
                || preparedWithdrawal?.transactionHash
                || normalizedHash,
        transactionHashes,
        transactionAttempts,
        startRecoveryPending: aggregatesUnconfirmedStarts
            ? true
            : existing?.startRecoveryPending === true,
        startSubmissionId: aggregatesUnconfirmedStarts && !resolvesStartClaim
            ? preparedWithdrawal?.submissionId || existing?.startSubmissionId || null
            : existing?.startSubmissionId || null,
        startOperationId: aggregatesUnconfirmedStarts && !resolvesStartClaim
            ? preparedWithdrawal?.operationId || existing?.startOperationId || null
            : resolvesStartClaim ? null : existing?.startOperationId || null,
        startSubmissionFrom: aggregatesUnconfirmedStarts && !resolvesStartClaim
            ? preparedWithdrawal?.submissionFrom || existing?.startSubmissionFrom || null
            : resolvesStartClaim ? null : existing?.startSubmissionFrom || null,
        startSubmissionNonce: aggregatesUnconfirmedStarts && !resolvesStartClaim
            ? (preparedWithdrawal?.submissionNonce ?? existing?.startSubmissionNonce ?? null)
            : resolvesStartClaim ? null : existing?.startSubmissionNonce ?? null,
        ...(
            (aggregatesUnconfirmedStarts || resolvesStartClaim)
            && !preparedWithdrawal?.submissionId
            && (!existing?.startSubmissionId || resolvesStartClaim)
                ? {
                    startSubmissionOutcome: null,
                    startMissingTransactionHashes: [],
                    startReplacementTransactionHashes: []
                }
                : {}
        ),
        ...(migratedPreNonceClaim ? {
            startSubmissionOutcome: 'rejected_before_broadcast',
            dismissedStartSubmissionClaims: [
                ...(Array.isArray(existing?.dismissedStartSubmissionClaims)
                    ? existing.dismissedStartSubmissionClaims
                    : []),
                migratedPreNonceClaim
            ].slice(-8)
        } : {}),
        revision: Number(existing?.revision || 0) + 1,
        createdAt: Number(existing?.createdAt || record.createdAt || attempt.observedAt || now),
        updatedAt: now
    };
    if (resolvesStartClaim) {
        delete durableRecord.startSubmissionId;
        delete durableRecord.startOperationId;
        delete durableRecord.startSubmissionOwner;
        delete durableRecord.startSubmissionStartedAt;
        delete durableRecord.startSubmissionFrom;
        delete durableRecord.startSubmissionNonce;
        delete durableRecord.startRetryFrom;
        delete durableRecord.startRetryNonce;
        delete durableRecord.startRetryOperationId;
        delete durableRecord.startRetrySavedAt;
    }
    withdrawalStore.put(durableRecord);

    const terminalStatus = record.phase === 'closed_unconfirmed' ? 'closed' : 'detached';
    const nextAttempt = {
        ...attempt,
        status: terminalStatus,
        backgroundRecordId: record.recordId,
        resolvedAt: now,
        error: null
    };
    const nextAttempts = attempts.map((entry, index) => {
        if (index === attemptIndex) return nextAttempt;
        const sameConsumedNote = sameLateNote(entry);
        return sameConsumedNote && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status)
            ? {
                ...entry,
                status: aggregatesUnconfirmedStarts ? 'detached' : 'superseded',
                ...(aggregatesUnconfirmedStarts
                    ? { backgroundRecordId: record.recordId }
                    : { supersededBy: normalizedHash }),
                resolvedAt: now,
                error: null
            }
            : entry;
    });
    const unresolved = nextAttempts.filter(entry =>
        !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status));
    const terminalHistory = nextAttempts.filter(entry =>
        LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status)).slice(-32);
    const next = normalizeRuntime({
        ...current,
        ...(selectedOwns ? {
            state: null,
            journal: null,
            preparedWithdrawal: null,
            lease: null
        } : {}),
        lateWithdrawalAttempts: [...terminalHistory, ...unresolved],
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord, attempt: nextAttempt };
}

/** Claim an exact-nonce replacement for a dropped background withdrawal start. */
function backgroundIdentityMatches(record, identity) {
    return record && identity?.recordId === record.recordId
        && identity.deploymentId === record.deploymentId
        && Number(identity.chainId) === Number(record.chainId)
        && String(identity.contractAddress || '').toLowerCase() === String(record.contractAddress || '').toLowerCase()
        && Number(identity.noteId) === Number(record.noteId)
        && identity.mode === record.mode
        && String(identity.destination || '').toLowerCase() === String(record.destination || '').toLowerCase();
}

function backgroundHasTransactions(record) {
    return [record, record?.preparedWithdrawal].some(value => value && (
        value.transactionHash || value.transactionHashes?.length || value.transactionAttempts?.length
        || value.submissionId || value.finalizeTransactionHash || value.finalizeTransactionHashes?.length
        || value.finalizeAttempts?.length || value.finalizeSubmissionId
    )) || Boolean(record?.startRecoveryPending || record?.startSubmissionId
        || record?.startRetryFrom || record?.startRetryNonce != null
        || record?.supersededStartSubmissionClaims?.length || record?.ambiguousStartReplacements?.length);
}

export function assertBrowserBackgroundWithdrawalAvailable(record, runtime, identity) {
    if (!backgroundIdentityMatches(record, identity) || !record.state
        || Number(record.state.note_id) !== Number(record.noteId)
        || record.mode !== 'mutual' || !['parked', 'restored'].includes(record.phase)
        || !/^0x[0-9a-fA-F]{40}$/.test(record.destination || '')
        || record.clearanceReserved !== true || backgroundHasTransactions(record)
        || Number(record.startBlockNumber || 0) > 0 || Number(record.closeBlockNumber || 0) > 0
        || Number(record.challengeDeadline || 0) > 0 || record.chainStatus === 'pending_withdrawal'
        || !['reserving', 'prepared'].includes(record.preparedWithdrawal?.phase || 'prepared')
        || !isUnsubmittedParkedMutualWithdrawal(record, runtime.lateWithdrawalAttempts || [])) {
        throw new Error('Check this saved withdrawal before preparing another transaction.');
    }
    if (runtime.deploymentId === record.deploymentId && runtime.state
        && Number(runtime.state.note_id) === Number(record.noteId)) {
        throw new Error('This balance is already selected; use its normal withdrawal flow.');
    }
    if ((runtime.lateWithdrawalAttempts || []).some(attempt =>
        !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)
        && attempt.deploymentId === record.deploymentId
        && Number(attempt.chainId) === Number(record.chainId)
        && String(attempt.contractAddress || '').toLowerCase() === String(record.contractAddress || '').toLowerCase()
        && Number(attempt.noteId) === Number(record.noteId))) {
        throw new Error('A transaction for this saved withdrawal still needs reconciliation.');
    }
}

export function isBrowserBackgroundWithdrawalPreparationCancelable(record, runtime, identity = record) {
    const prepared = record?.preparedWithdrawal;
    // Only the independent driver guarantees that it awaits a durable nonce
    // write before calling MetaMask. Never infer this for a legacy claim.
    if (record?.independentWithdrawal !== true || prepared?.submissionNonceJournalRequired !== true
        || record.phase !== 'submitted_unconfirmed' || prepared.phase !== 'awaiting_wallet'
        || record.startSubmissionOutcome !== 'awaiting_wallet'
        || prepared.submissionOutcome !== 'awaiting_wallet'
        || !record.startSubmissionId || !record.startOperationId
        || record.startSubmissionId !== prepared.submissionId
        || record.startOperationId !== prepared.operationId
        || Number(record.startResolutionBlock || 0) > 0 || record.resolvedStartClaims?.length) return false;
    const nonceEvidence = ['from', 'nonce', 'transactionNonce', 'replacementNonce',
        'submissionFrom', 'submissionNonce', 'startSubmissionFrom', 'startSubmissionNonce',
        'startRetryFrom', 'startRetryNonce'];
    if ([record, prepared].some(value => nonceEvidence.some(key => value[key] != null))) return false;
    const withoutClaim = { ...record, phase: 'parked', startSubmissionId: null,
        startRecoveryPending: false, startSubmissionOutcome: 'rejected_before_broadcast',
        preparedWithdrawal: { ...prepared, phase: 'prepared', submissionId: null,
            submissionOutcome: 'rejected_before_broadcast' } };
    try {
        // This also denies hashes, superseded/ambiguous claims, real chain
        // transitions, selected-note ownership, and a concurrent late WAL.
        assertBrowserBackgroundWithdrawalAvailable(withoutClaim, runtime, identity);
        return true;
    } catch {
        return false;
    }
}

// The runtime participates only in the ownership check. These operations never
// write it, so an unrelated chat/deposit/lease can continue without being swapped.
async function mutateBackgroundWithdrawal(identity, mutate) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const [record, runtime] = await Promise.all([
        requestResult(store.get(identity?.recordId)),
        requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY)).then(normalizeRuntime)
    ]);
    try {
        if (!backgroundIdentityMatches(record, identity)) throw new Error('The saved withdrawal identity changed.');
        const next = mutate(record, runtime);
        if (!next) { await transactionDone(transaction); return null; }
        if (JSON.stringify(next) === JSON.stringify(record)) {
            await transactionDone(transaction);
            return record;
        }
        const saved = { ...next, revision: Number(record.revision || 0) + 1, updatedAt: Date.now() };
        store.put(saved);
        await transactionDone(transaction);
        return saved;
    } catch (error) {
        try { transaction.abort(); } catch { /* Already aborted/completed. Preserve the original failure. */ }
        throw error;
    }
}

export async function repairBrowserUnsubmittedBackgroundWithdrawal(identity, observedBlock, expectedRevision) {
    return mutateBackgroundWithdrawal(identity, (record, runtime) => {
        if (Number(record.revision) !== Number(expectedRevision)
            || !Number.isSafeInteger(observedBlock) || observedBlock <= 0
            || observedBlock < Number(record.lastObservedBlock || 0)
            || !isUnsubmittedParkedMutualWithdrawal(record, runtime.lateWithdrawalAttempts || [])) return null;
        const next = { ...record, phase: 'parked', chainStatus: 'active', lastObservedBlock: observedBlock, error: null };
        for (const key of ['challengeObservedBlock', 'finalityCheckedBlock', 'finalitySource', 'finalizedBlockNumber']) delete next[key];
        return next;
    });
}

export async function resolveBrowserBackgroundWithdrawalForRetry(identity, {
    expectedRevision, resolvedTransactionHashes, finalizedBlock, observedBlock
}) {
    return mutateBackgroundWithdrawal(identity, (record, runtime) => {
        if (Number(record.revision) !== Number(expectedRevision)
            || !record.state || record.mode !== 'mutual' || record.chainStatus !== 'active'
            || record.startRecoveryPending !== false || record.startSubmissionOutcome !== 'resolved'
            || record.startSubmissionId || record.startRetryFrom || record.startRetryNonce != null
            || record.preparedWithdrawal?.submissionId || record.finalizeSubmissionId
            || record.finalizeTransactionHash || record.finalizeTransactionHashes?.length
            || !Number.isSafeInteger(finalizedBlock) || finalizedBlock <= 0
            || finalizedBlock < Number(record.startBlockNumber || 0)
            || finalizedBlock < Number(record.startResolutionBlock || 0)
            || !Number.isSafeInteger(observedBlock) || observedBlock < finalizedBlock
            || observedBlock < Number(record.lastObservedBlock || 0)) {
            throw new Error('The withdrawal changed or still has unresolved transactions. Check its status again.');
        }
        if ((runtime.lateWithdrawalAttempts || []).some(attempt =>
            !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)
            && attempt.deploymentId === record.deploymentId && Number(attempt.noteId) === Number(record.noteId))) {
            throw new Error('A late withdrawal transaction still needs reconciliation.');
        }
        const knownHashes = [...new Set([record, record.preparedWithdrawal].flatMap(value => value ? [
            ...(value.transactionHash ? [value.transactionHash] : []), ...(value.transactionHashes || []),
            ...(value.transactionAttempts || []).map(attempt => attempt.hash)
        ] : []).map(hash => String(hash).toLowerCase()))].sort();
        const resolved = [...new Set((resolvedTransactionHashes || []).map(hash => String(hash).toLowerCase()))].sort();
        if (knownHashes.some(hash => !/^0x[0-9a-f]{64}$/.test(hash))
            || JSON.stringify(knownHashes) !== JSON.stringify(resolved)) {
            throw new Error('Every saved withdrawal transaction must be finalized before retrying.');
        }
        const prepared = record.preparedWithdrawal || {};
        const history = [...(record.resolvedStartTransactionHistory || []), {
            operationId: prepared.operationId, transactionHashes: knownHashes,
            transactionAttempts: record.transactionAttempts || [],
            preparedTransactionAttempts: prepared.transactionAttempts || [],
            dismissedClaims: record.dismissedStartSubmissionClaims || [],
            supersededClaims: record.supersededStartSubmissionClaims || [],
            ambiguousClaims: record.ambiguousStartReplacements || [],
            resolvedClaims: (record.resolvedStartClaims || []).map(claim => ({
                submissionId: claim.submissionId, operationId: claim.operationId,
                from: claim.from, nonce: claim.nonce
            })),
            finalizedBlock, observedBlock, resolvedAt: Date.now()
        }];
        const next = { ...record, phase: 'parked', chainStatus: 'active', error: null,
            resolvedStartTransactionHistory: history, lastObservedBlock: observedBlock,
            startRecoveryPending: false, startSubmissionOutcome: 'resolved',
            preparedWithdrawal: { mode: 'mutual', phase: 'prepared', operationId: crypto.randomUUID(),
                noteId: Number(record.noteId), destination: record.destination, clearanceReserved: true,
                withdrawalNullifier: record.withdrawalNullifier || prepared.withdrawalNullifier
                    || prepared.public_inputs?.withdrawal_nullifier,
                createdAt: Number(record.createdAt || Date.now()) } };
        for (const key of ['transactionHash', 'transactionHashes', 'transactionAttempts', 'startBlockNumber',
            'closeBlockNumber', 'challengeDeadline', 'closedAt', 'challengeObservedBlock', 'finalityCheckedBlock',
            'finalitySource', 'finalizedBlockNumber', 'startMissingTransactionHashes', 'startReplacementTransactionHashes',
            'startSubmissionFrom', 'startSubmissionNonce', 'startSubmissionStartedAt', 'startSubmissionOwner',
            'startRetryFrom', 'startRetryNonce', 'startRetryOperationId', 'startRetrySavedAt',
            'supersededStartSubmissionClaims', 'ambiguousStartReplacements', 'ambiguousReplacements',
            'ambiguousSubmissions', 'replacementOf', 'finalizeAttempts', 'finalizeTransactionAttempts',
            'resolvedStartClaims', 'startResolutionBlock', 'startRecoveryResolvedAt']) delete next[key];
        return next;
    });
}

export async function saveBrowserBackgroundWithdrawalPlan(identity, expectedRecord, plan) {
    return mutateBackgroundWithdrawal(identity, (record, runtime) => {
        assertBrowserBackgroundWithdrawalAvailable(record, runtime, identity);
        // Polling may advance display/finality metadata during a long proof.
        // Only the captured private state/plan and submission eligibility own it.
        if (JSON.stringify(record.state) !== JSON.stringify(expectedRecord?.state)
            || JSON.stringify(record.preparedWithdrawal) !== JSON.stringify(expectedRecord?.preparedWithdrawal)) {
            throw new Error('The saved withdrawal changed while its proof was being prepared. Try again.');
        }
        if (!plan?.operationId || plan.mode !== 'mutual' || !plan.proof || !plan.public_inputs
            || Number(plan.public_inputs.note_id) !== Number(record.noteId)
            || String(plan.destination).toLowerCase() !== record.destination.toLowerCase()) {
            throw new Error('The saved withdrawal proof has the wrong identity.');
        }
        return { ...record, phase: 'parked', preparedWithdrawal: plan, independentWithdrawal: true,
            withdrawalNullifier: plan.withdrawalNullifier, error: null };
    });
}

export async function claimBrowserBackgroundWithdrawalSubmission(identity, expectedOperationId, ownerId) {
    const submissionId = crypto.randomUUID();
    const record = await mutateBackgroundWithdrawal(identity, (current, runtime) => {
        assertBrowserBackgroundWithdrawalAvailable(current, runtime, identity);
        const plan = current.preparedWithdrawal;
        if (!expectedOperationId || plan?.operationId !== expectedOperationId
            || !plan.proof || !plan.public_inputs || plan.phase !== 'prepared') {
            throw new Error('The saved withdrawal proof changed before its wallet request.');
        }
        const now = Date.now();
        return { ...current, phase: 'submitted_unconfirmed', startRecoveryPending: true,
            startOperationId: plan.operationId, startSubmissionId: submissionId,
            startSubmissionOwner: ownerId, startSubmissionStartedAt: now,
            startSubmissionOutcome: 'awaiting_wallet',
            preparedWithdrawal: { ...plan, phase: 'awaiting_wallet', submissionId,
                submissionOwner: ownerId, submissionStartedAt: now,
                submissionOutcome: 'awaiting_wallet', submissionNonceJournalRequired: true } };
    });
    const plan = record.preparedWithdrawal;
    return { ...identity, status: 'claimed', submissionId, transactionHash: null,
        operationId: plan.operationId, finalBalance: Number(plan.public_inputs.final_balance),
        clearanceReserved: true, withdrawalNullifier: plan.withdrawalNullifier,
        plan: structuredClone(plan) };
}

function assertBackgroundClaim(record, submission) {
    if (record.startSubmissionId !== submission.submissionId
        || record.startOperationId !== submission.operationId
        || record.preparedWithdrawal?.submissionId !== submission.submissionId
        || record.preparedWithdrawal?.operationId !== submission.operationId) {
        throw new Error('The saved withdrawal wallet claim changed.');
    }
}

export async function rememberBrowserBackgroundWithdrawalMetadata(submission, metadata) {
    const { from, nonce } = metadata || {};
    if (!/^0x[0-9a-fA-F]{40}$/.test(from || '') || !Number.isSafeInteger(nonce) || nonce < 0) {
        throw new Error('The withdrawal transaction metadata is invalid.');
    }
    return mutateBackgroundWithdrawal(submission, record => {
        assertBackgroundClaim(record, submission);
        if (record.startSubmissionFrom && (record.startSubmissionFrom !== from.toLowerCase()
            || record.startSubmissionNonce !== nonce)) throw new Error('The saved wallet nonce changed.');
        return { ...record, startSubmissionFrom: from.toLowerCase(), startSubmissionNonce: nonce,
            preparedWithdrawal: { ...record.preparedWithdrawal, submissionFrom: from.toLowerCase(), submissionNonce: nonce } };
    });
}

export async function markBrowserBackgroundWithdrawalAmbiguous(submission, message) {
    return mutateBackgroundWithdrawal(submission, record => {
        assertBackgroundClaim(record, submission);
        return { ...record, startSubmissionOutcome: 'ambiguous',
            startSubmissionError: message || 'MetaMask did not return a transaction ID.',
            preparedWithdrawal: { ...record.preparedWithdrawal, phase: 'ambiguous',
                submissionOutcome: 'ambiguous', submissionError: message || 'MetaMask did not return a transaction ID.' } };
    });
}

export async function releaseBrowserBackgroundWithdrawalSubmission(submission, { requireNoNonce = false } = {}) {
    return mutateBackgroundWithdrawal(submission, (record, runtime) => {
        assertBackgroundClaim(record, submission);
        if (requireNoNonce && !isBrowserBackgroundWithdrawalPreparationCancelable(record, runtime, submission)) {
            throw new Error('This withdrawal may already have reached MetaMask. Check its status instead of canceling its preparation.');
        }
        const next = { ...record, preparedWithdrawal: { ...record.preparedWithdrawal },
            dismissedStartSubmissionClaims: [...(record.dismissedStartSubmissionClaims || []), {
                submissionId: submission.submissionId, operationId: submission.operationId,
                from: record.startSubmissionFrom, nonce: record.startSubmissionNonce,
                reason: 'rejected_before_broadcast', dismissedAt: Date.now()
            }].slice(-8) };
        for (const key of ['submissionId', 'submissionOwner', 'submissionStartedAt', 'submissionFrom',
            'submissionNonce', 'submissionNonceJournalRequired', 'submissionError']) delete next.preparedWithdrawal[key];
        for (const key of ['startSubmissionId', 'startOperationId', 'startSubmissionOwner',
            'startSubmissionStartedAt', 'startSubmissionFrom', 'startSubmissionNonce', 'startSubmissionError']) delete next[key];
        next.startSubmissionOutcome = 'rejected_before_broadcast';
        const unresolved = backgroundHasTransactions({ ...next, startRecoveryPending: false });
        next.startRecoveryPending = unresolved;
        next.phase = unresolved ? 'submitted_unconfirmed' : 'parked';
        next.preparedWithdrawal.phase = unresolved ? 'submitted' : 'prepared';
        next.preparedWithdrawal.submissionOutcome = 'rejected_before_broadcast';
        return next;
    });
}

export async function rememberBrowserBackgroundWithdrawalTransaction(hash, submission, metadata = null) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash || '')) throw new Error('MetaMask returned an invalid withdrawal transaction hash.');
    return mutateBackgroundWithdrawal(submission, record => {
        const archives = record.resolvedStartTransactionHistory || [];
        const archivedIndex = archives.findIndex(entry => [
            ...(entry.resolvedClaims || []), ...(entry.transactionAttempts || []), ...(entry.preparedTransactionAttempts || [])
        ].some(claim => claim.operationId === submission.operationId && claim.submissionId === submission.submissionId));
        if (archivedIndex >= 0) {
            const archived = archives[archivedIndex];
            const claim = [...(archived.resolvedClaims || []), ...(archived.transactionAttempts || []),
                ...(archived.preparedTransactionAttempts || [])].find(value =>
                value.operationId === submission.operationId && value.submissionId === submission.submissionId);
            if (!/^0x[0-9a-fA-F]{40}$/.test(claim.from || '') || !Number.isSafeInteger(claim.nonce)
                || claim.nonce < 0 || (metadata?.from && metadata.from.toLowerCase() !== claim.from.toLowerCase())
                || (metadata?.nonce != null && metadata.nonce !== claim.nonce)) {
                throw new Error('The late transaction does not match its finalized wallet nonce.');
            }
            if ([...(archived.transactionHashes || []), ...(archived.lateObservedHashes || [])].includes(hash.toLowerCase())) {
                return record;
            }
            const history = [...archives];
            history[archivedIndex] = { ...archived, lateObservedHashes: [...(archived.lateObservedHashes || []), hash.toLowerCase()] };
            // Even a previously unseen hash cannot revive this finalized,
            // consumed sender nonce. Preserve only its audit, not a live WAL.
            return { ...record, resolvedStartTransactionHistory: history };
        }
        const activeClaim = record.startSubmissionId === submission.submissionId
            && record.startOperationId === submission.operationId;
        const priorClaims = [...(record.dismissedStartSubmissionClaims || []),
            ...(record.supersededStartSubmissionClaims || []), ...(record.ambiguousStartReplacements || []),
            ...(record.transactionAttempts || [])];
        const knownClaim = activeClaim || priorClaims.some(claim =>
            claim.submissionId === submission.submissionId && claim.operationId === submission.operationId);
        if (!knownClaim) throw new Error('The transaction does not belong to a saved withdrawal claim.');
        const saved = activeClaim ? { from: record.startSubmissionFrom, nonce: record.startSubmissionNonce }
            : priorClaims.find(claim =>
                claim.submissionId === submission.submissionId && claim.operationId === submission.operationId);
        const from = metadata?.from || saved?.from;
        const nonce = metadata?.nonce ?? saved?.nonce;
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '') || !Number.isSafeInteger(nonce) || nonce < 0
            || (saved?.from && saved.from.toLowerCase() !== from.toLowerCase())
            || (Number.isSafeInteger(saved?.nonce) && saved.nonce !== nonce)) {
            throw new Error('The transaction does not match its saved wallet nonce.');
        }
        const normalized = hash.toLowerCase();
        const hashes = [...new Set([...(record.transactionHashes || []), ...(record.transactionHash ? [record.transactionHash] : []), normalized])];
        const attempts = [...(record.transactionAttempts || []).filter(attempt => attempt.hash !== normalized), {
            hash: normalized, submissionId: submission.submissionId, operationId: submission.operationId,
            from: from.toLowerCase(), nonce, observedAt: Date.now()
        }];
        const next = { ...record, transactionHash: hashes[0], transactionHashes: hashes, transactionAttempts: attempts,
            phase: ['closed', 'closed_unconfirmed'].includes(record.phase) ? record.phase : 'submitted_unconfirmed',
            startRecoveryPending: record.phase !== 'closed' };
        if (record.preparedWithdrawal?.operationId === submission.operationId) {
            next.preparedWithdrawal = { ...record.preparedWithdrawal, transactionHash: hashes[0], transactionHashes: hashes,
                transactionAttempts: attempts, phase: 'submitted', submissionOutcome: 'submitted' };
        }
        if (activeClaim) {
            for (const key of ['startSubmissionId', 'startOperationId', 'startSubmissionOwner', 'startSubmissionStartedAt',
                'startSubmissionFrom', 'startSubmissionNonce', 'startSubmissionError']) delete next[key];
            if (next.preparedWithdrawal) {
                for (const key of ['submissionId', 'submissionOwner', 'submissionStartedAt', 'submissionFrom',
                    'submissionNonce', 'submissionNonceJournalRequired', 'submissionError']) delete next.preparedWithdrawal[key];
            }
            next.startSubmissionOutcome = 'submitted';
        }
        return next;
    });
}

export async function claimBrowserWithdrawalStartReplacement(
    recordId,
    ownerId,
    expectedFrom
) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const eligibleOutcome = ['receipt_missing', 'replacement_result_unknown']
        .includes(current?.startSubmissionOutcome);
    const liveClaimIdentity = current?.startSubmissionId
        && /^0x[0-9a-fA-F]{40}$/.test(current.startSubmissionFrom || '')
        && Number.isSafeInteger(Number(current.startSubmissionNonce))
        && Number(current.startSubmissionNonce) >= 0
        ? {
            from: current.startSubmissionFrom.toLowerCase(),
            nonce: Number(current.startSubmissionNonce)
        }
        : null;
    const savedRetryIdentity = !current?.startSubmissionId
        && /^0x[0-9a-fA-F]{40}$/.test(current?.startRetryFrom || '')
        && Number.isSafeInteger(Number(current?.startRetryNonce))
        && Number(current.startRetryNonce) >= 0
        ? {
            from: current.startRetryFrom.toLowerCase(),
            nonce: Number(current.startRetryNonce)
        }
        : null;
    const claimIdentity = liveClaimIdentity || savedRetryIdentity;
    if (!current?.state || !current.preparedWithdrawal
        || current.startRecoveryPending !== true
        || current.phase !== 'submitted_unconfirmed'
        || current.chainStatus !== 'active'
        || (!eligibleOutcome && !claimIdentity)) {
        transaction.abort();
        throw new Error('Check the background withdrawal before replacing its transaction.');
    }
    const prepared = { ...current.preparedWithdrawal };
    const noteId = Number(prepared.noteId
        ?? prepared.public_inputs?.note_id
        ?? current.noteId);
    if (noteId !== Number(current.noteId)
        || !['escape', 'mutual'].includes(prepared.mode)
        || !/^0x[0-9a-fA-F]{40}$/.test(prepared.destination || '')
        || !prepared.proof || !prepared.public_inputs) {
        transaction.abort();
        throw new Error('The retained background withdrawal proof is incomplete.');
    }
    if (liveClaimIdentity && (prepared.submissionId !== current.startSubmissionId
        || (current.startOperationId || prepared.operationId) !== prepared.operationId)) {
        transaction.abort();
        throw new Error('The background wallet claim does not match its retained withdrawal proof.');
    }
    if (savedRetryIdentity && current.startRetryOperationId !== prepared.operationId) {
        transaction.abort();
        throw new Error('The saved background retry does not match its retained withdrawal proof.');
    }
    const allHashes = Array.isArray(current.transactionHashes)
        ? current.transactionHashes
        : current.transactionHash ? [current.transactionHash] : [];
    const allHashSet = new Set(allHashes.map(hash => String(hash).toLowerCase()));
    const preparedHashes = new Set((Array.isArray(prepared.transactionHashes)
        ? prepared.transactionHashes
        : prepared.transactionHash ? [prepared.transactionHash] : [])
        .map(hash => String(hash).toLowerCase()));
    const markedReplacementHashes = (Array.isArray(current.startReplacementTransactionHashes)
        ? current.startReplacementTransactionHashes
        : [])
        .map(hash => String(hash).toLowerCase());
    const replacementHashSet = new Set(markedReplacementHashes.filter(hash =>
        allHashSet.has(hash) && preparedHashes.has(hash)));
    if (!claimIdentity && !replacementHashSet.size) {
        transaction.abort();
        throw new Error('The dropped transaction does not match the retained withdrawal proof. Cancel or speed it up in MetaMask, then check again.');
    }
    const identities = claimIdentity
        ? [claimIdentity]
        : [...new Map((current.transactionAttempts || [])
            .filter(attempt => replacementHashSet.has(String(attempt.hash || '').toLowerCase())
                && attempt.operationId === prepared.operationId
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => {
                const identity = {
                    from: attempt.from.toLowerCase(),
                    nonce: Number(attempt.nonce)
                };
                return [`${identity.from}:${identity.nonce}`, identity];
            })).values()];
    if (identities.length !== 1) {
        transaction.abort();
        throw new Error(identities.length > 1
            ? 'The background withdrawal has more than one wallet nonce. Cancel or speed up those transactions in MetaMask, then check again.'
            : 'The background withdrawal has no replacement nonce. Check its transaction status first.');
    }
    const [{ from, nonce }] = identities;
    if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
        || from !== expectedFrom.toLowerCase()) {
        transaction.abort();
        throw new Error(`Connect the MetaMask account ${from} that submitted this withdrawal.`);
    }
    const now = Date.now();
    const submissionId = crypto.randomUUID();
    const operationId = prepared.operationId || current.startOperationId || crypto.randomUUID();
    const nextPrepared = {
        ...prepared,
        phase: 'awaiting_wallet',
        operationId,
        submissionOutcome: 'replacement_awaiting_wallet',
        submissionId,
        submissionOwner: ownerId,
        submissionStartedAt: now,
        submissionFrom: from,
        submissionNonce: nonce,
        submissionNonceJournalRequired: true,
        replacementOf: claimIdentity
            ? (prepared.replacementOf || [...preparedHashes])
            : [...replacementHashSet]
    };
    const supersededClaims = Array.isArray(current.supersededStartSubmissionClaims)
        ? current.supersededStartSubmissionClaims
        : [];
    const next = {
        ...current,
        preparedWithdrawal: nextPrepared,
        startOperationId: operationId,
        startSubmissionId: submissionId,
        startSubmissionOwner: ownerId,
        startSubmissionStartedAt: now,
        startSubmissionFrom: from,
        startSubmissionNonce: nonce,
        startSubmissionOutcome: 'replacement_awaiting_wallet',
        ...(current.startSubmissionId ? {
            supersededStartSubmissionClaims: [...supersededClaims, {
                submissionId: current.startSubmissionId,
                operationId: current.startOperationId,
                from: current.startSubmissionFrom,
                nonce: Number(current.startSubmissionNonce),
                supersededAt: now,
                reason: 'exact_nonce_takeover'
            }].slice(-8)
        } : {}),
        revision: Number(current.revision || 0) + 1,
        updatedAt: now
    };
    delete next.startRetryFrom;
    delete next.startRetryNonce;
    delete next.startRetryOperationId;
    delete next.startRetrySavedAt;
    store.put(next);
    await transactionDone(transaction);
    return {
        status: 'claimed',
        recordId,
        submissionId,
        transactionHash: null,
        operationId,
        noteId,
        mode: nextPrepared.mode,
        destination: nextPrepared.destination,
        finalBalance: Number(nextPrepared.public_inputs.final_balance
            ?? current.finalBalance),
        clearanceReserved: nextPrepared.clearanceReserved === true
            || nextPrepared.mode === 'mutual',
        withdrawalNullifier: nextPrepared.withdrawalNullifier
            || nextPrepared.public_inputs.withdrawal_nullifier
            || null,
        deploymentId: current.deploymentId,
        chainId: Number(current.chainId),
        contractAddress: current.contractAddress,
        replacementFrom: from,
        replacementNonce: nonce,
        plan: structuredClone(nextPrepared)
    };
}

/**
 * Release an exact start prompt after its note may have moved to background.
 * Replacement prompts remain constrained by their original nonce, so an
 * unknown provider result can release the UI claim without discarding any
 * previously observed hash.
 */
export async function releaseBrowserWithdrawalStartSubmission(recordId, submission, {
    replacementUnknown = false,
    message = null
} = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const withdrawalStore = transaction.objectStore(WITHDRAWAL_STORE);
    const [runtime, current] = await Promise.all([
        requestResult(runtimeStore.get(RUNTIME_KEY)).then(normalizeRuntime),
        requestResult(withdrawalStore.get(recordId))
    ]);
    const prepared = runtime.preparedWithdrawal;
    const replacementNonce = Number(submission?.replacementNonce);
    const hasReplacementNonce = Number.isSafeInteger(replacementNonce)
        && replacementNonce >= 0;
    const selectedMatches = prepared
        && prepared.submissionId === submission?.submissionId
        && prepared.operationId === submission?.operationId
        && runtime.deploymentId === submission?.deploymentId
        && Number(prepared.noteId ?? prepared.public_inputs?.note_id)
            === Number(submission?.noteId)
        && prepared.mode === submission?.mode
        && String(prepared.destination || '').toLowerCase()
            === String(submission?.destination || '').toLowerCase()
        && (!replacementUnknown || (hasReplacementNonce
            && Number(prepared.submissionNonce) === replacementNonce));
    // Canonical status updates legitimately rewrite the record's top-level
    // destination/mode. The hashless claim belongs to the migrated prepared
    // plan, so exact-match that nested identity when it is available.
    const backgroundPrepared = current?.preparedWithdrawal;
    const backgroundClaimPlan = backgroundPrepared?.submissionId === current?.startSubmissionId
        ? backgroundPrepared
        : current;
    const backgroundMatches = current
        && current.startSubmissionId === submission?.submissionId
        && (current.startOperationId || current.preparedWithdrawal?.operationId)
            === submission?.operationId
        && current.deploymentId === submission?.deploymentId
        && Number(current.chainId) === Number(submission?.chainId)
        && String(current.contractAddress || '').toLowerCase()
            === String(submission?.contractAddress || '').toLowerCase()
        && Number(backgroundClaimPlan?.noteId
            ?? backgroundClaimPlan?.public_inputs?.note_id
            ?? current.noteId) === Number(submission?.noteId)
        && (!backgroundClaimPlan?.mode || backgroundClaimPlan.mode === submission?.mode)
        && String(backgroundClaimPlan?.destination || '').toLowerCase()
            === String(submission?.destination || '').toLowerCase()
        && (!replacementUnknown || (hasReplacementNonce
            && Number(backgroundClaimPlan?.submissionNonce
                ?? current.startSubmissionNonce) === replacementNonce));
    if (!selectedMatches && !backgroundMatches) {
        const alreadyReleasedInBackground = [
            ...(Array.isArray(current?.dismissedStartSubmissionClaims)
                ? current.dismissedStartSubmissionClaims
                : []),
            ...(Array.isArray(current?.ambiguousStartReplacements)
                ? current.ambiguousStartReplacements
                : [])
        ].some(claim => claim.submissionId === submission?.submissionId
            && claim.operationId === submission?.operationId);
        await transactionDone(transaction);
        return alreadyReleasedInBackground ? {
            location: 'background',
            runtime,
            withdrawal: current
        } : null;
    }
    const now = Date.now();
    let nextRuntime = runtime;
    if (selectedMatches) {
        const nextPrepared = { ...prepared };
        const hashes = Array.isArray(nextPrepared.transactionHashes)
            ? nextPrepared.transactionHashes
            : nextPrepared.transactionHash ? [nextPrepared.transactionHash] : [];
        nextPrepared.phase = replacementUnknown
            ? 'dropped_or_pending'
            : hashes.length ? 'submitted' : 'prepared';
        nextPrepared.submissionOutcome = replacementUnknown
            ? 'replacement_result_unknown'
            : 'rejected_before_broadcast';
        if (replacementUnknown) {
            const history = Array.isArray(nextPrepared.ambiguousReplacements)
                ? nextPrepared.ambiguousReplacements
                : [];
            nextPrepared.ambiguousReplacements = [...history, {
                submissionId: submission.submissionId,
                nonce: replacementNonce,
                startedAt: nextPrepared.submissionStartedAt,
                releasedAt: now,
                message: message || 'The wallet did not return a withdrawal replacement transaction ID.'
            }].slice(-8);
            nextPrepared.missingReceiptCheckedAt = now;
        }
        delete nextPrepared.submissionId;
        delete nextPrepared.submissionOwner;
        delete nextPrepared.submissionStartedAt;
        delete nextPrepared.submissionFrom;
        delete nextPrepared.submissionNonce;
        delete nextPrepared.submissionNonceJournalRequired;
        delete nextPrepared.submissionError;
        nextRuntime = normalizeRuntime({
            ...runtime,
            preparedWithdrawal: nextPrepared,
            updatedAt: now
        });
        runtimeStore.put(nextRuntime, RUNTIME_KEY);
    }
    let nextWithdrawal = current;
    if (backgroundMatches) {
        const dismissedHistory = Array.isArray(current.dismissedStartSubmissionClaims)
            ? current.dismissedStartSubmissionClaims
            : [];
        const ambiguousHistory = Array.isArray(current.ambiguousStartReplacements)
            ? current.ambiguousStartReplacements
            : [];
        const currentStartFrom = /^0x[0-9a-fA-F]{40}$/.test(
            current.startSubmissionFrom || ''
        ) ? current.startSubmissionFrom.toLowerCase() : null;
        const currentStartNonce = Number(current.startSubmissionNonce);
        const hasCurrentStartIdentity = currentStartFrom
            && Number.isSafeInteger(currentStartNonce)
            && currentStartNonce >= 0;
        // Taking over a live prompt with the same nonce does not close that
        // older MetaMask window. Likewise, a prior provider timeout may have
        // accepted a transaction without returning its hash. If this exact
        // replacement is then rejected, retain the nonce as an unresolved
        // recovery guard; otherwise a later Active sync could restore the note
        // while the older request is still capable of broadcasting.
        const hasPriorUnresolvedSameNonce = hasCurrentStartIdentity && (
            (current.supersededStartSubmissionClaims || []).some(claim =>
                claim.operationId === submission.operationId
                && String(claim.from || '').toLowerCase() === currentStartFrom
                && Number(claim.nonce) === currentStartNonce)
            || ambiguousHistory.some(claim =>
                claim.operationId === submission.operationId
                && Number(claim.nonce) === currentStartNonce)
        );
        const retainStartRetryIdentity = hasCurrentStartIdentity
            && (replacementUnknown || hasPriorUnresolvedSameNonce);
        const nextBackgroundPrepared = current.preparedWithdrawal
            ? { ...current.preparedWithdrawal }
            : null;
        if (nextBackgroundPrepared?.submissionId === submission.submissionId) {
            const hashes = Array.isArray(nextBackgroundPrepared.transactionHashes)
                ? nextBackgroundPrepared.transactionHashes
                : nextBackgroundPrepared.transactionHash
                    ? [nextBackgroundPrepared.transactionHash]
                    : [];
            nextBackgroundPrepared.phase = replacementUnknown
                ? 'dropped_or_pending'
                : hashes.length ? 'submitted' : 'prepared';
            nextBackgroundPrepared.submissionOutcome = replacementUnknown
                ? 'replacement_result_unknown'
                : 'rejected_before_broadcast';
            if (replacementUnknown) {
                const history = Array.isArray(nextBackgroundPrepared.ambiguousReplacements)
                    ? nextBackgroundPrepared.ambiguousReplacements
                    : [];
                nextBackgroundPrepared.ambiguousReplacements = [...history, {
                    submissionId: submission.submissionId,
                    nonce: replacementNonce,
                    startedAt: nextBackgroundPrepared.submissionStartedAt,
                    releasedAt: now,
                    message: message || 'The wallet did not return a withdrawal replacement transaction ID.'
                }].slice(-8);
                nextBackgroundPrepared.missingReceiptCheckedAt = now;
            }
            delete nextBackgroundPrepared.submissionId;
            delete nextBackgroundPrepared.submissionOwner;
            delete nextBackgroundPrepared.submissionStartedAt;
            delete nextBackgroundPrepared.submissionFrom;
            delete nextBackgroundPrepared.submissionNonce;
            delete nextBackgroundPrepared.submissionNonceJournalRequired;
            delete nextBackgroundPrepared.submissionError;
        }
        nextWithdrawal = {
            ...current,
            preparedWithdrawal: nextBackgroundPrepared,
            ...(retainStartRetryIdentity
                && current.preparedWithdrawal?.operationId === submission.operationId
                ? {
                    startRetryFrom: currentStartFrom,
                    startRetryNonce: currentStartNonce,
                    startRetryOperationId: submission.operationId,
                    startRetrySavedAt: now
                }
                : {}),
            ...(replacementUnknown ? {
                startSubmissionOutcome: 'replacement_result_unknown',
                ambiguousStartReplacements: [...ambiguousHistory, {
                    submissionId: submission.submissionId,
                    operationId: submission.operationId,
                    nonce: replacementNonce,
                    startedAt: current.startSubmissionStartedAt
                        ?? current.preparedWithdrawal?.submissionStartedAt,
                    releasedAt: now,
                    message: message || 'The wallet did not return a withdrawal replacement transaction ID.'
                }].slice(-8)
            } : {
                startSubmissionOutcome: 'rejected_before_broadcast',
                dismissedStartSubmissionClaims: [...dismissedHistory, {
                    submissionId: submission.submissionId,
                    operationId: submission.operationId,
                    dismissedAt: now,
                    reason: 'rejected_before_broadcast'
                }].slice(-8)
            }),
            revision: Number(current.revision || 0) + 1,
            updatedAt: now
        };
        delete nextWithdrawal.startSubmissionId;
        delete nextWithdrawal.startOperationId;
        delete nextWithdrawal.startSubmissionOwner;
        delete nextWithdrawal.startSubmissionStartedAt;
        delete nextWithdrawal.startSubmissionFrom;
        delete nextWithdrawal.startSubmissionNonce;
        if (!retainStartRetryIdentity) {
            delete nextWithdrawal.startRetryFrom;
            delete nextWithdrawal.startRetryNonce;
            delete nextWithdrawal.startRetryOperationId;
            delete nextWithdrawal.startRetrySavedAt;
        }
        withdrawalStore.put(nextWithdrawal);
    }
    await transactionDone(transaction);
    return {
        location: backgroundMatches ? (selectedMatches ? 'both' : 'background') : 'selected',
        runtime: nextRuntime,
        withdrawal: nextWithdrawal
    };
}

/** Park a withdrawal-only mutual-close note so a fresh note can be funded. */
export async function parkBrowserWithdrawal(record) {
    if (!record?.recordId || record.noteId == null) {
        throw new Error('A parked withdrawal requires a durable note identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (!current.state || Number(current.state.note_id) !== Number(record.noteId)
        || !current.preparedWithdrawal) {
        transaction.abort();
        throw new Error('The prepared withdrawal changed before it could be set aside.');
    }
    if (current.journal || current.lease || current.pendingDeposit) {
        transaction.abort();
        throw new Error('Finish the other private-balance operation before setting this balance aside.');
    }
    const prepared = current.preparedWithdrawal;
    const hashes = Array.isArray(prepared.transactionHashes)
        ? prepared.transactionHashes
        : prepared.transactionHash ? [prepared.transactionHash] : [];
    if (!['reserving', 'prepared'].includes(prepared.phase || 'prepared')
        || prepared.submissionId || hashes.length) {
        transaction.abort();
        throw new Error('Check the submitted withdrawal before setting this balance aside.');
    }
    const now = Date.now();
    const durableRecord = {
        ...record,
        deploymentId: record.deploymentId || current.deploymentId,
        state: current.state,
        preparedWithdrawal: current.preparedWithdrawal,
        clearanceReserved: current.preparedWithdrawal.clearanceReserved === true
            || current.preparedWithdrawal.mode === 'mutual',
        withdrawalNullifier: current.preparedWithdrawal.withdrawalNullifier
            || current.preparedWithdrawal.public_inputs?.withdrawal_nullifier
            || null,
        revision: 1,
        createdAt: Number(record.createdAt || now),
        updatedAt: now
    };
    transaction.objectStore(WITHDRAWAL_STORE).put(durableRecord);
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        pendingDeposit: current.pendingDeposit,
        lateWithdrawalAttempts: current.lateWithdrawalAttempts || [],
        lateDepositAttempts: current.lateDepositAttempts || [],
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord };
}

/**
 * Restore a challenged or parked note only when no newer selected note exists.
 * This prevents a background escape challenge from overwriting fresh funds.
 */
export async function restoreBrowserWithdrawal(recordId, identity = {}, expectedRevision = null) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE, ARCHIVE_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const withdrawalStore = transaction.objectStore(WITHDRAWAL_STORE);
    const archiveStore = transaction.objectStore(ARCHIVE_STORE);
    const [current, record, archives] = await Promise.all([
        requestResult(runtimeStore.get(RUNTIME_KEY)).then(normalizeRuntime),
        requestResult(withdrawalStore.get(recordId)),
        requestResult(archiveStore.getAll())
    ]);
    if (!record?.state) {
        transaction.abort();
        throw new Error('The recoverable private balance is no longer available.');
    }
    if (expectedRevision != null && Number(record.revision) !== Number(expectedRevision)) {
        transaction.abort();
        throw new Error('The withdrawal changed before this balance could be selected. Check its status again.');
    }
    const sameDeployment = record.deploymentId === identity.deploymentId
        && Number(record.chainId) === Number(identity.chainId)
        && String(record.contractAddress || '').toLowerCase()
            === String(identity.contractAddress || '').toLowerCase();
    if (!sameDeployment) {
        transaction.abort();
        throw new Error('This balance belongs to a different zkAPI deployment.');
    }
    if (current.deploymentId && current.deploymentId !== identity.deploymentId) {
        transaction.abort();
        throw new Error('The selected wallet belongs to a different zkAPI deployment.');
    }
    if (Number(record.state.note_id) !== Number(record.noteId)) {
        transaction.abort();
        throw new Error('The saved private balance does not match this withdrawal record.');
    }
    const withdrawalOnly = record.mode === 'mutual' || record.clearanceReserved === true;
    const unresolvedLateStart = (current.lateWithdrawalAttempts || []).some(attempt =>
        !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)
        && attempt.deploymentId === record.deploymentId
        && Number(attempt.chainId) === Number(record.chainId)
        && String(attempt.contractAddress || '').toLowerCase()
            === String(record.contractAddress || '').toLowerCase()
        && Number(attempt.noteId) === Number(record.noteId));
    if (record.startRecoveryPending === true || record.startSubmissionId
        || unresolvedLateStart) {
        transaction.abort();
        throw new Error('A submitted withdrawal for this balance is still being checked.');
    }
    const unresolvedFinalizationHashes = Array.isArray(record.finalizeTransactionHashes)
        ? record.finalizeTransactionHashes
        : record.finalizeTransactionHash ? [record.finalizeTransactionHash] : [];
    if (record.finalizeSubmissionId || unresolvedFinalizationHashes.length) {
        transaction.abort();
        throw new Error('Resolve the outstanding MetaMask finalization request before selecting this balance.');
    }
    const canRestore = record.phase === 'restored'
        || (record.phase === 'parked' && withdrawalOnly);
    if (!canRestore) {
        transaction.abort();
        throw new Error('This withdrawal is still active on-chain. Check its status before selecting it.');
    }
    if (current.state || current.pendingDeposit || current.journal || current.lease
        || current.preparedWithdrawal) {
        transaction.abort();
        throw new Error('Finish the current private balance before selecting this one.');
    }
    const preparedWithdrawal = withdrawalOnly
        ? {
            ...(record.preparedWithdrawal || {}),
            phase: 'prepared',
            mode: record.preparedWithdrawal?.mode || record.mode || 'escape',
            noteId: Number(record.noteId),
            destination: record.destination,
            withdrawalNullifier: record.withdrawalNullifier
                || record.preparedWithdrawal?.withdrawalNullifier
                || record.preparedWithdrawal?.public_inputs?.withdrawal_nullifier
                || null,
            clearanceReserved: true,
            createdAt: Number(record.createdAt || Date.now())
        }
        : null;
    if (preparedWithdrawal) {
        // A challenged escape uses a new active root. Never reuse the old
        // proof, but keep the irreversible server-clearance guard intact.
        delete preparedWithdrawal.proof;
        delete preparedWithdrawal.public_inputs;
        delete preparedWithdrawal.transactionHash;
        delete preparedWithdrawal.transactionHashes;
        delete preparedWithdrawal.submissionId;
        delete preparedWithdrawal.submissionOwner;
        delete preparedWithdrawal.submissionStartedAt;
    }
    // Only a finalized EscapeWithdrawalChallenged log for this exact note and
    // nullifier (verified by the reconciler) becomes challenge evidence. A
    // reorged-out start or a canceled replacement carries none.
    const requestArchive = requestArchiveMap(archives);
    let evidenceChanges = new Set();
    const challenge = record.challengeEvidence;
    if (record.mode === 'escape' && challenge && record.state.current_anchor != null
        && Number(challenge.noteId) === Number(record.noteId)
        && challenge.nullifier != null && record.withdrawalNullifier != null
        && sameFeltValue(challenge.nullifier, record.withdrawalNullifier)) {
        try {
            evidenceChanges = mergeRequestArchiveUpdates(requestArchive, [buildRequestEvidenceRecord({
                deploymentId: record.deploymentId,
                noteId: record.noteId,
                anchor: record.state.current_anchor,
                nullifier: challenge.nullifier,
                source: 'escape_challenged',
                evidence: challenge
            })], Date.now(), { enforceCapacity: false });
        } catch (error) {
            transaction.abort();
            throw error;
        }
    }
    const next = normalizeRuntime({
        deploymentId: record.deploymentId,
        state: record.state,
        preparedWithdrawal,
        lateWithdrawalAttempts: current.lateWithdrawalAttempts || [],
        lateDepositAttempts: current.lateDepositAttempts || [],
        updatedAt: Date.now()
    });
    runtimeStore.put(next, RUNTIME_KEY);
    withdrawalStore.delete(recordId);
    writeRequestArchiveChanges(archiveStore, requestArchive, evidenceChanges);
    await transactionDone(transaction);
    return next;
}

export async function updateBrowserWithdrawal(recordId, changes = {}, {
    sanitize = false,
    expectedRevision = null,
    expectedPhase = null,
    expectedFinalizeTransactionHash = undefined
} = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database,
        sanitize ? [WITHDRAWAL_STORE, DEPOSIT_STORE, ARCHIVE_STORE] : [WITHDRAWAL_STORE, DEPOSIT_STORE]);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current) {
        transaction.abort();
        throw new Error('The durable withdrawal record was not found.');
    }
    if (expectedRevision != null && Number(current.revision) !== Number(expectedRevision)) {
        transaction.abort();
        throw new Error('The withdrawal changed while its status was being checked.');
    }
    const allowedPhases = Array.isArray(expectedPhase) ? expectedPhase : [expectedPhase];
    if (expectedPhase != null && !allowedPhases.includes(current.phase)) {
        transaction.abort();
        throw new Error('The withdrawal moved to a different phase while it was being checked.');
    }
    if (expectedFinalizeTransactionHash !== undefined
        && (current.finalizeTransactionHash || null) !== (expectedFinalizeTransactionHash || null)) {
        transaction.abort();
        throw new Error('The finalization transaction changed while its receipt was being checked.');
    }
    if (current.phase === 'closed' && changes.phase && changes.phase !== 'closed') {
        transaction.abort();
        throw new Error('A completed withdrawal cannot return to an earlier phase.');
    }
    const next = {
        ...current,
        ...changes,
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    if (sanitize) {
        // Preserve the original deposit before finality removes the last copy
        // of a legacy note's private recovery state.
        const depositStore = transaction.objectStore(DEPOSIT_STORE);
        const archiveStore = transaction.objectStore(ARCHIVE_STORE);
        const [deposits, archives] = await Promise.all([
            requestResult(depositStore.getAll()),
            requestResult(archiveStore.getAll())
        ]);
        if (next.phase === 'closed') {
            // A finalized close retires every transmitted request of this note.
            const requestArchive = requestArchiveMap(archives);
            writeRequestArchiveChanges(archiveStore, requestArchive, supersedeNoteRequestArchive(
                requestArchive, current.deploymentId, current.noteId ?? current.state?.note_id, Date.now()));
        }
        mergeDepositRecord(depositRecordMap(deposits),
            depositRecord(current.state, current.deploymentId), depositStore);
        if (next.phase === 'closed') {
            // Terminal chain finality releases the UI's live wallet claims.
            // Keep their minimal identities for callbacks from old wallet tabs,
            // without retaining any proof, clearance, or private note material.
            const prepared = next.preparedWithdrawal || {};
            const claims = [
                { submissionId: next.startSubmissionId, operationId: next.startOperationId,
                    from: next.startSubmissionFrom, nonce: next.startSubmissionNonce },
                { submissionId: prepared.submissionId, operationId: prepared.operationId,
                    from: prepared.submissionFrom, nonce: prepared.submissionNonce },
                ...(next.resolvedStartClaims || []), ...(next.dismissedStartSubmissionClaims || []),
                ...(next.supersededStartSubmissionClaims || []), ...(next.ambiguousStartReplacements || [])
            ].filter(claim => claim.submissionId && claim.operationId).map(claim => ({
                submissionId: claim.submissionId, operationId: claim.operationId,
                from: claim.from, nonce: claim.nonce
            }));
            next.resolvedStartTransactionHistory = [...(next.resolvedStartTransactionHistory || []), {
                resolution: 'closed_finalized', finalizedBlock: next.finalizedBlockNumber || null,
                transactionHashes: [...new Set([...(next.transactionHashes || []),
                    ...(next.transactionHash ? [next.transactionHash] : [])])],
                transactionAttempts: next.transactionAttempts || [],
                preparedTransactionAttempts: prepared.transactionAttempts || [],
                resolvedClaims: claims
            }];
            next.startRecoveryPending = false;
            for (const key of ['startSubmissionId', 'startOperationId', 'startSubmissionOwner',
                'startSubmissionStartedAt', 'startSubmissionFrom', 'startSubmissionNonce', 'startSubmissionError',
                'startSubmissionOutcome', 'startRetryFrom', 'startRetryNonce', 'startRetryOperationId',
                'startRetrySavedAt', 'startMissingTransactionHashes', 'startReplacementTransactionHashes',
                'supersededStartSubmissionClaims', 'ambiguousStartReplacements', 'resolvedStartClaims']) delete next[key];
        }
        delete next.state;
        delete next.preparedWithdrawal;
        delete next.proof;
        delete next.withdrawalNullifier;
        delete next.finalizeTransactionHash;
        delete next.finalizeTransactionHashes;
        delete next.finalizeAttempts;
        delete next.finalizeSubmissionId;
        delete next.finalizeSubmissionOwner;
        delete next.finalizeSubmissionStartedAt;
        delete next.finalizeSubmissionFrom;
        delete next.finalizeSubmissionNonce;
        delete next.finalizeSubmissionError;
    }
    store.put(next);
    await transactionDone(transaction);
    return next;
}

const FINALIZATION_TERMINAL_PHASES = new Set(['closed', 'restored', 'parked']);

function finalizationReference(value) {
    if (!value || typeof value !== 'object') return null;
    return {
        recordId: value.recordId || null,
        submissionId: value.submissionId || null,
        operationId: value.operationId || null,
        generation: Number(value.generation || 0),
        deploymentId: value.deploymentId || null,
        chainId: Number(value.chainId),
        contractAddress: value.contractAddress || null,
        noteId: Number(value.noteId),
        destination: value.destination || null
    };
}

function finalizationIdentity(record) {
    return {
        recordId: record.recordId,
        deploymentId: record.deploymentId,
        chainId: Number(record.chainId),
        contractAddress: record.contractAddress,
        noteId: Number(record.noteId),
        destination: record.destination
    };
}

function matchesFinalizationClaim(record, reference) {
    return Boolean(reference?.submissionId
        && reference?.operationId
        && reference.recordId === record.recordId
        && reference.submissionId === record.finalizeSubmissionId
        && reference.operationId === record.finalizeOperationId
        && Number(reference.generation) === Number(record.finalizeGeneration || 0)
        && reference.deploymentId === record.deploymentId
        && Number(reference.chainId) === Number(record.chainId)
        && String(reference.contractAddress || '').toLowerCase()
            === String(record.contractAddress || '').toLowerCase()
        && Number(reference.noteId) === Number(record.noteId)
        && String(reference.destination || '').toLowerCase()
            === String(record.destination || '').toLowerCase());
}

export async function claimBrowserWithdrawalFinalization(recordId, ownerId) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current || !['pending', 'finalizing', 'awaiting_wallet', 'ambiguous'].includes(current.phase)) {
        transaction.abort();
        throw new Error('There is no pending escape withdrawal to finalize.');
    }
    if (current.chainStatus === 'active') {
        transaction.abort();
        throw new Error('This escape was challenged and is no longer available to finalize.');
    }
    const hashes = Array.isArray(current.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    if (hashes.length) {
        await transactionDone(transaction);
        return {
            status: 'submitted',
            transactionHash: hashes[0],
            submissionId: current.finalizeSubmissionId || null,
            operationId: current.finalizeOperationId || null,
            generation: Number(current.finalizeGeneration || 0),
            ...finalizationIdentity(current),
            record: current
        };
    }
    if (current.phase === 'ambiguous') {
        transaction.abort();
        throw new Error('The previous MetaMask request has an unknown result. Check its status, then explicitly retry if the escape is still pending.');
    }
    if (current.finalizeSubmissionId) {
        transaction.abort();
        throw new Error('This escape is already awaiting MetaMask in this or another tab.');
    }
    const now = Date.now();
    const submissionId = crypto.randomUUID();
    const operationId = current.finalizeOperationId || crypto.randomUUID();
    const generation = Number(current.finalizeGeneration || 0) + 1;
    const next = {
        ...current,
        phase: 'awaiting_wallet',
        finalizeOperationId: operationId,
        finalizeGeneration: generation,
        finalizeSubmissionId: submissionId,
        finalizeSubmissionOwner: ownerId,
        finalizeSubmissionStartedAt: now,
        revision: Number(current.revision || 0) + 1,
        updatedAt: now
    };
    store.put(next);
    await transactionDone(transaction);
    return {
        status: 'claimed',
        transactionHash: null,
        ...finalizationIdentity(next),
        submissionId,
        operationId,
        generation,
        record: next
    };
}

export async function claimBrowserWithdrawalFinalizationReplacement(
    recordId,
    ownerId,
    expectedFrom
) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current || current.phase !== 'finalizing'
        || current.chainStatus === 'active' || current.chainStatus === 'closed') {
        transaction.abort();
        throw new Error('Check the pending escape before replacing its finalization.');
    }
    if (current.finalizeSubmissionId) {
        transaction.abort();
        throw new Error('A finalization replacement request is already open in MetaMask.');
    }
    const hashes = Array.isArray(current.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
    const identities = [...new Map((current.finalizeAttempts || [])
        .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
            && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
            && Number.isSafeInteger(Number(attempt.nonce))
            && Number(attempt.nonce) >= 0)
        .map(attempt => {
            const identity = {
                from: attempt.from.toLowerCase(),
                nonce: Number(attempt.nonce)
            };
            return [`${identity.from}:${identity.nonce}`, identity];
        })).values()];
    const replacementEligible = ['receipt_missing', 'replacement_result_unknown']
        .includes(current.finalizeSubmissionOutcome);
    if (!replacementEligible || identities.length !== 1) {
        transaction.abort();
        throw new Error(identities.length > 1
            ? 'The saved finalization has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
            : 'The saved finalization has no replacement nonce. Check its transaction status first.');
    }
    const [{ from, nonce }] = identities;
    if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
        || from !== expectedFrom.toLowerCase()) {
        transaction.abort();
        throw new Error(`Connect the MetaMask account ${from} that submitted this finalization.`);
    }
    const now = Date.now();
    const submissionId = crypto.randomUUID();
    const operationId = current.finalizeOperationId || crypto.randomUUID();
    const generation = Number(current.finalizeGeneration || 0) + 1;
    const next = {
        ...current,
        finalizeOperationId: operationId,
        finalizeGeneration: generation,
        finalizeSubmissionId: submissionId,
        finalizeSubmissionOwner: ownerId,
        finalizeSubmissionStartedAt: now,
        finalizeSubmissionFrom: from,
        finalizeSubmissionNonce: nonce,
        finalizeSubmissionOutcome: 'replacement_awaiting_wallet',
        finalizeReplacementOf: [...hashSet],
        revision: Number(current.revision || 0) + 1,
        updatedAt: now
    };
    store.put(next);
    await transactionDone(transaction);
    return {
        status: 'claimed',
        ...finalizationIdentity(next),
        submissionId,
        operationId,
        generation,
        replacementFrom: from,
        replacementNonce: nonce,
        record: next
    };
}

export async function rememberBrowserWithdrawalFinalizationSubmissionMetadata(
    recordId,
    submission,
    transactionMetadata
) {
    const from = transactionMetadata?.from;
    const nonce = Number(transactionMetadata?.nonce);
    if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
        || !Number.isSafeInteger(nonce) || nonce < 0) {
        throw new Error('The finalization transaction metadata is invalid.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const reference = finalizationReference(submission);
    if (!current || !matchesFinalizationClaim(current, reference)) {
        transaction.abort();
        throw new Error('The finalization wallet claim changed before its nonce was saved.');
    }
    const next = {
        ...current,
        finalizeSubmissionFrom: from.toLowerCase(),
        finalizeSubmissionNonce: nonce,
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function rememberBrowserWithdrawalFinalization(
    recordId,
    transactionHash,
    submission = null,
    transactionMetadata = null
) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
        throw new Error('MetaMask returned an invalid finalization transaction hash.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current) {
        transaction.abort();
        throw new Error('The pending escape record is no longer available.');
    }
    const reference = finalizationReference(submission);
    if (!reference?.submissionId || !reference.operationId || reference.recordId !== recordId) {
        transaction.abort();
        throw new Error('The finalization transaction is missing its durable operation identity.');
    }
    const hashes = [...new Set([
        ...(Array.isArray(current.finalizeTransactionHashes)
            ? current.finalizeTransactionHashes
            : current.finalizeTransactionHash ? [current.finalizeTransactionHash] : []),
        transactionHash
    ].map(value => value.toLowerCase()))];
    const normalizedHash = transactionHash.toLowerCase();
    const attempts = [
        ...(Array.isArray(current.finalizeAttempts)
            ? current.finalizeAttempts.filter(attempt => attempt.hash !== normalizedHash)
            : []),
        {
            hash: normalizedHash,
            submissionId: reference.submissionId,
            operationId: reference.operationId,
            generation: reference.generation,
            from: /^0x[0-9a-fA-F]{40}$/.test(
                transactionMetadata?.from || current.finalizeSubmissionFrom || ''
            )
                ? (transactionMetadata?.from || current.finalizeSubmissionFrom).toLowerCase()
                : null,
            nonce: Number.isSafeInteger(Number(
                transactionMetadata?.nonce ?? current.finalizeSubmissionNonce
            ))
                ? Number(transactionMetadata?.nonce ?? current.finalizeSubmissionNonce)
                : null,
            observedAt: Date.now()
        }
    ];
    const terminal = FINALIZATION_TERMINAL_PHASES.has(current.phase);
    const claimMatches = matchesFinalizationClaim(current, reference);
    const next = {
        ...current,
        phase: terminal ? current.phase : 'finalizing',
        finalizeTransactionHash: hashes[0],
        finalizeTransactionHashes: hashes,
        finalizeAttempts: attempts,
        ...(!claimMatches && (
            current.finalizeSubmissionId
            || reference.operationId !== current.finalizeOperationId
            || Number(reference.generation) !== Number(current.finalizeGeneration || 0)
        )
            ? { concurrentFinalizationObserved: true }
            : {}),
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    if (claimMatches) {
        delete next.finalizeSubmissionId;
        delete next.finalizeSubmissionOwner;
        delete next.finalizeSubmissionStartedAt;
        delete next.finalizeSubmissionFrom;
        delete next.finalizeSubmissionNonce;
    }
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function releaseBrowserWithdrawalFinalization(recordId, {
    submission = null,
    transactionHash = null,
} = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current) {
        await transactionDone(transaction);
        return current || null;
    }
    const reference = finalizationReference(submission);
    const hashes = Array.isArray(current.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    if (transactionHash
        && !hashes.some(hash => hash.toLowerCase() === transactionHash.toLowerCase())) {
        transaction.abort();
        throw new Error('The finalization transaction changed while its receipt was being checked.');
    }
    if (!transactionHash && !matchesFinalizationClaim(current, reference)) {
        transaction.abort();
        throw new Error('The finalization request changed while MetaMask was open.');
    }
    const remaining = transactionHash
        ? hashes.filter(hash => hash.toLowerCase() !== transactionHash.toLowerCase())
        : hashes;
    const remainingAttempts = Array.isArray(current.finalizeAttempts)
        ? current.finalizeAttempts.filter(attempt => !transactionHash
            || attempt.hash.toLowerCase() !== transactionHash.toLowerCase())
        : [];
    const releasesClaim = !transactionHash && matchesFinalizationClaim(current, reference);
    const terminal = FINALIZATION_TERMINAL_PHASES.has(current.phase);
    const hasClaimAfter = Boolean(current.finalizeSubmissionId) && !releasesClaim;
    const next = {
        ...current,
        phase: terminal
            ? current.phase
            : remaining.length
                ? 'finalizing'
                : hasClaimAfter
                    ? (current.phase === 'ambiguous' ? 'ambiguous' : 'awaiting_wallet')
                    : 'pending',
        finalizeTransactionHashes: remaining,
        finalizeAttempts: remainingAttempts,
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    if (remaining.length) {
        next.finalizeTransactionHash = remaining[0];
    } else {
        delete next.finalizeTransactionHash;
        delete next.finalizeTransactionHashes;
    }
    if (releasesClaim) {
        delete next.finalizeSubmissionId;
        delete next.finalizeSubmissionOwner;
        delete next.finalizeSubmissionStartedAt;
        delete next.finalizeSubmissionFrom;
        delete next.finalizeSubmissionNonce;
    }
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function markBrowserWithdrawalFinalizationMissingReceipts(
    recordId,
    expectedTransactionHashes
) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current || FINALIZATION_TERMINAL_PHASES.has(current.phase)) {
        await transactionDone(transaction);
        return current || null;
    }
    const normalize = values => [...values]
        .map(value => String(value).toLowerCase())
        .sort();
    const hashes = Array.isArray(current.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    if (JSON.stringify(normalize(hashes))
        !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
        transaction.abort();
        throw new Error('The finalization transactions changed while their receipts were checked.');
    }
    if (current.finalizeSubmissionId || current.chainStatus === 'active'
        || current.chainStatus === 'closed') {
        await transactionDone(transaction);
        return current;
    }
    if (current.finalizeSubmissionOutcome === 'receipt_missing') {
        await transactionDone(transaction);
        return current;
    }
    const next = {
        ...current,
        phase: 'finalizing',
        finalizeSubmissionOutcome: 'receipt_missing',
        finalizeMissingReceiptCheckedAt: Date.now(),
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function releaseBrowserWithdrawalFinalizationReplacementClaim(
    recordId,
    submission,
    message = null
) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const reference = finalizationReference(submission);
    if (!current || !matchesFinalizationClaim(current, reference)
        || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
        transaction.abort();
        throw new Error('The finalization replacement request changed before it could be released.');
    }
    const history = Array.isArray(current.ambiguousFinalizationReplacements)
        ? current.ambiguousFinalizationReplacements
        : [];
    const now = Date.now();
    const next = {
        ...current,
        phase: FINALIZATION_TERMINAL_PHASES.has(current.phase) ? current.phase : 'finalizing',
        finalizeSubmissionOutcome: 'replacement_result_unknown',
        ambiguousFinalizationReplacements: [...history, {
            ...reference,
            nonce: Number(submission.replacementNonce),
            startedAt: current.finalizeSubmissionStartedAt,
            releasedAt: now,
            message: message || 'The wallet did not return a finalization replacement transaction ID.'
        }].slice(-8),
        finalizeMissingReceiptCheckedAt: now,
        revision: Number(current.revision || 0) + 1,
        updatedAt: now
    };
    delete next.finalizeSubmissionId;
    delete next.finalizeSubmissionOwner;
    delete next.finalizeSubmissionStartedAt;
    delete next.finalizeSubmissionFrom;
    delete next.finalizeSubmissionNonce;
    delete next.finalizeSubmissionError;
    store.put(next);
    await transactionDone(transaction);
    return next;
}

/**
 * Release a hashless finalization prompt only after a sufficiently-new chain
 * read proved that the escape was challenged. This is an explicit user
 * acknowledgement that MetaMask is closed, not a timeout-based takeover.
 */
export async function resolveBrowserChallengedFinalization(recordId, submission, {
    expectedRevision = null,
    observedBlock = null
} = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const reference = finalizationReference(submission);
    const hashes = Array.isArray(current?.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current?.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    const chainFloor = Math.max(
        Number(current?.startBlockNumber || 0),
        Number(current?.lastObservedBlock || 0)
    );
    if (!current || expectedRevision == null
        || Number(current.revision) !== Number(expectedRevision)
        || observedBlock == null || Number(observedBlock) < chainFloor
        || current.chainStatus !== 'active' || hashes.length
        || !matchesFinalizationClaim(current, reference)) {
        transaction.abort();
        throw new Error('This challenged finalization changed. Check its on-chain status again.');
    }
    const history = Array.isArray(current.dismissedFinalizationClaims)
        ? current.dismissedFinalizationClaims
        : [];
    const withdrawalOnly = current.clearanceReserved === true
        || current.preparedWithdrawal?.clearanceReserved === true;
    const next = {
        ...current,
        phase: withdrawalOnly ? 'parked' : 'restored',
        dismissedFinalizationClaims: [...history, {
            ...reference,
            dismissedAt: Date.now(),
            reason: 'challenged_prompt_closed'
        }],
        finalizeSubmissionOutcome: 'challenged_prompt_closed',
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    delete next.finalizeSubmissionId;
    delete next.finalizeSubmissionOwner;
    delete next.finalizeSubmissionStartedAt;
    delete next.finalizeSubmissionFrom;
    delete next.finalizeSubmissionNonce;
    delete next.finalizeSubmissionError;
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function markBrowserWithdrawalFinalizationAmbiguous(recordId, submission, message = null) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const reference = finalizationReference(submission);
    if (!current || FINALIZATION_TERMINAL_PHASES.has(current.phase)
        || !matchesFinalizationClaim(current, reference)) {
        transaction.abort();
        throw new Error('The finalization changed before its unknown result could be saved.');
    }
    const next = {
        ...current,
        phase: 'ambiguous',
        finalizeSubmissionOutcome: 'ambiguous',
        finalizeSubmissionError: message || 'MetaMask did not return a transaction ID.',
        finalizeAmbiguousAt: Date.now(),
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function authorizeBrowserWithdrawalFinalizationRetry(recordId) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, WITHDRAWAL_STORE);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    const hashes = Array.isArray(current?.finalizeTransactionHashes)
        ? current.finalizeTransactionHashes
        : current?.finalizeTransactionHash ? [current.finalizeTransactionHash] : [];
    if (!current || current.phase !== 'ambiguous' || !current.finalizeSubmissionId
        || hashes.length) {
        transaction.abort();
        throw new Error('There is no unknown finalization request to retry.');
    }
    const history = Array.isArray(current.ambiguousFinalizationSubmissions)
        ? current.ambiguousFinalizationSubmissions
        : [];
    const next = {
        ...current,
        phase: 'pending',
        finalizeSubmissionOutcome: 'retry_authorized',
        ambiguousFinalizationSubmissions: [...history, {
            submissionId: current.finalizeSubmissionId,
            operationId: current.finalizeOperationId,
            generation: Number(current.finalizeGeneration || 0),
            startedAt: current.finalizeSubmissionStartedAt,
            authorizedAt: Date.now()
        }].slice(-8),
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    delete next.finalizeSubmissionId;
    delete next.finalizeSubmissionOwner;
    delete next.finalizeSubmissionStartedAt;
    delete next.finalizeSubmissionFrom;
    delete next.finalizeSubmissionNonce;
    delete next.finalizeSubmissionError;
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function requestPersistentStorage() {
    if (!navigator.storage?.persist) return false;
    try {
        if (await navigator.storage.persisted?.()) return true;
        return await navigator.storage.persist();
    } catch {
        return false;
    }
}

/** Serialize all wallet mutations across tabs. */
export async function withBrowserWalletLock(deploymentId, operation) {
    // The selected runtime uses one same-origin IndexedDB key. All deployment
    // manifests therefore share one mutation lock; deployment-scoped locks
    // could otherwise overwrite each other from separate tabs.
    const lockName = 'zkapi-wallet:active-runtime';
    if (navigator.locks?.request) {
        return navigator.locks.request(lockName, { mode: 'exclusive' }, operation);
    }
    const previous = fallbackLock;
    let release;
    fallbackLock = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
        return await operation();
    } finally {
        release();
    }
}

export function createWalletChannel(deploymentId, onChange) {
    if (typeof BroadcastChannel === 'undefined') return { postMessage() {}, close() {} };
    const channel = new BroadcastChannel('zkapi-wallet:active-runtime');
    channel.addEventListener('message', (event) => onChange?.(event.data));
    return channel;
}
