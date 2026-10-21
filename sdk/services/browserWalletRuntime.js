import { browserSdkOptions, beginBrowserSdkInitialization, browserSdkTransport } from '../configure.js';
import { assertNativeVault, exitRpcUrl, pinnedRpcRequest, urlRpcRequest, validateNativeFunding, validateNativeQuote, validateProofBoundQuote, readNativeQuote, readVaultWord, nativeUnitsForUsd, nativeUsdMicros, sameNativeQuote, requestBillingQuote } from './zkapiNativeEth.mjs';
import { CHAT_SPENDING_TIER_USD } from './zkapiRequestCompat.mjs';
import { TestnetPasswordAuth, testnetPasswordRequired } from './testnetPasswordAuth.mjs';
import { sameFelt, waitForExpectedActiveRoot } from './zkapiWithdrawalRoot.mjs';
import { isUnsubmittedParkedMutualWithdrawal } from './zkapiWithdrawalRecovery.mjs';
import {
    INVALID_SUCCESSOR_DISPOSITION,
    LATE_SUCCESSOR_DISPOSITION,
    REQUEST_EVIDENCE_TYPE,
    REQUEST_JOURNAL_TYPE,
    anchorArchiveCapacity,
    buildRequestJournalRecord,
    feltKey,
    journalClientRequestId,
    lastDefinitiveObservation,
    lastObservation,
    requestObservation,
    unresolvedRequestArchiveAt
} from './zkapiRequestArchive.mjs';
import {
    EXIT_TIMING, RECORD_CLASS, WITHDRAWAL_KIND, afterClearanceFailure, decideExit, escapeAt, escapeCostUnits, exitCostWarning,
    exitLockDeadAfter, exitLockRefusal,
    exitLockReleasable, exitRecordClass, lowExpiry, mustInitiateBy, nearExpiry, newExitLock, ownershipOutcome,
    ownershipProofAction,
    recordClearanceOutcome, recordReleasedProof, releasedExitProofs, requestRecordsAtState, stateExitStatus, switchExitLock
} from './zkapiExitPolicy.mjs';
import { rebuildNotePath } from './zkapiTreeRebuild.mjs';
import { buildExitKitPayload, sealExitKit } from './zkapiExitKit.mjs';
import { canaryLimits, canaryRefusal, deploymentMismatchError, verifyDeployment } from './zkapiDeploymentCheck.mjs';
import { GASLESS_TIMING, bundlerClient, bundlerUrl as validBundlerUrl, gaslessError, gaslessPins } from './zkapiGasless.mjs';
import {
    archiveBrowserWallet,
    assertBrowserBackgroundWithdrawalAvailable,
    browserRuntimeHoldsState,
    authorizeBrowserWithdrawalFinalizationRetry,
    claimBrowserWithdrawalStartReplacement,
    claimBrowserBackgroundWithdrawalSubmission,
    claimBrowserWithdrawalFinalization,
    claimBrowserWithdrawalFinalizationReplacement,
    FINALIZATION_CLAIM_LIVE_MESSAGE,
    commitBrowserWallet,
    createWalletChannel,
    detachBrowserClosedWithdrawal,
    detachBrowserEscapeWithdrawal,
    gaslessRecordFields,
    isGaslessWithdrawal,
    listBrowserWithdrawals,
    isBrowserBackgroundWithdrawalPreparationCancelable,
    markBrowserWithdrawalFinalizationAmbiguous,
    markBrowserBackgroundWithdrawalAmbiguous,
    markBrowserWithdrawalFinalizationMissingReceipts,
    PARK_REQUIRES_CLEARANCE_MESSAGE,
    parkBrowserWithdrawal,
    preparedWithdrawalParkable,
    projectBrowserDeposits,
    putBrowserRequestArchive,
    readBrowserWalletSnapshot,
    recordBrowserExpiryClaims,
    releaseBrowserWithdrawalFinalization,
    releaseBrowserWithdrawalFinalizationReplacementClaim,
    releaseBrowserWithdrawalStartSubmission,
    releaseBrowserBackgroundWithdrawalSubmission,
    rememberBrowserBackgroundWithdrawalMetadata,
    rememberBrowserBackgroundWithdrawalTransaction,
    rememberBrowserWithdrawalFinalization,
    rememberBrowserWithdrawalFinalizationSubmissionMetadata,
    requestPersistentStorage,
    repairBrowserUnsubmittedBackgroundWithdrawal,
    resolveBrowserBackgroundWithdrawalForRetry,
    resolveBrowserChallengedFinalization,
    restoreBrowserWithdrawal,
    saveBrowserBackgroundWithdrawalPlan,
    transferBrowserLateWithdrawalAttempt,
    updateBrowserWithdrawal,
    withBrowserWalletLock,
    writeBrowserWallet
} from './browserWalletStore.js';

// The build-pinned settlement window W when a profile predates it (mainnet's).
const DEFAULT_SETTLEMENT_WINDOW_SECONDS = 21_905;
const EXIT_RPC_STORAGE_KEY = 'zkapi-exit-rpc-url';
// The user's ERC-4337 bundler for sponsored withdrawals, per origin like the exit RPC.
const BUNDLER_URL_STORAGE_KEY = 'zkapi-bundler-url';
const RECEIPT_UNRECOVERABLE_MESSAGE = 'The server reports a finalized private request for this balance that this browser cannot apply: its request journal is gone. Only withdrawing remains, conceding at most the request’s bound.';
const DEVICE_NOT_NEWEST_MESSAGE = 'Another device spent this balance’s next state, so this device is not the newest. Restore the newest backup or exit kit before withdrawing.';
const EXIT_LOCKED_MESSAGE = 'A withdrawal of this balance is in progress, so no new private chat can start from it. Finish the withdrawal, or cancel it; a released exit proof keeps the balance frozen until it expires.';
const EXIT_RELEASE_PENDING_MESSAGE = 'An earlier exit proof of this balance has expired, and a newer balance state is waiting until the vault confirms that the proof can no longer land. The vault’s record of this balance could not be confirmed yet. Try again shortly, or set your own exit RPC. Close to the balance’s exit deadline the exit goes ahead from the earlier state, conceding at most its last chat’s budget.';
const NOTE_NEAR_EXPIRY_MESSAGE = 'This balance is too close to its expiry for a new private chat: a chat now could still be settling when the balance must be withdrawn. Withdraw it instead.';
const INVALID_SUCCESSOR_MESSAGE = 'The server settled a private request for this balance with a successor that fails this wallet’s checks. It is treated as withheld: the balance can only be withdrawn, conceding at most that request’s bound.';
const DEPOSITS_CLOSED_MESSAGE = 'This deployment no longer accepts new deposits. Existing balances and deposits already started can still be completed, recovered and withdrawn.';
const REQUEST_ARCHIVE_LIMIT_MESSAGE = 'Too many unsettled private requests are recorded for this balance state, so no new chat can start from it. Chats resume only if the server settles one of them; otherwise withdraw this balance.';
const EXIT_ONLY_MESSAGE = 'Withdrawals work, but new deposits and private chats wait until the operator’s deployment manifest is served and matches this build again.';
// Every operator call outside exit mode (lease issuance and retirement,
// recovery, quotes, the indexer, the manifest) ends by this time, so no hung
// call holds the wallet lock, and an exit queued behind it, indefinitely.
// It is above the server's own bounds (30 s issuance lock, 45 s retirement).
// Exit-mode calls use E0's CALL_TIMEOUT instead.
const OPERATOR_CALL_TIMEOUT_MS = 90_000;
const STALE_ROOT_RETRY_DELAYS_MS = Object.freeze([2_000, 4_000, 8_000, 16_000]);
const SETTLEMENT_RETRY_MIN_MS = 2_000;
const SETTLEMENT_RETRY_MAX_MS = 60_000;
const VAULT_SELECTORS = Object.freeze({
    currentRoot: '0xfdab463d',
    challengePeriod: '0xf3f480d9',
    effectiveExpiry: '0x7cb4a03c',
    challengedNullifiers: '0x6cda756a'
});
const WITHDRAWAL_RESTART = Symbol('withdrawal-restart');
// E4.1's path sources in order: the deposit-time path (Amendment A1), the
// operator's indexer checked against the vault, the vault's own logs (§6.6).
const EXIT_PATH_SOURCES = Object.freeze(['deposit', 'indexer', 'rebuild']);
// After the vault refused a proof's root: any source but the saved one, and
// never the refused root itself.
const AFTER_UNKNOWN_ROOT_SOURCES = Object.freeze(['indexer', 'rebuild']);
const REQUEST_PUBLIC_INPUT_FIELDS = Object.freeze([
    'request_nullifier', 'authorization_tag', 'anonymous_commitment_x', 'anonymous_commitment_y',
    'solvency_bound', 'request_time'
]);

/** A saved observation of a nullifier reading, marking and naming the receipt it carried. */
function readingObservation(observed, context) {
    return requestObservation(observed.status, context, Date.now(), {
        clientRequestId: observed.response?.client_request_id
            ? String(observed.response.client_request_id) : null,
        receipt: Boolean(observed.response)
    });
}

/**
 * A GET /v2/nullifiers answer as a reading: only 'unknown', 'reserved',
 * 'finalized' (with its response), 'clearance_reserved', 'exit_deferred' and
 * 'exited_unsigned' are readings; anything else is 'unavailable'. A reported
 * settlement deadline (seconds) is kept for E3.
 */
function nullifierReading(recovery) {
    const deadline = Number(recovery?.settlement_deadline);
    const settlementDeadline = Number.isSafeInteger(deadline) && deadline > 0 ? deadline : null;
    if (recovery?.status === 'not_found' && recovery.nullifier_status === 'unknown' && !recovery.request_response) {
        return { status: 'unknown', response: null, settlementDeadline };
    }
    if (recovery?.status === 'ok'
        && ['reserved', 'finalized', 'clearance_reserved', 'exit_deferred', 'exited_unsigned'].includes(recovery.nullifier_status)) {
        return {
            status: recovery.nullifier_status,
            response: recovery.nullifier_status === 'finalized' ? recovery.request_response || null : null,
            settlementDeadline
        };
    }
    return { status: 'unavailable', response: null, settlementDeadline: null };
}

function browserConfigUrl() {
    const configured = browserSdkOptions().configUrl;
    if (!configured) throw new Error('Configure a trusted configUrl before initializing the zkAPI browser SDK.');
    return configured;
}
const REQUIRED_CIRCUIT_ID = 'zkapi-v2-concession-v1';
// Setups a bundle can be built for; the build-pinned profile names one, and
// the proof worker must run a bundle of exactly that setup.
const BUNDLE_SETUP_IDS = Object.freeze(['dev', 'mpc-1']);
// A saved withdrawal proof is reused only while this much of its validity
// remains, so a reused proof can still be signed and included in time (E4.7).
const WITHDRAWAL_PROOF_REUSE_MARGIN_SECONDS = 1_800;
// installRecoveredResponse's answer for a valid successor that arrived after
// an exit proof was released: archived as late_successor, not installed (E4.6).
const LATE_SUCCESSOR = Symbol('late-successor');
const MAX_RECOVERY_WAIT_MS = 45_000;
// OA may briefly throttle child-key creation. Keep retrying the same durable,
// idempotent lease request long enough to cross a one-minute limiter without
// ever reproving, waiting indefinitely, or amplifying the limiter with a tight
// retry loop. The production schedule is 5s, 10s, 20s, then 30s.
const LEASE_ISSUE_MAX_WAIT_MS = 75_000;
const LEASE_ISSUE_MAX_ATTEMPTS = 5;
const LEASE_ISSUE_INITIAL_RETRY_MS = 5_000;
const LEASE_ISSUE_MAX_RETRY_MS = 30_000;
// Never begin a potentially long frontier-model stream on a key that is near
// the server's independent settlement boundary. A follow-up inside this
// window transparently closes the old key and obtains a fresh key at the selected model tier.
const MIN_REQUEST_LEASE_REMAINING_SECONDS = 90;
const TAB_OWNER_STORAGE_KEY = 'zkapi-browser-tab-owner-v1';
const LATE_WITHDRAWAL_TERMINAL_STATUSES = new Set([
    'closed',
    'detached',
    'reverted',
    'challenged',
    'superseded',
    'quarantined'
]);
const LATE_DEPOSIT_TERMINAL_STATUSES = new Set(['confirmed', 'reverted', 'superseded']);

class BrowserWalletHttpError extends Error {
    constructor(message, status, code, data = null) {
        super(message);
        this.name = 'BrowserWalletHttpError';
        this.status = status;
        this.code = code;
        this.data = data;
    }
}

/** A 429's retry_after_seconds (body or Retry-After header) in milliseconds, else 0. */
function retryAfterMilliseconds(error) {
    const seconds = Number(error?.data?.retry_after_seconds);
    return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds * 1_000) : 0;
}

class WorkerBridge {
    constructor() {
        this.worker = new Worker(browserSdkOptions().workerUrl || new URL('./zkapiWasmWorker.js', import.meta.url), { type: 'module' });
        this.pending = new Map();
        this.sequence = 0;
        this.worker.addEventListener('message', (event) => {
            const entry = this.pending.get(event.data?.id);
            if (!entry) return;
            this.pending.delete(event.data.id);
            if (event.data.error) entry.reject(new Error(event.data.error));
            else entry.resolve(event.data.result);
        });
        this.worker.addEventListener('error', (event) => {
            const error = new Error(event.message || 'The zkAPI proof worker crashed.');
            for (const entry of this.pending.values()) entry.reject(error);
            this.pending.clear();
        });
    }

    call(operation, payload = {}) {
        const id = ++this.sequence;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.worker.postMessage({ id, operation, payload });
        });
    }
}

function normalizeUrl(value) {
    return String(value || '').replace(/\/+$/, '');
}

function throwIfAborted(signal) {
    if (!signal?.aborted) return;
    const error = new DOMException('The operation was aborted.', 'AbortError');
    error.isCancelled = true;
    throw error;
}

/**
 * `promise`, or a rejection as soon as `signal` aborts: an exit-mode call must
 * end at its timeout even when the transport ignores the signal (E0).
 */
function abortable(promise, signal) {
    if (!signal) return promise;
    if (signal.aborted) return Promise.reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
    return new Promise((resolve, reject) => {
        const aborted = () => reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
        signal.addEventListener('abort', aborted, { once: true });
        promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
    });
}

/**
 * `request` (EIP-1193 style) with every call bounded to `timeoutMs`; a call
 * that does not answer in time fails with `message`.
 */
function boundedRequest(request, timeoutMs, message) {
    return async payload => {
        try {
            return await abortable(Promise.resolve().then(() => request(payload)), AbortSignal.timeout(timeoutMs));
        } catch (error) {
            if (error?.name === 'TimeoutError') throw new Error(message);
            throw error;
        }
    };
}

/**
 * `request` used only on `chainId`: its first call asks eth_chainId, and on
 * another chain that call and every later one fail with `code` before
 * anything else is asked. `onChecked(matches)` sees the answer.
 */
function onChainRequest(request, chainId, { code, message, onChecked = () => {} }) {
    let checked = null;
    return async payload => {
        checked ||= Promise.resolve().then(() => request({ method: 'eth_chainId', params: [] })).then(chain => {
            const matches = BigInt(chain) === BigInt(chainId);
            onChecked(matches);
            if (!matches) throw Object.assign(new Error(message), { code });
        });
        await checked;
        return request(payload);
    };
}

function exactTrustedUrl(supplied, expected, label) {
    if (!expected?.startsWith('https://') && !expected?.startsWith('http://127.0.0.1:')
        && !expected?.startsWith('http://localhost:')) {
        throw new Error(`${label} is not a secure or loopback URL.`);
    }
    if (normalizeUrl(supplied) !== normalizeUrl(expected)) {
        throw new Error(`${label} did not match the deployment trust anchor.`);
    }
}

function delay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            const error = new Error('Request aborted');
            error.name = 'AbortError';
            reject(error);
        }, { once: true });
    });
}

function isExplicitlyRetriableLeaseError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    // These responses require a new proof or local lost-key reconciliation;
    // repeatedly sending the same lease request cannot resolve either state.
    return explicitlyRetriable
        && !['stale_root', 'native_quote_expired', 'native_quote_superseded', 'lease_pending', 'lease_settlement_pending'].includes(error?.code);
}

function isExplicitlyRetriableLeaseRetirementError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    return isExplicitlyRetriableLeaseError(error)
        || (explicitlyRetriable
            && ['lease_pending', 'lease_settlement_pending'].includes(error?.code));
}

function isLeaseRateLimit(error) {
    return error?.status === 429
        || /^oa_(?:minute_request_limit|hourly_issuance_budget|rate_limited)$/.test(error?.code || '')
        || /(?:\b429\b|too many requests|rate[ -]?limit)/i.test(error?.message || '');
}

function leaseRetryAfterMilliseconds(error) {
    const candidates = [
        error?.data?.retry_after_seconds,
        error?.data?.error?.retry_after_seconds,
        error?.data?.detail?.retry_after_seconds,
        error?.data?.error?.detail?.retry_after_seconds
    ];
    for (const candidate of candidates) {
        const seconds = Number(candidate);
        if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1_000);
    }
    return null;
}

function describeRetryDelay(milliseconds) {
    const seconds = Math.max(1, Math.ceil(milliseconds / 1_000));
    if (seconds < 60) return seconds === 1 ? '1 second' : `${seconds} seconds`;
    const minutes = Math.ceil(seconds / 60);
    if (minutes < 60) return minutes === 1 ? 'about 1 minute' : `about ${minutes} minutes`;
    const hours = Math.ceil(minutes / 60);
    return hours === 1 ? 'about 1 hour' : `about ${hours} hours`;
}

function makeLeaseRateLimitActionable(error, retryAfterMs = null) {
    if (!isLeaseRateLimit(error)) return error;
    error.shortMessage = retryAfterMs != null
        ? `Temporary-key capacity is full. Your message is saved and was not sent. Try again in ${describeRetryDelay(retryAfterMs)}.`
        : 'The temporary-key service is still busy. Your message is saved and was not sent; use Retry in a moment.';
    return error;
}

function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function browserTabOwnerId() {
    try {
        const existing = sessionStorage.getItem(TAB_OWNER_STORAGE_KEY);
        if (existing && /^[0-9a-f-]{36}$/i.test(existing)) return existing;
        const created = uuid();
        sessionStorage.setItem(TAB_OWNER_STORAGE_KEY, created);
        return created;
    } catch {
        return uuid();
    }
}

function retainAttemptHistory(attempts, terminalStatuses, terminalLimit = 32) {
    const unresolved = attempts.filter(attempt => !terminalStatuses.has(attempt.status));
    const terminal = attempts
        .filter(attempt => terminalStatuses.has(attempt.status))
        .slice(-terminalLimit);
    // An unresolved transaction is a recovery capability, not log history. It
    // must never be evicted merely because more wallet attempts were made.
    return [...terminal, ...unresolved];
}

function unresolvedLateWithdrawalForNote(runtime, noteId) {
    return (runtime?.lateWithdrawalAttempts || []).find(attempt =>
        Number(attempt.noteId) === Number(noteId)
        && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)) || null;
}

async function responsePayload(response) {
    const text = await response.text();
    try {
        return text ? JSON.parse(text) : {};
    } catch {
        return { raw: text };
    }
}

function isAbortError(error, signal = null) {
    return Boolean(signal?.aborted || error?.name === 'AbortError' || error?.isCancelled);
}

function abiWordHex(value) {
    return BigInt(value).toString(16).padStart(64, '0');
}

function withdrawalDestinationHex(value) {
    if (typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
    if (!Array.isArray(value) || value.length !== 20
        || value.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) return null;
    return `0x${value.map(byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

function preparedWithdrawalHashes(prepared) {
    return Array.isArray(prepared?.transactionHashes)
        ? prepared.transactionHashes
        : prepared?.transactionHash ? [prepared.transactionHash] : [];
}

function preparedWithdrawalHasSubmission(prepared) {
    return Boolean(prepared?.submissionId || preparedWithdrawalHashes(prepared).length);
}

function preparedWithdrawalNullifier(prepared) {
    return prepared?.withdrawalNullifier ?? prepared?.public_inputs?.withdrawal_nullifier ?? null;
}

/**
 * The ownership proof the withdrawal-only marker keeps for exactly this state
 * nullifier (C3), or null.
 */
function keptOwnershipProof(prepared, nullifier) {
    const kept = prepared?.ownershipProof;
    if (!kept?.public_inputs || !kept.proof || nullifier == null) return null;
    if (preparedWithdrawalNullifier(prepared) == null || !sameFelt(preparedWithdrawalNullifier(prepared), nullifier)) return null;
    return sameFelt(kept.public_inputs.withdrawal_nullifier, nullifier) ? kept : null;
}

/** A persisted server clearance is reusable only for the exact state nullifier. */
function validClearance(prepared, nullifier) {
    const clearance = prepared?.clearance;
    return Boolean(clearance?.signature && clearance.withdrawal_nullifier != null && nullifier != null
        && sameFelt(clearance.withdrawal_nullifier, nullifier));
}

// Everything of a note state except its bound (bound_at_state), which the
// prover sets on the state a request proof is made at.
const STATE_IDENTITY_FIELDS = Object.freeze(['protocol_version', 'chain_id', 'contract_address', 'note_id',
    'secret_s', 'deposit_amount', 'expiry_ts', 'current_balance', 'balance_blinding', 'current_commitment_x',
    'current_commitment_y', 'current_anchor', 'is_genesis', 'state_signature', 'prev_anchor']);

function sameStateExceptBound(next, current) {
    if (!next || typeof next !== 'object' || !current) return false;
    return STATE_IDENTITY_FIELDS.every(field => JSON.stringify(next[field] ?? null) === JSON.stringify(current[field] ?? null));
}

/** A note state from the WebAssembly, with the deposit-time path the previous one saved. */
function withDepositPath(next, previous) {
    return previous?.deposit_path && next && Number(next.note_id) === Number(previous.note_id)
        ? { ...next, deposit_path: previous.deposit_path }
        : next;
}

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

// A set-aside balance warns this long before its must_initiate_by.
const SET_ASIDE_WARNING_SECONDS = 7 * 86_400;

/**
 * The exit deadlines of a set-aside (parked or restored) note, from its own
 * expiry_ts (E0), for the snapshot: `expiry` and `must_initiate_by` in
 * milliseconds, and `exit_deadline_near` within a week of must_initiate_by.
 * An unfinished set-aside close is claimed by the treasury at expiry.
 */
function setAsideDeadlines(record) {
    if (!['parked', 'restored'].includes(record?.phase)) return {};
    let deadline;
    try {
        deadline = mustInitiateBy(lowExpiry(record.state?.expiry_ts));
    } catch {
        return {};
    }
    return {
        expiry: Number(record.state.expiry_ts) * 1_000,
        must_initiate_by: deadline * 1_000,
        exit_deadline_near: nowSeconds() >= deadline - SET_ASIDE_WARNING_SECONDS
    };
}

/** A saved kind-0/1 proof is reused only while enough of its validity remains. */
/** The journal fields of a sponsored operation's settlement (wei as decimal strings). */
function gaslessOutcomeFields(outcome) {
    const wei = value => (value == null ? null : BigInt(value).toString());
    const fields = {};
    if (outcome?.success != null) fields.userOpSuccess = Boolean(outcome.success);
    if (outcome?.chargedWei !== undefined) fields.chargedWei = wei(outcome.chargedWei);
    if (outcome?.owedPaidWei !== undefined) fields.owedPaidWei = wei(outcome.owedPaidWei);
    if (outcome?.receivedWei !== undefined) fields.receivedWei = wei(outcome.receivedWei);
    if (outcome?.paidOutWei !== undefined) fields.paidOutWei = wei(outcome.paidOutWei);
    if (outcome?.initiationDebtWei !== undefined) fields.initiationDebtWei = wei(outcome.initiationDebtWei);
    if (outcome?.paymasterCredited != null) fields.paymasterCredited = Boolean(outcome.paymasterCredited);
    if (outcome?.paymasterCreditedWei !== undefined) fields.paymasterCreditedWei = wei(outcome.paymasterCreditedWei);
    if (outcome?.fundsWaitingInTransit != null) fields.fundsWaitingInTransit = Boolean(outcome.fundsWaitingInTransit);
    if (outcome?.transitBalanceWei !== undefined) fields.transitBalanceWei = wei(outcome.transitBalanceWei);
    return fields;
}

function withdrawalProofStillValid(inputs) {
    const validUntil = Number(inputs?.valid_until);
    return Number.isSafeInteger(validUntil) && validUntil - nowSeconds() >= WITHDRAWAL_PROOF_REUSE_MARGIN_SECONDS;
}

class BrowserWalletRuntime extends EventTarget {
    constructor() {
        super();
        this.worker = null;
        this.browserConfig = null;
        this.manifest = null;
        this.config = null;
        this.runtime = null;
        this.withdrawals = [];
        this.deposits = [];
        this.otherDeploymentWithdrawals = [];
        this.otherDeploymentCredits = [];
        // Transmitted-request archive cache. Decisions use it only after
        // reload() under the global wallet lock.
        this.requestArchive = [];
        this.settlementFailures = 0;
        this.activeLease = null;
        this.initialized = false;
        this.initPromise = null;
        // Exit-only mode (design §1.2(6), E0): set when the operator's
        // manifest is missing, slow or differs from the build-pinned profile.
        // Exits run from the pins; deposits and requests are refused.
        this.manifestUrl = null;
        this.manifestSelectionProblem = null;
        this.manifestProblem = null;
        // The pinned RPC's native-ETH vault check: a promise of null or the
        // error. Deposits and requests wait on it; exits never do.
        this.nativeVaultCheck = null;
        this.startupRecovery = null;
        this.startupRecoveryController = null;
        this.leasePromise = null;
        this.leasePromiseSession = null;
        this.leasePromiseSpendingLimitUsd = null;
        this.leaseAbortController = null;
        this.leaseWaiterCount = 0;
        this.leaseProgressListeners = new Set();
        this.lastLeaseProgress = null;
        this.retirementPromise = null;
        this.requestProverWarmup = null;
        this.settlementTimer = null;
        this.legacyMigrationInProgress = false;
        this.channel = null;
        // sessionStorage survives a reload in this tab but is isolated from an
        // independently opened browser tab. That lets crash recovery retire a
        // lost in-memory key without allowing another live tab to take it.
        this.ownerId = browserTabOwnerId();
        // The sponsored claims (a prepared plan's submissionId, a record's
        // finalizeSubmissionId) a client of this runtime is following now.
        this.liveGaslessClaims = new Set();
    }

    /**
     * Whether the sponsored claim `submissionId` held by `owner` (claimed or
     * last sent at `lastActiveAt`) is still followed: by a client of this
     * runtime, or by another tab within `liveWindowMs` (the re-send window:
     * a following tab sends again or gives up within it). A claim of this
     * tab that no client follows any more, or a quiet one of another tab, is
     * taken over by a resume (§3.2: the journaled op is self-describing).
     */
    gaslessClaimLive({ submissionId, owner, lastActiveAt }, liveWindowMs = GASLESS_TIMING.resendAfterMs) {
        if (!submissionId) return false;
        if (this.liveGaslessClaims.has(submissionId)) return true;
        if (owner === this.ownerId) return false;
        return Date.now() - Number(lastActiveAt || 0) < Number(liveWindowMs);
    }

    /** A client stopped following the sponsored claim `submissionId`. */
    endGaslessClaim(submissionId) {
        if (submissionId) this.liveGaslessClaims.delete(submissionId);
    }

    async init() {
        beginBrowserSdkInitialization();
        if (this.initPromise) return this.initPromise;
        const pending = this.initialize();
        this.initPromise = pending;
        // A failed initialization is not kept: the next call starts again.
        pending.catch(() => {
            if (this.initPromise === pending) this.initPromise = null;
        });
        return pending;
    }

    /**
     * Initialization never waits on the operator or on the pinned RPC
     * (design §1.2(6), E0, §7.5 "Operator stalls HTTP"): every exit awaits it.
     * - The build-pinned profile alone configures the wallet when the
     *   operator's manifest is missing, slow or different (exit-only mode);
     *   deposits and requests are refused until it matches again.
     * - The pinned RPC's checks run in the background; deposits and requests
     *   wait on them, exits never do.
     * - Recovery of an interrupted request runs after initialization, bounded
     *   like E1, and an exit started in this tab stops it.
     */
    async initialize() {
        this.browserConfig = await this.loadBrowserConfig();
        // The build-pinned profile itself must be usable (fatal otherwise).
        this.validateTrustedProfile();
        const pinned = this.pinnedManifest();
        this.validateManifest(pinned);
        this.validateManifestTrust(pinned);
        // An untrusted ?zkapiDeployment link only stops deposits and chats.
        try {
            this.manifestUrl = this.selectedManifestUrl();
            this.manifestSelectionProblem = null;
        } catch (error) {
            this.manifestUrl = null;
            this.manifestSelectionProblem = { code: 'deployment_manifest_untrusted', message: String(error?.message || error) };
        }
        const served = await this.loadServedManifest(this.manifestUrl);
        this.manifest = served.manifest || pinned;
        this.manifestProblem = served.problem || null;
        if (served.manifest) this.rememberManifestUrl();
        this.config = this.buildClientConfig(this.manifest, this.browserConfig);
        this.testnetAuth = new TestnetPasswordAuth({
            funding: this.config.funding,
            fetch: (url, init) => this.remoteFetchRaw(url, init),
            requestPassword: browserSdkOptions().requestTestnetPassword
        });
        this.startPinnedRpcChecks();
        this.worker ||= new WorkerBridge();
        await this.assertWorkerBundle();
        // Initialization participates in the same global lock as every later
        // mutation. This prevents two same-origin deployment tabs from both
        // rebinding the singleton runtime and committing stale snapshots.
        // Nothing under it reaches the network.
        await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.deploymentId !== this.manifest.deployment_id) {
                this.runtime = await writeBrowserWallet({
                    ...this.runtime,
                    deploymentId: this.manifest.deployment_id,
                    billingAsset: 'native_eth'
                });
            }
            await this.discardClosedDepositDraftLocked();
        });
        this.channel ||= createWalletChannel(this.manifest.deployment_id, () => {
            // A channel notification can arrive while this tab is awaiting a
            // proof or server response inside a wallet mutation. Reading the
            // singleton IndexedDB snapshot outside the global lock can then
            // install an older in-memory value which the mutation later
            // spreads into a commit. Queue the refresh behind mutations.
            void withBrowserWalletLock(this.manifest.deployment_id, () => this.reload())
                .then(() => this.dispatchEvent(new Event('change')))
                .catch(error => this.dispatchEvent(new CustomEvent('runtime-error', { detail: error })));
        });
        await requestPersistentStorage();
        this.initialized = true;
        this.startupRecovery = this.recoverOnStartup();
        return this.snapshot();
    }

    async loadBrowserConfig() {
        const signal = AbortSignal.timeout(this.exitTiming().callTimeoutMs);
        const response = await abortable(fetch(browserConfigUrl(), { cache: 'no-store', credentials: 'omit', signal }), signal);
        if (!response.ok) throw new Error(`Unable to load browser-config.json (${response.status}).`);
        return abortable(response.json(), signal);
    }

    /** The manifest URL this page selected: a trusted ?zkapiDeployment, the remembered one, or the build's. */
    selectedManifestUrl() {
        const allowedManifests = (this.browserConfig.allowed_deployment_manifest_urls
            || [this.browserConfig.deployment_manifest_url])
            .filter(Boolean)
            .map(value => new URL(value, location.href).href);
        const requestedManifest = new URLSearchParams(location.search).get('zkapiDeployment');
        let storedManifest = null;
        try {
            storedManifest = localStorage.getItem('zkapi-browser-deployment');
        } catch {
            storedManifest = null;
        }
        if (requestedManifest
            && !allowedManifests.includes(new URL(requestedManifest, location.href).href)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        if (storedManifest
            && !allowedManifests.includes(new URL(storedManifest, location.href).href)) {
            try { localStorage.removeItem('zkapi-browser-deployment'); } catch { /* Not remembered. */ }
        }
        const configuredManifest = requestedManifest
            || (storedManifest && allowedManifests.includes(new URL(storedManifest, location.href).href)
                ? storedManifest
                : null)
            || this.browserConfig.deployment_manifest_url;
        if (!configuredManifest) return null;
        const manifestUrl = new URL(configuredManifest, location.href).href;
        if (!allowedManifests.includes(manifestUrl)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        return manifestUrl;
    }

    rememberManifestUrl() {
        try {
            if (this.manifestUrl) localStorage.setItem('zkapi-browser-deployment', this.manifestUrl);
        } catch {
            // Only a convenience: the build's manifest is used next time.
        }
    }

    /**
     * The deployment manifest as the build-pinned profile states it. A served
     * manifest must equal it on every field an exit, a deposit or a request
     * relies on (validateManifestTrust), so exits need nothing else.
     */
    pinnedManifest() {
        const trusted = this.browserConfig?.trusted_deployment || {};
        return {
            protocol_version: 2,
            proof_backend: 'groth16_bn254',
            proof_setup: {
                circuit_id: trusted.circuit_id,
                setup_id: trusted.setup_id,
                request_proving_key_sha256: trusted.request_proving_key_sha256,
                withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256
            },
            deployment_id: trusted.deployment_id,
            contract_address: trusted.contract_address,
            chain_id: trusted.chain_id,
            protocol_server_url: trusted.protocol_server_url,
            indexer_url: trusted.indexer_url,
            rpc_url: trusted.rpc_url,
            billing_asset: trusted.billing_asset,
            billing_unit: trusted.billing_unit,
            billing_token_address: null,
            native_asset_wei_per_unit: trusted.native_asset_wei_per_unit,
            native_price_feed_address: trusted.native_price_feed_address,
            native_price_feed_decimals: trusted.native_price_feed_decimals,
            native_price_max_age_seconds: trusted.native_price_max_age_seconds,
            request_charge_cap: trusted.request_charge_cap,
            state_signing_key: trusted.state_signing_key,
            clearance_signing_key: trusted.clearance_signing_key,
            privacy_mode: {
                openrouter_inference_base: trusted.openrouter_inference_base,
                verifier_url: trusted.verifier_url
            }
        };
    }

    /**
     * The operator's manifest, bounded by CALL_TIMEOUT: { manifest } when it
     * loads and matches the pins, else { problem: { code, message } }.
     */
    async loadServedManifest(url) {
        if (this.manifestSelectionProblem) return { problem: this.manifestSelectionProblem };
        if (!url) {
            return { problem: { code: 'deployment_manifest_unavailable', message: 'The website has no zkAPI deployment manifest configured.' } };
        }
        let manifest;
        try {
            manifest = await this.directJson(url, { timeoutMs: this.exitTiming().callTimeoutMs });
        } catch (error) {
            return { problem: { code: 'deployment_manifest_unavailable',
                message: error?.name === 'TimeoutError' ? `Unable to load ${url} (timed out).` : String(error?.message || error) } };
        }
        try {
            this.validateManifest(manifest);
            this.validateManifestTrust(manifest);
        } catch (error) {
            return { problem: { code: error?.code === 'incompatible_proof_circuit' ? error.code : 'deployment_manifest_mismatch',
                message: String(error?.message || error) } };
        }
        return { manifest };
    }

    /** The pinned RPC's checks, in the background: never awaited by initialization or an exit. */
    startPinnedRpcChecks() {
        this.nativeVaultCheck = this.checkNativeVault();
        // Design §6.5: the pinned RPC's view of the deployment pins, checked
        // again through the wallet provider before every deposit. A mismatch
        // only refuses deposits; exits never depend on it.
        this.deploymentVerification = { checkedAt: null, ok: null, pending: true };
        void verifyDeployment({ request: this.pinnedRpc(), trusted: this.browserConfig.trusted_deployment,
            chainId: Number(this.config.funding.chain_id), source: 'pinned_rpc' })
            .then(result => ({ checkedAt: Date.now(), ok: result.ok, results: [result] }),
                error => ({ checkedAt: Date.now(), ok: false, error: error?.code || error?.message || String(error) }))
            .then(verification => { this.deploymentVerification = verification; });
    }

    checkNativeVault() {
        return assertNativeVault(this.config.funding, { signal: AbortSignal.timeout(this.exitTiming().callTimeoutMs) })
            .then(() => null, error => error || new Error('The pinned vault RPC check failed.'));
    }

    /** Whether deposits and requests are available, for the snapshot. */
    serviceStatus() {
        return this.manifestProblem
            ? { available: false, exits: true, code: this.manifestProblem.code, message: EXIT_ONLY_MESSAGE,
                detail: this.manifestProblem.message }
            : { available: true, exits: true, code: null, message: null, detail: null };
    }

    /**
     * Deposits and requests need the operator's manifest to match the pins
     * and the pinned RPC to confirm the native-ETH vault. A failed check is
     * retried once, bounded, before refusing. Exits never call this.
     */
    async assertServiceAvailable() {
        if (this.manifestProblem) {
            const served = await this.loadServedManifest(this.manifestUrl);
            if (!served.manifest) {
                this.manifestProblem = served.problem;
                this.dispatchEvent(new Event('change'));
                throw new BrowserWalletHttpError(`${EXIT_ONLY_MESSAGE} ${served.problem.message}`, 503, served.problem.code,
                    { exits: true });
            }
            this.manifest = served.manifest;
            this.manifestProblem = null;
            this.config = this.buildClientConfig(served.manifest, this.browserConfig);
            this.rememberManifestUrl();
            this.dispatchEvent(new Event('change'));
        }
        if (!this.nativeVaultCheck) return;
        if (await this.nativeVaultCheck) this.nativeVaultCheck = this.checkNativeVault();
        const failure = await this.nativeVaultCheck;
        if (failure) {
            throw new BrowserWalletHttpError(failure.message || 'The pinned vault RPC check failed.', 503, 'native_vault_unverified',
                { exits: true });
        }
    }

    /**
     * Startup recovery of a request journal left by a closed tab: one pass
     * after initialization, never awaited by it. It runs under the wallet
     * lock within RECOVERY_BUDGET (E0), and an exit started in this tab
     * aborts it (preemptForExit), so it never holds an exit behind the
     * operator.
     */
    async recoverOnStartup() {
        if (!this.runtime?.journal) return false;
        const controller = new AbortController();
        this.startupRecoveryController = controller;
        const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(this.exitTiming().recoveryBudgetMs)]);
        try {
            return await withBrowserWalletLock(this.manifest.deployment_id, async () => {
                if (signal.aborted) return false;
                await this.reload();
                return this.recoverPendingLocked({ retireLostKey: true, quiet: true, signal });
            });
        } catch {
            return false;
        } finally {
            if (this.startupRecoveryController === controller) this.startupRecoveryController = null;
        }
    }

    /**
     * An exit in this tab stops this tab's startup recovery, and on a
     * withdrawal any private key being issued, so that neither holds the
     * wallet lock ahead of it (E0). Both are journaled and resume later.
     */
    preemptForExit({ requests = false } = {}) {
        this.startupRecoveryController?.abort();
        if (requests) this.leaseAbortController?.abort();
    }

    deploymentProxyUrl(url) {
        const proxyPath = this.browserConfig?.deployment_api_proxy_path;
        if (!proxyPath) return null;
        const proxyBase = new URL(proxyPath, location.origin);
        if (proxyBase.origin !== location.origin || !proxyBase.pathname.endsWith('/')) {
            throw new Error('browser-config.json contains an invalid deployment API proxy path.');
        }
        const target = new URL(url, location.href);
        const trusted = this.browserConfig?.trusted_deployment;
        const trustedOrigins = new Set([
            trusted?.protocol_server_url,
            trusted?.indexer_url,
            this.browserConfig?.deployment_manifest_url,
            ...(this.browserConfig?.allowed_deployment_manifest_urls || [])
        ].filter(Boolean).map(value => new URL(value, location.href).origin));
        if (!trustedOrigins.has(target.origin)) return null;
        return new URL(`${target.pathname.replace(/^\/+/, '')}${target.search}`, proxyBase).href;
    }

    async directJson(url, { timeoutMs = this.operatorCallTimeoutMs() } = {}) {
        const signal = AbortSignal.timeout(timeoutMs);
        const read = target => abortable(fetch(target, { cache: 'no-store', credentials: 'omit', signal }), signal);
        const proxyUrl = this.deploymentProxyUrl(url);
        let response = proxyUrl ? await read(proxyUrl) : null;
        // Local static development servers do not necessarily provide the
        // production rewrite. Fall back to the deployment URL only for that
        // unambiguous case; Vercel serves the trusted target at the proxy URL.
        if (!response || response.status === 404) {
            response = await read(url);
        }
        if (!response.ok) throw new Error(`Unable to load ${url} (${response.status}).`);
        return abortable(response.json(), signal);
    }

    validateManifest(manifest) {
        if (Number(manifest.protocol_version) !== 2 || manifest.proof_backend !== 'groth16_bn254') {
            throw new Error('The selected deployment is not a zkAPI v2 Groth16 deployment.');
        }
        if (manifest.proof_setup?.circuit_id !== REQUIRED_CIRCUIT_ID) {
            const error = new Error('This deployment uses an incompatible legacy proof circuit. Funding is unavailable until the operator publishes a new vault and concession-exit proof setup. Keep existing funds and recovery data with the legacy deployment.');
            error.code = 'incompatible_proof_circuit';
            throw error;
        }
        for (const field of ['deployment_id', 'contract_address', 'protocol_server_url', 'indexer_url']) {
            if (!manifest[field]) throw new Error(`The deployment manifest omitted ${field}.`);
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(manifest.contract_address)) {
            throw new Error('The deployment manifest contains an invalid contract address.');
        }
        validateNativeFunding(manifest);
        for (const field of ['protocol_server_url', 'indexer_url']) {
            const url = new URL(manifest[field]);
            if (url.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(url.hostname)) {
                throw new Error(`The deployment ${field} is not HTTPS or loopback.`);
            }
        }
        if (!manifest.state_signing_key?.x || !manifest.clearance_signing_key?.x) {
            throw new Error('The deployment manifest omitted its pinned server signing keys.');
        }
        if (!manifest.privacy_mode?.openrouter_inference_base) {
            throw new Error('The deployment does not advertise prompt-private OpenRouter leases.');
        }
    }

    /**
     * The build-pinned profile itself (browser-config.json's
     * trusted_deployment). Its errors are fatal: without a usable profile
     * there is nothing to exit from either.
     */
    validateTrustedProfile() {
        if (this.browserConfig.deployment_status === 'migration_required') {
            throw new Error('This application still pins a legacy vault. Configure a newly deployed note-bound vault before funding.');
        }
        const trusted = this.browserConfig.trusted_deployment;
        if (!trusted) {
            throw new Error('browser-config.json omitted its trusted deployment pins.');
        }
        if (trusted.deployment_status === 'not_deployed') {
            throw new BrowserWalletHttpError('This application pins a placeholder profile: no vault for this proof setup is deployed on this network yet.',
                409, 'deployment_not_deployed');
        }
        // Vault revision 3 only: the concession exit is not a monotone
        // upgrade of revision 2, so its own capability must be pinned.
        if (trusted.exit_concession !== 1) {
            throw new BrowserWalletHttpError('This application build supports only vaults with the concession exit (exit_concession 1).',
                409, 'exit_concession_required');
        }
        if (!BUNDLE_SETUP_IDS.includes(trusted.setup_id)) {
            throw new Error('browser-config.json contains an invalid trusted setup_id.');
        }
        // Capabilities come only from the build-pinned trust anchor, never
        // from the served manifest. This build supports vault revision 3 only.
        if (trusted.vault_revision !== 3) {
            throw new Error('browser-config.json contains an invalid trusted vault_revision (this build needs 3).');
        }
        if (trusted.clearance_ownership_proof !== 'required') {
            throw new Error('browser-config.json contains an invalid trusted clearance_ownership_proof (this build needs "required").');
        }
        if (trusted.settlement_window_seconds != null
            && (!Number.isSafeInteger(trusted.settlement_window_seconds) || trusted.settlement_window_seconds <= 0)) {
            throw new Error('browser-config.json contains an invalid trusted settlement_window_seconds.');
        }
        // The deposit cutoff of a deployment being drained, also from the
        // build-pinned profile only.
        if (trusted.deposits != null && !['open', 'closed'].includes(trusted.deposits)) {
            throw new Error('browser-config.json contains an invalid trusted deposits setting.');
        }
        return trusted;
    }

    /** A served deployment manifest against the build-pinned profile. */
    validateManifestTrust(manifest) {
        const trusted = this.validateTrustedProfile();
        const requireEqual = (actual, expected, label, normalize = value => String(value)) => {
            if (expected == null || normalize(actual) !== normalize(expected)) {
                throw new Error(`The deployment manifest changed its pinned ${label}.`);
            }
        };
        const lowercase = value => String(value || '').toLowerCase();
        const normalizedUrl = value => normalizeUrl(new URL(value).href);
        requireEqual(manifest.proof_setup?.circuit_id, trusted.circuit_id, 'proof circuit');
        requireEqual(manifest.deployment_id, trusted.deployment_id, 'deployment id');
        requireEqual(manifest.chain_id, trusted.chain_id, 'chain id', Number);
        requireEqual(manifest.contract_address, trusted.contract_address, 'vault address', lowercase);
        validateNativeFunding(manifest);
        validateNativeFunding(trusted);
        requireEqual(manifest.billing_asset, trusted.billing_asset, 'billing asset');
        requireEqual(manifest.billing_unit, trusted.billing_unit, 'billing unit');
        requireEqual(manifest.native_asset_wei_per_unit, trusted.native_asset_wei_per_unit, 'native asset scale');
        requireEqual(manifest.native_price_feed_address, trusted.native_price_feed_address, 'ETH price feed', lowercase);
        requireEqual(manifest.native_price_feed_decimals, trusted.native_price_feed_decimals, 'ETH price decimals', Number);
        requireEqual(manifest.native_price_max_age_seconds, trusted.native_price_max_age_seconds, 'ETH price freshness', Number);
        requireEqual(manifest.rpc_url, trusted.rpc_url, 'native asset RPC', normalizedUrl);
        requireEqual(manifest.protocol_server_url, trusted.protocol_server_url, 'protocol server', normalizedUrl);
        requireEqual(manifest.indexer_url, trusted.indexer_url, 'indexer', normalizedUrl);
        requireEqual(manifest.request_charge_cap, trusted.request_charge_cap, 'request charge cap', Number);
        for (const keyName of ['state_signing_key', 'clearance_signing_key']) {
            for (const coordinate of ['x', 'y']) {
                requireEqual(
                    manifest[keyName]?.[coordinate],
                    trusted[keyName]?.[coordinate],
                    `${keyName}.${coordinate}`,
                    lowercase
                );
            }
        }
        requireEqual(
            manifest.proof_setup?.request_proving_key_sha256,
            trusted.request_proving_key_sha256,
            'request proving key hash',
            lowercase
        );
        requireEqual(
            manifest.proof_setup?.withdrawal_proving_key_sha256,
            trusted.withdrawal_proving_key_sha256,
            'withdrawal proving key hash',
            lowercase
        );
        requireEqual(
            manifest.privacy_mode?.openrouter_inference_base,
            trusted.openrouter_inference_base,
            'OpenRouter origin',
            normalizedUrl
        );
        requireEqual(
            manifest.privacy_mode?.verifier_url,
            trusted.verifier_url,
            'OA verifier',
            normalizedUrl
        );
    }

    /**
     * Whether the build-pinned profile closed this deployment to new deposits
     * (trusted_deployment.deposits "closed"). Deposits already started stay
     * tracked, completable and recoverable; nothing new can be quoted or
     * prepared.
     */
    depositsClosed() {
        return this.browserConfig?.trusted_deployment?.deposits === 'closed';
    }

    depositsClosedError() {
        return new BrowserWalletHttpError(DEPOSITS_CLOSED_MESSAGE, 409, 'deposits_closed');
    }

    /**
     * On a closed deployment an unused deposit draft can never be promoted or
     * sent, so drop it: it would otherwise count as this deployment's wallet
     * state. A draft is never signed and holds no funds. Call under the lock.
     */
    async discardClosedDepositDraftLocked() {
        if (!this.depositsClosed() || !this.runtime?.depositQuote) return false;
        await this.commit({ ...this.runtime, depositQuote: null });
        return true;
    }

    /**
     * Deployment capabilities. This build supports only vault revision 3
     * (capability exit_concession 1): escape payouts that the destination
     * rejects are credited, and every clearance carries a kind-2 ownership
     * proof.
     */
    vaultCapabilities() {
        return { vaultRevision: 3, exitConcession: true, payoutCredits: true, sendOwnershipProof: true };
    }

    /**
     * The proof worker must run a bundle of the pinned circuit and setup: a
     * development bundle never proves for a ceremony profile, nor the reverse.
     */
    async assertWorkerBundle() {
        const trusted = this.browserConfig?.trusted_deployment || {};
        const identity = await this.worker.call('identity', {});
        if (identity?.circuit_id !== REQUIRED_CIRCUIT_ID || identity?.circuit_id !== trusted.circuit_id
            || identity?.setup_id !== trusted.setup_id) {
            throw new BrowserWalletHttpError(`The proof worker runs ${identity?.circuit_id}/${identity?.setup_id}, `
                + `but this deployment pins ${trusted.circuit_id}/${trusted.setup_id}.`, 409, 'setup_mismatch');
        }
    }

    buildClientConfig(manifest, browserConfig) {
        const keyBase = new URL(browserConfig.proving_keys_base_url || './proofs/', browserConfigUrl());
        const requestKey = new URL('request.pk', keyBase).href;
        const withdrawalKey = new URL('withdrawal.pk', keyBase).href;
        const requestVerifyingKey = new URL('request.vk', keyBase).href;
        const requestCap = Number(manifest.request_charge_cap);
        validateNativeFunding(manifest);
        return {
            ux_proposal: String(browserConfig.ux_proposal || 'quiet'),
            credits_per_usd: null,
            request_charge_cap: requestCap,
            request_charge_cap_usd: null,
            policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
            policy_enabled: Boolean(manifest.policy_enabled),
            upstream_kind: 'openrouter',
            direct_openrouter_available: true,
            request_mode: 'direct_openrouter',
            browser_wallet: true,
            active_lease: null,
            prepared_withdrawal: null,
            wallet_core: {
                protocol_version: Number(manifest.protocol_version),
                chain_id: Number(manifest.chain_id),
                contract_address: manifest.contract_address,
                request_charge_cap: requestCap,
                policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
                policy_enabled: Boolean(manifest.policy_enabled),
                state_signing_key: manifest.state_signing_key,
                clearance_signing_key: manifest.clearance_signing_key
            },
            proving_keys: {
                request: {
                    url: requestKey,
                    sha256: manifest.proof_setup?.request_proving_key_sha256
                },
                withdrawal: {
                    url: withdrawalKey,
                    sha256: manifest.proof_setup?.withdrawal_proving_key_sha256
                }
            },
            // The stale-device pre-check verifies operator evidence with the
            // build-pinned request.vk only.
            verifying_keys: {
                request: {
                    url: requestVerifyingKey,
                    sha256: browserConfig.trusted_deployment?.request_verifying_key_sha256
                }
            },
            openrouter: {
                inference_base: normalizeUrl(manifest.privacy_mode.openrouter_inference_base),
                verifier_url: normalizeUrl(manifest.privacy_mode.verifier_url),
                require_oa_key_source: browserConfig.require_oa_key_source !== false
            },
            funding: {
                contract_address: manifest.contract_address,
                chain_id: Number(manifest.chain_id),
                indexer_url: normalizeUrl(manifest.indexer_url),
                protocol_server_url: normalizeUrl(manifest.protocol_server_url),
                models: manifest.models || [],
                suggested_deposit_amount: Number(browserConfig.suggested_deposit_amount || requestCap * 100),
                demo_rpc_url: manifest.rpc_url || null,
                billing_token_symbol: 'ETH',
                billing_token_decimals: 9,
                billing_asset: manifest.billing_asset,
                billing_unit: manifest.billing_unit,
                native_asset_wei_per_unit: manifest.native_asset_wei_per_unit,
                native_price_feed_address: manifest.native_price_feed_address,
                native_price_feed_decimals: manifest.native_price_feed_decimals,
                native_price_max_age_seconds: manifest.native_price_max_age_seconds,
                demo_note_ttl_seconds: Number(manifest.note_ttl_seconds || 0) || null
            }
        };
    }

    snapshot() {
        const active = this.activeLease && this.activeLease.expires_at > Math.floor(Date.now() / 1000)
            ? {
                session_id: this.activeLease.sessionId,
                client_request_id: this.activeLease.client_request_id,
                expires_at: this.activeLease.expires_at,
                settle_after: this.activeLease.settle_after,
                spending_limit_usd: Number(this.activeLease.spending_limit_usd),
                station_id: this.activeLease.verification?.station_id || null
            }
            : null;
        const prepared = this.runtime?.preparedWithdrawal;
        const pendingDeposit = this.runtime?.pendingDeposit;
        const preparedHashes = new Set((Array.isArray(prepared?.transactionHashes)
            ? prepared.transactionHashes
            : prepared?.transactionHash ? [prepared.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const replacementIdentities = new Set((prepared?.transactionAttempts || [])
            .filter(attempt => preparedHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const pendingDepositHashes = new Set((Array.isArray(pendingDeposit?.transactionHashes)
            ? pendingDeposit.transactionHashes
            : pendingDeposit?.transactionHash ? [pendingDeposit.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const depositReplacementIdentities = new Set((pendingDeposit?.transactionAttempts || [])
            .filter(attempt => pendingDepositHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const config = this.config ? {
            ...this.config,
            deposits: this.depositsClosed() ? 'closed' : 'open',
            // Exit-only mode: withdrawals work from the build-pinned profile
            // while deposits and private chats wait for the operator.
            service: this.serviceStatus(),
            other_deployment_withdrawals: (this.otherDeploymentWithdrawals || []).map(record => ({
                deployment_id: record.deploymentId,
                record_id: record.recordId,
                note_id: record.noteId,
                mode: record.mode,
                phase: record.phase
            })),
            // Escape payouts another deployment's vault only credited. They
            // do not block a deposit here; the claim needs that profile.
            other_deployment_credits: (this.otherDeploymentCredits || []).map(credit => ({
                deployment_id: credit.deploymentId,
                record_id: credit.recordId,
                note_id: credit.noteId,
                chain_id: credit.chainId,
                contract_address: credit.contractAddress,
                destination: credit.destination,
                credited_amount: credit.creditedAmount
            })),
            active_lease: active,
            late_withdrawal_attempts: (this.runtime?.lateWithdrawalAttempts || [])
                .filter(attempt => !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    mode: attempt.mode,
                    destination: attempt.destination,
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status,
                    error: attempt.error || null
                })),
            late_deposit_attempts: (this.runtime?.lateDepositAttempts || [])
                .filter(attempt => !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    amount: Number(attempt.amount),
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status
                })),
            pending_deposit: pendingDeposit ? {
                operation_id: pendingDeposit.operationId || null,
                phase: pendingDeposit.phase || (pendingDeposit.transactionHash ? 'submitted' : 'ambiguous'),
                amount: Number(pendingDeposit.amount),
                funding_quote_available: Boolean(this.config?.funding)
                    && this.canQuotePendingDeposit(pendingDeposit),
                next_note_id: Number(pendingDeposit.next_note_id),
                transaction_hash: pendingDeposit.transactionHash || null,
                transaction_hashes: Array.isArray(pendingDeposit.transactionHashes)
                    ? [...pendingDeposit.transactionHashes]
                    : pendingDeposit.transactionHash ? [pendingDeposit.transactionHash] : [],
                replacement_available: pendingDeposit.phase === 'dropped_or_pending'
                    && depositReplacementIdentities.size === 1
            } : null,
            prepared_withdrawal: prepared ? {
                mode: prepared.mode,
                phase: prepared.phase || (prepared.transactionHash ? 'submitted' : 'prepared'),
                note_id: prepared.public_inputs?.note_id ?? prepared.noteId ?? prepared.note_id,
                destination: Array.isArray(prepared.public_inputs?.destination)
                    ? `0x${prepared.public_inputs.destination.map(byte => Number(byte).toString(16).padStart(2, '0')).join('')}`
                    : prepared.destination,
                transaction_hash: prepared.transactionHash || null,
                clearance_reserved: prepared.clearanceReserved === true || prepared.mode === 'mutual',
                // Only a granted close can be set aside (parkPreparedWithdrawal).
                clearance_granted: preparedWithdrawalParkable(prepared, this.runtime?.exitLock),
                replacement_available: prepared.phase === 'dropped_or_pending'
                    && replacementIdentities.size === 1,
                // A sponsored plan (§3.2): the fee payer, the payout address
                // Y (the journaled destination is the transit account S), the
                // transit identity and the operation's hash and phase.
                fee_payer: prepared.feePayer === 'payout' ? 'payout' : 'wallet',
                payout: prepared.feePayer === 'payout' ? prepared.payout || null : null,
                transit: prepared.feePayer === 'payout' && prepared.transit ? structuredClone(prepared.transit) : null,
                user_op_hash: prepared.feePayer === 'payout' ? prepared.userOpHash || null : null,
                user_op_phase: prepared.feePayer === 'payout' ? prepared.userOpPhase || null : null
            } : null,
            gasless: this.gaslessSnapshot(),
            ...this.requestArchiveSummary()
        } : null;
        return {
            config,
            runtime: this.runtime,
            activeLease: active,
            deposits: this.deposits.map(record => ({ ...record,
                ...(record.expiryClaim ? { expiryClaim: { ...record.expiryClaim } } : {}) })),
            withdrawals: this.withdrawals.map(record => {
                const {
                    state: _state,
                    preparedWithdrawal: _prepared,
                    proof: _proof,
                    withdrawalNullifier: _nullifier,
                    challengeEvidence,
                    ...summary
                } = record;
                return { ...summary, ...setAsideDeadlines(record), challengeObserved: Boolean(challengeEvidence),
                    backgroundWithdrawalReady: isUnsubmittedParkedMutualWithdrawal(
                    record, this.runtime?.lateWithdrawalAttempts || []
                ), backgroundPreparationCancelable: Boolean(this.config && this.manifest)
                    && isBrowserBackgroundWithdrawalPreparationCancelable(
                        record, this.runtime, this.backgroundWithdrawalIdentity(record)
                    ) };
            })
        };
    }

    /**
     * The snapshot's `gasless` object (§3.2): whether the profile pins the
     * gasless contracts, the effective bundler and whether it answered on
     * another chain, and the paymaster's float, policy and the attempts the
     * last availability read saw (null until one ran).
     */
    gaslessSnapshot() {
        const pins = this.gaslessPins();
        const bundlerUrlValue = pins ? this.effectiveBundlerUrl() : null;
        const status = this.gaslessStatus || null;
        return {
            supported: Boolean(pins),
            bundler_url: bundlerUrlValue,
            bundler_wrong_chain: Boolean(bundlerUrlValue) && this.bundlerChainCheck?.url === bundlerUrlValue
                && this.bundlerChainCheck.matches === false,
            paymaster_deposit_wei: status?.paymaster_deposit_wei ?? null,
            policy: status?.policy ? structuredClone(status.policy) : null,
            attempts_left: status?.attempts_left ?? null,
            // The prefund the last pre-flight priced against the float (§3.1).
            max_cost_wei: status?.max_cost_wei ?? null,
            ...(status?.available != null ? { available: status.available, reason: status.reason ?? null, checked_at: status.checked_at ?? null } : {})
        };
    }

    /** Public, proof-free view of transmitted requests and the exit rules at the selected note state. */
    requestArchiveSummary() {
        const state = this.runtime?.state;
        const entries = this.archivedRequestsAt(state);
        const exit = this.exitSummary(state);
        const installed = (this.requestArchive || [])
            .filter(record => record.type === REQUEST_JOURNAL_TYPE && record.disposition === 'installed'
                && record.deploymentId === this.manifest?.deployment_id
                && Number(record.noteId) === Number(state?.note_id))
            .sort((left, right) => Number(right.installedAt || right.updatedAt || 0)
                - Number(left.installedAt || left.updatedAt || 0))[0];
        return {
            vault_revision: this.vaultCapabilities().vaultRevision,
            exit,
            unresolved_requests: entries.map(entry => {
                const observed = lastObservation(entry);
                return {
                    client_request_id: entry.clientRequestId || null,
                    kind: entry.type === REQUEST_JOURNAL_TYPE ? 'request' : 'evidence',
                    disposition: entry.disposition,
                    class: exitRecordClass(entry),
                    created_at: Number(entry.createdAt) || null,
                    server_status: observed?.status || null,
                    server_status_at: observed?.at || null,
                    escape_at: exit?.escape_at ?? null
                };
            }),
            last_settlement: installed ? {
                client_request_id: installed.clientRequestId,
                charge_applied: installed.chargeApplied ?? null,
                charge_basis: installed.chargeBasis ?? null,
                settlement_reason: installed.settlementReason ?? null,
                installed_at: installed.installedAt ?? installed.updatedAt ?? null
            } : null
        };
    }

    /**
     * The exit rules at a state from local data only (design §6.4): when an
     * exit must start, whether the state is fresh (E2), when an escape
     * concedes the bound (T, E3), the exit lock and the exit kit's age.
     * Times are in milliseconds.
     */
    exitSummary(state = this.runtime?.state) {
        if (!state) return null;
        const now = nowSeconds();
        let deadline = null;
        try {
            deadline = mustInitiateBy(lowExpiry(state.expiry_ts));
        } catch {
            deadline = null;
        }
        const status = stateExitStatus({ boundAtState: state.bound_at_state || 0, records: this.exitRecordsAt(state) });
        const T = status.fresh || status.newestUnresolvedCreatedAt == null || deadline == null ? null : escapeAt({
            createdAt: status.newestUnresolvedCreatedAt,
            settlementWindowSeconds: this.settlementWindowSeconds(),
            unsettledAfterSeconds: this.browserConfig?.unsettled_request_escape_after_seconds,
            mustInitiateBy: deadline
        });
        const lock = this.runtime?.exitLock;
        const exits = releasedExitProofs(lock);
        const stateSeq = Number(this.runtime?.stateSeq || 0);
        const exported = this.runtime?.exitKitExportedSeq;
        const exitRpcUrlValue = this.getExitRpcUrl();
        return {
            must_initiate_by: deadline == null ? null : deadline * 1_000,
            near_expiry: deadline != null && nearExpiry({ now, settlementWindowSeconds: this.settlementWindowSeconds(),
                mustInitiateBy: deadline }),
            bound_at_state: String(status.boundAtState),
            state_fresh: status.fresh,
            escape_at: T == null ? null : T * 1_000,
            device_not_newest: status.challenged,
            lock: lock ? {
                mode: lock.mode,
                since: Number(lock.since) * 1_000,
                released: (lock.released || []).length,
                exit_proofs_released: exits.length,
                releasable_after: exits.length ? exitLockDeadAfter(lock) * 1_000 : null
            } : null,
            exit_kit: { state_seq: stateSeq, exported_seq: exported ?? null, out_of_date: exported == null || exported < stateSeq },
            deposit_path_saved: Boolean(state.deposit_path),
            exit_cost_warning: this.exitCostWarningAt(state),
            exit_rpc_url: exitRpcUrlValue,
            // The exit RPC answered on another chain than the vault's, so
            // exits read the wallet provider and the pinned RPC instead.
            exit_rpc_wrong_chain: Boolean(exitRpcUrlValue) && this.exitRpcChainCheck?.url === exitRpcUrlValue
                && this.exitRpcChainCheck.matches === false,
            // Without a saved deposit path an escape's path comes from the
            // operator's indexer or a log rebuild; the user's own exit RPC
            // (or an exit kit made on the depositing device) removes that
            // dependence on the operator.
            exit_rpc_recommended: !state.deposit_path && !exitRpcUrlValue
        };
    }

    /**
     * G1 (§2.3): `{ floor, cost, gas_price_wei }` when the state's payout
     * floor B − bound_at_state is below three times an escape's estimated
     * network fee at the last gas price the wallet provider reported, else
     * null (also while no gas price was read). Amounts are ledger units.
     */
    exitCostWarningAt(state = this.runtime?.state) {
        const price = this.exitGasPrice?.wei;
        if (!state || price == null) return null;
        try {
            const cost = escapeCostUnits({ gasPriceWei: price,
                weiPerUnit: this.config?.funding?.native_asset_wei_per_unit ?? 1_000_000_000 });
            const warning = exitCostWarning({ stateBalance: state.current_balance, boundAtState: state.bound_at_state || 0,
                exitCostUnits: cost });
            return warning ? { floor: String(warning.floor), cost: String(warning.cost), gas_price_wei: String(price) } : null;
        } catch {
            return null;
        }
    }

    /**
     * Read the gas price through the user's wallet provider (on the vault's
     * chain only) for the G1 exit-cost warning. Best effort and bounded: the
     * whole read ends within E0's CALL_TIMEOUT, and a failed or late read
     * keeps the last price. Returns the selected state's warning, or null.
     */
    async refreshExitCost({ request } = {}) {
        if (typeof request === 'function' && this.config?.funding?.chain_id != null) {
            try {
                const wallet = this.walletOnVaultChain(request);
                const price = BigInt(await abortable(wallet({ method: 'eth_gasPrice', params: [] }),
                    AbortSignal.timeout(this.exitTiming().callTimeoutMs)));
                if (price > 0n) {
                    const changed = this.exitGasPrice?.wei !== price;
                    this.exitGasPrice = { wei: price, at: Date.now() };
                    if (changed) this.dispatchEvent(new Event('change'));
                }
            } catch {
                // The warning is advisory; the last price stays.
            }
        }
        return this.exitCostWarningAt();
    }

    archiveKey(state = this.runtime?.state) {
        const deploymentId = this.manifest?.deployment_id;
        if (!deploymentId || state?.note_id == null || state.current_anchor == null) return null;
        return { deploymentId, noteId: Number(state.note_id), anchor: state.current_anchor };
    }

    /** Unresolved transmitted requests and challenge evidence at a note state. */
    archivedRequestsAt(state = this.runtime?.state) {
        const key = this.archiveKey(state);
        return key ? unresolvedRequestArchiveAt(this.requestArchive, key) : [];
    }

    /** A complete archive record for a journal at a state, or null when incomplete. */
    tryRequestJournalRecord(journal, state = this.runtime?.state, options = {}) {
        try {
            return buildRequestJournalRecord({
                deploymentId: this.manifest?.deployment_id,
                state,
                journal,
                ...options
            });
        } catch {
            return null;
        }
    }

    async saveRequestObservations(entries, observed, context) {
        if (!entries?.length || !observed?.status) return;
        try {
            const observation = readingObservation(observed, context);
            this.requestArchive = await putBrowserRequestArchive(entries.map(entry => ({
                archiveId: entry.archiveId,
                type: entry.type,
                serverObservations: [observation]
            })), { deploymentId: this.manifest.deployment_id });
        } catch (error) {
            // The decision already used the fresh observation in memory.
            console.warn('Unable to save a private request status observation.', error);
        }
    }

    async reload() {
        const deploymentId = this.manifest?.deployment_id || this.runtime?.deploymentId || null;
        const snapshot = await readBrowserWalletSnapshot(deploymentId);
        const storedRuntime = snapshot.runtime;
        const hasDurableState = browserRuntimeHoldsState(storedRuntime);
        if (this.manifest && hasDurableState
            && (!storedRuntime.deploymentId || storedRuntime.deploymentId !== this.manifest.deployment_id
                || (storedRuntime.billingAsset != null && storedRuntime.billingAsset !== 'native_eth'))) {
            throw new Error(`This browser contains a wallet for ${storedRuntime.deploymentId || 'an unidentified legacy deployment'}. Switch back to that deployment before using or withdrawing it.`);
        }
        this.runtime = storedRuntime.deploymentId
            && this.manifest
            && storedRuntime.deploymentId !== this.manifest.deployment_id
            ? { ...storedRuntime, deploymentId: this.manifest.deployment_id }
            : storedRuntime;
        this.withdrawals = snapshot.withdrawals;
        // Only another deployment's runtime can finish these; the snapshot
        // reports them so a host can switch profiles before funding here.
        this.otherDeploymentWithdrawals = snapshot.otherDeploymentWithdrawals || [];
        this.otherDeploymentCredits = snapshot.otherDeploymentCredits || [];
        this.deposits = snapshot.deposits;
        this.requestArchive = snapshot.requestArchive || [];
        return this.runtime;
    }

    notify() {
        this.channel?.postMessage({ updatedAt: this.runtime.updatedAt });
        this.dispatchEvent(new Event('change'));
    }

    async commit(next, options = {}) {
        const committed = await commitBrowserWallet({ ...next, deploymentId: this.manifest.deployment_id, billingAsset: 'native_eth' }, options);
        this.runtime = committed.runtime;
        // The same transaction returned the merged archive; no fallible read follows.
        if (committed.requestArchive) this.requestArchive = committed.requestArchive;
        this.deposits = projectBrowserDeposits(this.runtime, this.deposits,
            this.manifest.deployment_id, options.depositConfirmation);
        this.notify();
        return this.runtime;
    }

    async getDepositHistory() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.snapshot().deposits;
        });
    }

    async rememberExpiryClaims(claims) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const updated = await recordBrowserExpiryClaims(this.manifest.deployment_id, claims);
            await this.reload();
            if (updated.length) this.notify();
            return updated;
        });
    }

    async walletStatus() {
        await this.init();
        const status = await this.worker.call('walletStatus', {
            state: this.runtime.state,
            journal: this.runtime.journal
        });
        // Let the lightweight status needed for the first paint leave the
        // worker before beginning the CPU-heavy decode. The warm-up then runs
        // while a funded user reads or types, without delaying page readiness.
        if (this.runtime.state || this.runtime.pendingDeposit) {
            void this.prewarmRequestProver();
        }
        return status;
    }

    prewarmRequestProver() {
        if (!this.worker || !this.config?.proving_keys?.request) {
            return Promise.resolve(false);
        }
        if (this.requestProverWarmup) return this.requestProverWarmup;
        const warmup = this.worker.call('preloadRequestProver', {
            provingKey: this.config.proving_keys.request
        }).then(() => true).catch(error => {
            // Pre-warming is an optimization. A failed fetch/decode must stay
            // silent here and be retried by the normal Send path later.
            if (this.requestProverWarmup === warmup) this.requestProverWarmup = null;
            console.warn('Unable to pre-warm the zkAPI request prover.', error);
            return false;
        });
        this.requestProverWarmup = warmup;
        return warmup;
    }

    async hasPendingLease() {
        await this.init();
        await this.reload();
        return Boolean(this.activeLease || this.runtime?.journal);
    }

    async getPendingLeaseOwner() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime?.lease?.sessionId || this.activeLease?.sessionId || null;
        });
    }

    async remoteFetch(url, init = {}) {
        return this.testnetAuth ? this.testnetAuth.fetch(url, init) : this.remoteFetchRaw(url, init);
    }

    async remoteFetchRaw(url, init = {}) {
        const proxyUrl = this.deploymentProxyUrl(url);
        if (proxyUrl) {
            try {
                const response = await fetch(proxyUrl, {
                    ...init,
                    credentials: 'omit'
                });
                if (response.status !== 404) return response;
            } catch {
                // A local static development server may not implement the
                // production rewrite. Keep the existing privacy-proxy/direct
                // fallback available there.
            }
        }
        return browserSdkTransport(url, init, { preferProxy: true });
    }

    /**
     * One operator call, ended (connect and full body) by `timeoutMs` or the
     * caller's signal, whichever comes first: no operator call made under the
     * wallet lock can hold it indefinitely (E0).
     */
    async remoteJson(url, { timeoutMs = this.operatorCallTimeoutMs(), ...init } = {}) {
        const timeout = AbortSignal.timeout(timeoutMs);
        const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
        const response = await abortable(this.remoteFetch(url, { ...init, signal }), signal);
        if (response.status === 401 && this.testnetAuth?.protects(url)) throw testnetPasswordRequired();
        let payload = await abortable(responsePayload(response), signal);
        if (!response.ok) {
            const retryAfterHeader = response.headers.get('retry-after');
            const retryAfter = retryAfterHeader == null || retryAfterHeader.trim() === ''
                ? Number.NaN
                : Number(retryAfterHeader);
            if (Number.isFinite(retryAfter) && retryAfter >= 0
                && payload?.retry_after_seconds == null) {
                payload = { ...payload, retry_after_seconds: retryAfter };
            }
            const details = payload?.error && typeof payload.error === 'object'
                ? payload.error
                : {};
            throw new BrowserWalletHttpError(
                details.error_message
                    || details.message
                    || payload.error_message
                    || payload.message
                    || `HTTP ${response.status}`,
                response.status,
                details.error_code
                    || details.code
                    || payload.error_code
                    || payload.code,
                payload
            );
        }
        return payload;
    }

    async treePath(noteId, requireExisting = true, expectedActiveRoot = null, signal = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`, { signal });
            return this.worker.call('treePath', { snapshot, noteId, requireExisting });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds, signal) });
    }

    async nextDepositPath(expectedActiveRoot = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`);
            return this.worker.call('treePath', {
                snapshot,
                noteId: Number(snapshot.next_note_id),
                requireExisting: false
            });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds) });
    }

    canQuotePendingDeposit(pending = this.runtime?.pendingDeposit) {
        const noActiveAttempt = pending && typeof pending.operationId === 'string' && pending.operationId
            && !pending.submissionId && !pending.transactionHash
            && !pending.transactionHashes?.length && !pending.transactionAttempts?.length
            && !pending.submissionFrom && pending.submissionNonce == null
            && !(this.runtime?.lateDepositAttempts || []).some(attempt =>
                attempt.operationId === pending.operationId
                && !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status));
        if (!noActiveAttempt) return false;
        if (pending.phase === 'retry_exact') {
            return pending.fundingQuoteRetryAuthorized === true && Boolean(pending.ambiguousSubmissions?.length);
        }
        return pending.phase === 'prepared' && !pending.legacyRecovery
            && !(pending.ambiguousSubmissions || []).some(attempt =>
                !(pending.resolvedAmbiguousSubmissionIds || []).includes(attempt.submissionId));
    }

    async prepareDepositQuote(amount, expectedActiveRoot) {
        await this.init();
        // Exit-only mode refuses new deposits (initialize()).
        await this.assertServiceAvailable();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending && this.depositsClosed()) {
                // Only a deposit already started may still be quoted.
                await this.discardClosedDepositDraftLocked();
                throw this.depositsClosedError();
            }
            if (this.runtime.state || (pending && !this.canQuotePendingDeposit(pending))) {
                throw new Error('Recover the existing private balance or deposit before preparing another quote.');
            }
            if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('Invalid deposit amount.');
            if (pending && pending.amount !== amount) {
                throw new Error('The prepared deposit amount is fixed. Refresh its existing funding quote.');
            }
            if (pending?.phase === 'retry_exact') {
                // An explicit retry may coexist with an unknown old send. Its
                // exact calldata must remain fixed until chain recovery proves
                // the old slot cannot execute; quoting never rebases it.
                return { ...pending };
            }
            const previous = pending || this.runtime.depositQuote;
            const params = previous?.amount === amount ? previous
                : await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath(expectedActiveRoot);
            const draft = {
                ...(pending || {}),
                operationId: previous?.amount === amount ? previous.operationId : uuid(),
                createdAt: previous?.amount === amount ? previous.createdAt : Date.now(),
                amount,
                secret: params.secret,
                commitment: params.commitment || params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // A new quote is only a draft. A rejected-before-broadcast pending
            // plan can be requoted, but only for its original amount and identity.
            // Neither path creates a claim, history entry or transaction.
            await this.commit(pending
                ? { ...this.runtime, depositQuote: null, pendingDeposit: draft }
                : { ...this.runtime, depositQuote: draft });
            return draft;
        });
    }

    async prepareDeposit(amount, { preparedOperationId = null } = {}) {
        await this.init();
        await this.assertServiceAvailable();
        const plan = await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId === preparedOperationId
                && this.runtime.pendingDeposit.amount !== amount) {
                throw new Error('The prepared deposit amount does not match the selected quote.');
            }
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId !== preparedOperationId) {
                const draft = this.runtime.depositQuote;
                if (this.runtime.pendingDeposit || !draft || draft.operationId !== preparedOperationId
                    || draft.amount !== amount) {
                    throw new Error('The deposit quote changed in another tab. Refresh the quote before continuing.');
                }
                if (this.depositsClosed()) {
                    await this.discardClosedDepositDraftLocked();
                    throw this.depositsClosedError();
                }
                const promoted = { ...draft, phase: 'prepared' };
                // Promotion is the explicit deposit action, atomic with the
                // stale-quote check under the same cross-tab wallet lock.
                await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: promoted });
                return promoted;
            }
            if (this.runtime.pendingDeposit) {
                let pending = this.runtime.pendingDeposit;
                if (!pending.operationId || !pending.phase) {
                    // Legacy clients opened MetaMask without a durable claim.
                    // A missing hash is not proof that nothing was broadcast.
                    pending = {
                        ...pending,
                        operationId: pending.operationId || uuid(),
                        phase: pending.transactionHash ? 'submitted' : 'ambiguous',
                        legacyRecovery: true
                    };
                    await this.commit({ ...this.runtime, pendingDeposit: pending });
                }
                if (Number(pending.amount) !== Number(amount)) {
                    if (pending.phase !== 'prepared' || pending.submissionId
                        || pending.transactionHash || pending.transactionHashes?.length) {
                        throw new Error('A previous deposit may already be in MetaMask. Recover it before changing the amount.');
                    }
                    // Replacing it would start a new deposit; it stays as it is.
                    if (this.depositsClosed()) throw this.depositsClosedError();
                    await this.commit({ ...this.runtime, pendingDeposit: null });
                    await this.reload();
                } else {
                    return pending;
                }
            }
            if (this.depositsClosed()) {
                await this.discardClosedDepositDraftLocked();
                throw this.depositsClosedError();
            }
            const params = await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath();
            const plan = {
                operationId: uuid(),
                createdAt: Date.now(),
                phase: 'prepared',
                amount: Number(amount),
                secret: params.secret,
                commitment: params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Persist the note secret before MetaMask is opened. If the tab is
            // closed after the transaction is submitted, the deposit can still
            // be confirmed from its on-chain receipt without losing funds.
            await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: plan });
            return plan;
        });
        // Start only after deposit preparation's small WASM calls have left the
        // worker. MetaMask/on-chain confirmation normally outlasts the decode,
        // hiding it without creating a lease or disposable inference request.
        void this.prewarmRequestProver();
        return plan;
    }

    async refreshPendingDeposit(amount, expectedActiveRoot = null, { expectedOperationId = null } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            if (Number(pending.amount) !== Number(amount)) {
                throw new Error('The prepared private note has a different deposit amount.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (pending.phase !== 'prepared' || pending.submissionId || hashes.length) {
                throw new Error('This deposit already has a wallet attempt. Check it before refreshing the vault path.');
            }
            const path = await this.nextDepositPath(expectedActiveRoot);
            const refreshed = {
                ...pending,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Keep the durable secret and commitment, but rebase their unused
            // note onto the latest append position before the wallet prompt.
            await this.commit({ ...this.runtime, pendingDeposit: refreshed });
            return refreshed;
        });
    }

    async pendingDeposit() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.pendingDeposit ? { ...this.runtime.pendingDeposit } : null;
        });
    }

    async claimPendingDepositSubmission(expectedOperationId = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (hashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: hashes[0],
                    operationId: pending.operationId,
                    submissionId: pending.submissionId || null,
                    noteId: Number(pending.next_note_id),
                    amount: Number(pending.amount),
                    commitment: pending.commitment,
                    secret: pending.secret,
                    deploymentId: this.manifest.deployment_id,
                    chainId: Number(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (pending.phase === 'ambiguous') {
                throw new BrowserWalletHttpError(
                    'The previous deposit has an unknown result. Check it before explicitly retrying.',
                    409,
                    'deposit_submission_ambiguous'
                );
            }
            if (pending.submissionId) {
                throw new BrowserWalletHttpError(
                    'This deposit is already awaiting MetaMask in this or another tab.',
                    409,
                    'deposit_wallet_pending'
                );
            }
            if (!['prepared', 'retry_exact'].includes(pending.phase)) {
                throw new Error('This deposit is not ready for a wallet request.');
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                plan: { ...next },
                transactionHash: null,
                operationId: next.operationId,
                submissionId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async claimPendingDepositReplacement(expectedFrom) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted deposit before replacing it.');
            }
            if (pending.submissionId) {
                throw new Error('A deposit replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((pending.transactionAttempts || [])
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
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved deposit has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved deposit has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this deposit.`);
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPendingDepositSubmissionMetadata(submission, metadata) {
        await this.init();
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The deposit transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...pending,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    depositSubmissionMatches(pending, reference) {
        return Boolean(reference?.operationId && reference?.submissionId
            && pending?.operationId === reference.operationId
            && Number(pending.next_note_id) === Number(reference.noteId)
            && Number(pending.amount) === Number(reference.amount)
            && sameFelt(pending.commitment, reference.commitment)
            && reference.deploymentId === this.manifest.deployment_id
            && Number(reference.chainId) === Number(this.config.funding.chain_id)
            && String(reference.contractAddress || '').toLowerCase()
                === String(this.config.funding.contract_address || '').toLowerCase());
    }

    async rememberPendingDepositTransaction(
        transactionHash,
        submission,
        transactionMetadata = null
    ) {
        await this.init();
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid deposit transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) {
                throw new Error('The durable pending deposit is missing.');
            }
            if (!this.depositSubmissionMatches(pending, submission)) {
                const attempts = Array.isArray(this.runtime.lateDepositAttempts)
                    ? this.runtime.lateDepositAttempts
                    : [];
                const lateAttempt = {
                    operationId: submission?.operationId || null,
                    submissionId: submission?.submissionId || null,
                    noteId: Number(submission?.noteId),
                    amount: Number(submission?.amount),
                    commitment: submission?.commitment || null,
                    secret: submission?.secret || null,
                    deploymentId: submission?.deploymentId || null,
                    chainId: Number(submission?.chainId),
                    contractAddress: submission?.contractAddress || null,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(transactionMetadata?.from || '')
                        ? transactionMetadata.from.toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(transactionMetadata?.nonce))
                        ? Number(transactionMetadata.nonce)
                        : null,
                    status: 'submitted_late',
                    observedAt: Date.now()
                };
                await this.commit({
                    ...this.runtime,
                    lateDepositAttempts: retainAttemptHistory([...attempts.filter(attempt => !(
                        attempt.operationId === lateAttempt.operationId
                        && attempt.transactionHash === lateAttempt.transactionHash
                    )), lateAttempt], new Set(['confirmed', 'reverted', 'superseded']))
                });
                return { late: true, ...lateAttempt };
            }
            const normalizedHash = transactionHash.toLowerCase();
            const hashes = [...new Set([
                ...(Array.isArray(pending.transactionHashes)
                    ? pending.transactionHashes
                    : pending.transactionHash ? [pending.transactionHash] : []),
                normalizedHash
            ].map(value => value.toLowerCase()))];
            const pendingDeposit = {
                ...pending,
                phase: 'submitted',
                transactionHash: hashes[0],
                transactionHashes: hashes,
                transactionAttempts: [
                    ...(Array.isArray(pending.transactionAttempts)
                        ? pending.transactionAttempts.filter(attempt => attempt.hash !== normalizedHash)
                        : []),
                    {
                        hash: normalizedHash,
                        submissionId: submission.submissionId,
                        operationId: submission.operationId,
                        from: /^0x[0-9a-fA-F]{40}$/.test(
                            transactionMetadata?.from || pending.submissionFrom || ''
                        )
                            ? (transactionMetadata?.from || pending.submissionFrom).toLowerCase()
                            : null,
                        nonce: Number.isSafeInteger(Number(
                            transactionMetadata?.nonce ?? pending.submissionNonce
                        ))
                            ? Number(transactionMetadata?.nonce ?? pending.submissionNonce)
                            : null,
                        observedAt: Date.now()
                    }
                ]
            };
            if (pending.submissionId === submission.submissionId) {
                delete pendingDeposit.submissionId;
                delete pendingDeposit.submissionOwner;
                delete pendingDeposit.submissionStartedAt;
                delete pendingDeposit.submissionFrom;
                delete pendingDeposit.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit });
            return { ...pendingDeposit };
        });
    }

    async markPendingDepositRetryable(expectedTransactionHash = null, submission = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            if (!expectedTransactionHash && !this.depositSubmissionMatches(pending, submission)) {
                throw new Error('The deposit operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The deposit transaction changed while its receipt was checked.');
            }
            const remaining = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const releasesClaim = !expectedTransactionHash
                && pending.submissionId === submission?.submissionId;
            const next = {
                ...pending,
                phase: remaining.length
                    ? 'submitted'
                    : pending.submissionId && !releasesClaim
                        ? (pending.phase === 'ambiguous' ? 'ambiguous' : 'awaiting_wallet')
                        : pending.fundingQuoteRetryAuthorized === true && pending.ambiguousSubmissions?.length
                            ? 'retry_exact' : 'prepared',
                transactionHashes: remaining,
                transactionAttempts: Array.isArray(pending.transactionAttempts)
                    ? pending.transactionAttempts.filter(attempt => !expectedTransactionHash
                        || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                    : []
            };
            if (remaining.length) next.transactionHash = remaining[0];
            else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The deposit transactions changed while their receipts were checked.');
            }
            if (pending.submissionId) return pending;
            if (pending.phase === 'dropped_or_pending') return pending;
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async releasePendingDepositReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.submissionId !== submission?.submissionId
                || pending.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The deposit replacement request changed before it could be released.');
            }
            const history = Array.isArray(pending.ambiguousReplacements)
                ? pending.ambiguousReplacements
                : [];
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: pending.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: pending.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a deposit replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit operation changed before its unknown result could be saved.');
            }
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositUnknown() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending?.submissionId) throw new Error('There is no deposit wallet prompt to recover.');
            if (pending.phase === 'ambiguous') return pending;
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async authorizePendingDepositRetry({ forFundingQuote = false } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            const hashes = Array.isArray(pending?.transactionHashes)
                ? pending.transactionHashes
                : pending?.transactionHash ? [pending.transactionHash] : [];
            if (forFundingQuote && pending?.phase === 'retry_exact' && !pending.submissionId
                && !hashes.length && !pending.transactionAttempts?.length && pending.ambiguousSubmissions?.length) {
                const authorized = { ...pending, fundingQuoteRetryAuthorized: true };
                if (!this.canQuotePendingDeposit(authorized)) {
                    throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
                }
                await this.commit({ ...this.runtime, pendingDeposit: authorized });
                return authorized;
            }
            if (!pending || pending.phase !== 'ambiguous' || !pending.submissionId || hashes.length) {
                throw new Error('There is no unknown deposit request to retry.');
            }
            const history = Array.isArray(pending.ambiguousSubmissions)
                ? pending.ambiguousSubmissions
                : [];
            const next = {
                ...pending,
                phase: 'retry_exact',
                fundingQuoteRetryAuthorized: forFundingQuote,
                ambiguousSubmissions: [...history, {
                    submissionId: pending.submissionId,
                    startedAt: pending.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            if (forFundingQuote && !this.canQuotePendingDeposit(next)) {
                throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async resolvePendingDepositSlotConflict(expected) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalizeHashes = value => [...new Set((Array.isArray(value)
                ? value
                : value ? [value] : [])
                .map(hash => String(hash).toLowerCase()))].sort();
            const pendingHashes = normalizeHashes(
                pending.transactionHashes || pending.transactionHash
            );
            const expectedHashes = normalizeHashes(
                expected?.transactionHashes || expected?.transactionHash
            );
            if (!expected?.operationId
                || pending.operationId !== expected.operationId
                || Number(pending.next_note_id) !== Number(expected.noteId)
                || Number(pending.amount) !== Number(expected.amount)
                || !sameFelt(pending.commitment, expected.commitment)
                || (pending.phase || null) !== (expected.phase || null)
                || (pending.submissionId || null) !== (expected.submissionId || null)
                || JSON.stringify(pendingHashes) !== JSON.stringify(expectedHashes)) {
                throw new Error('The pending deposit changed while its vault slot was being checked. Check it again before retrying.');
            }
            const next = {
                ...pending,
                phase: 'prepared',
                previousSlot: Number(pending.next_note_id),
                // Finalized occupation by another commitment proves every old
                // ambiguous call for this append slot can no longer succeed.
                // Retain those claims for late recovery, while recording exactly
                // which ambiguity was resolved before allowing a fresh quote.
                resolvedAmbiguousSubmissionIds: (pending.ambiguousSubmissions || []).map(attempt => attempt.submissionId),
                legacyRecovery: false,
                fundingQuoteRetryAuthorized: false
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.transactionHash;
            delete next.transactionHashes;
            delete next.transactionAttempts;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async confirmDeposit(args) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) {
                // The SDK's background reconcile may have confirmed this very
                // deposit from the vault while the foreground waited for its
                // receipt. That is the same confirmation, not a second note.
                const confirmed = this.confirmedDepositFor(args);
                if (!confirmed) throw new Error('This browser already has an active private note.');
                return this.completeConfirmedDeposit(confirmed, args);
            }
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.secret !== args.secret
                || (args.operationId && pending.operationId !== args.operationId)
                || Number(pending.next_note_id) !== Number(args.note_id)
                || Number(pending.amount) !== Number(args.amount)
                || (args.commitment && !sameFelt(pending.commitment, args.commitment))) {
                throw new Error('The deposit secret does not match this browser’s durable pending deposit.');
            }
            let state = await this.worker.call('confirmDeposit', {
                config: this.config.wallet_core,
                args: {
                    secret: args.secret,
                    note_id: Number(args.note_id),
                    amount: Number(args.amount),
                    expiry_ts: Number(args.expiry_ts)
                }
            });
            // Amendment A1: the path the deposit used, at the root it set (the
            // NoteDeposited newRoot), proves exits for the note's whole life:
            // the vault accepts any root it ever held. Kept only if it leads
            // from this note's leaf to that root.
            const depositPath = await this.verifiedDepositPath(state, args.deposit_root, pending.zero_path);
            if (depositPath) state = { ...state, deposit_path: depositPath };
            await this.commit({
                ...this.runtime,
                state,
                stateSeq: 1,
                exitLock: null,
                journal: null,
                pendingDeposit: null,
                preparedWithdrawal: null
            }, {
                depositConfirmation: {
                    operationId: pending.operationId,
                    createdAt: pending.createdAt || pending.submissionStartedAt || null,
                    confirmedAt: Date.now(),
                    // A saved attempt may have been replaced. Only the receipt
                    // caller identifies the actual mined transaction; recovery
                    // from the vault alone intentionally leaves it unknown.
                    transactionHash: args.transactionHash || null,
                    ...(args.receiptMetadata || {})
                }
            });
            // The atomic note/history write is the confirmation boundary.
            // A later worker status refresh must not turn this exact committed
            // deposit into a reported funding failure or authorize resubmission.
            return {
                status: 'confirmed',
                operationId: pending.operationId,
                noteId: Number(args.note_id),
                amount: Number(args.amount),
                transactionHash: args.transactionHash || null
            };
        });
    }

    /**
     * The confirmed deposit record of the active note when that note is the
     * one `args` confirms: the same note id, deposit amount and secret (the
     * secret fixes the registration commitment), and a confirmed record for
     * this deployment that carries `args.operationId`. Anything else is null.
     */
    confirmedDepositFor(args) {
        const state = this.runtime.state;
        if (!state || typeof args?.operationId !== 'string' || !args.operationId) return null;
        const secret = state.secret_s;
        if (Number(state.note_id) !== Number(args.note_id)
            || Number(state.deposit_amount) !== Number(args.amount)
            || secret == null || args.secret == null
            || !(secret === args.secret || sameFelt(secret, args.secret))) return null;
        const record = (this.deposits || []).find(deposit => deposit.type === 'deposit'
            && deposit.status === 'confirmed'
            && deposit.deploymentId === this.manifest.deployment_id
            && Number(deposit.noteId) === Number(args.note_id));
        return record?.operationId === args.operationId ? record : null;
    }

    /**
     * Finish a confirmation whose note another path (the background vault
     * recovery) already committed: fill in the receipt-only fields that path
     * could not know (the transaction hash and fee on the deposit record, and
     * the note's deposit path of Amendment A1 from the receipt's
     * NoteDeposited root and `args.zero_path`, the plan's siblings, since the
     * pending deposit that held them is gone), then return what a fresh
     * confirmation returns, so both orders of the race end in the same
     * durable state. Called under the wallet lock.
     */
    async completeConfirmedDeposit(record, args) {
        const metadata = args.receiptMetadata || {};
        const transactionHash = args.transactionHash || metadata.transactionHash || null;
        const missingHash = !record.transactionHash && /^0x[0-9a-fA-F]{64}$/.test(transactionHash || '');
        const missingFee = record.feeWei == null && metadata.feeWei != null
            && (!record.transactionHash || !transactionHash
                || record.transactionHash === String(transactionHash).toLowerCase());
        const state = this.runtime.state;
        const depositPath = !state.deposit_path && args.deposit_root != null
            ? await this.verifiedDepositPath(state, args.deposit_root, args.zero_path)
            : null;
        if (missingHash || missingFee || depositPath) {
            await this.commit({ ...this.runtime, ...(depositPath ? { state: { ...state, deposit_path: depositPath } } : {}) },
                missingHash || missingFee ? {
                    depositConfirmation: {
                        operationId: record.operationId,
                        createdAt: record.createdAt,
                        confirmedAt: record.confirmedAt,
                        transactionHash,
                        ...metadata
                    }
                } : undefined);
        }
        return {
            status: 'confirmed',
            operationId: record.operationId,
            noteId: Number(args.note_id),
            amount: Number(args.amount),
            transactionHash: transactionHash || record.transactionHash || null
        };
    }

    /** The deposit-time Merkle path, when it leads from the note's leaf to `root`. */
    async verifiedDepositPath(state, root, siblings) {
        if (root == null || !Array.isArray(siblings) || siblings.length !== 32) return null;
        let activeRoot;
        try {
            activeRoot = `0x${BigInt(root).toString(16).padStart(64, '0')}`;
        } catch {
            return null;
        }
        const path = { active_root: activeRoot, siblings: siblings.map(String) };
        try {
            return await this.worker.call('notePathMatches', { state, path }) === true ? path : null;
        } catch {
            return null;
        }
    }

    async nativeBillingQuote(signal) {
        const funding = this.config.funding;
        const quoted = await this.remoteJson(`${funding.protocol_server_url}/v2/billing/quote`, { signal });
        validateNativeQuote(quoted, funding);
        const verified = await readNativeQuote(funding, { expected: quoted, signal });
        this.ethUsdQuote = verified;
        return verified;
    }

    leaseBudget(spendingLimitUsd, quote = null, { checkBalance = false } = {}) {
        if (!CHAT_SPENDING_TIER_USD.includes(Number(spendingLimitUsd))) throw new Error('Invalid private-balance model budget configuration.');
        validateNativeQuote(quote, this.config.funding, { allowExpired: true });
        const amount = Number(nativeUnitsForUsd(spendingLimitUsd, quote));
        if (checkBalance) {
            const balance = Number(this.runtime.state.current_balance);
            if (!Number.isSafeInteger(balance) || balance < 0) throw new Error('Invalid native ETH wallet balance.');
            if (amount < Number(this.config.request_charge_cap)) throw new Error('This model budget is below the deployment’s minimum private-chat budget.');
            if (balance < amount) {
                const error = new Error(`This model requires at least $${Number(spendingLimitUsd).toFixed(2)} in private balance for a new key. Choose a lower-cap model, or fund a larger balance.`);
                error.code = 'insufficient_chat_balance';
                error.required_credits = amount;
                error.required_balance_usd = Number(spendingLimitUsd);
                throw error;
            }
        }
        return amount;
    }

    async prepareLeaseRequest(onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        throwIfAborted(signal);
        if (!this.runtime.state) throw new Error('Fund a private balance before starting a chat.');
        if (unresolvedLateWithdrawalForNote(this.runtime, this.runtime.state.note_id)) {
            throw new BrowserWalletHttpError(
                'A withdrawal from another tab may already be on-chain. Check its status before using this balance.',
                409,
                'late_withdrawal_pending'
            );
        }
        if (this.runtime.journal) return this.runtime.journal.prepared_request;
        // C3: no request proof while the exit lock is held. A lock whose
        // released proofs are all dead is released here (E6); one never
        // released needs the user's cancel.
        if (this.runtime.exitLock) {
            const release = await this.releaseExitLockLocked();
            if (!release.released) throw this.exitLockedError(this.runtime.exitLock, release);
            if (release.installed || !this.runtime.state) {
                throw new BrowserWalletHttpError('The balance changed when its withdrawal ended. Send the message again.',
                    409, 'lease_pending');
            }
        }
        if (this.runtime.preparedWithdrawal) throw new Error('Finish the prepared withdrawal before sending another message.');
        // C4: a request whose settlement could run past the latest time to
        // start an exit is refused (from the note's own expiry_ts).
        if (nearExpiry({ now: nowSeconds(), settlementWindowSeconds: this.settlementWindowSeconds(),
            mustInitiateBy: mustInitiateBy(lowExpiry(this.runtime.state.expiry_ts)) })) {
            throw new BrowserWalletHttpError(NOTE_NEAR_EXPIRY_MESSAGE, 409, 'note_near_expiry');
        }
        // Fail closed before proving: every transmitted request needs an
        // archive identity, is never sent at a state the server is already
        // settling, and keeps the archive bounded.
        if (!this.archiveKey(this.runtime.state)) {
            throw new Error('The prepared request journal is incomplete.');
        }
        this.assertAnchorAcceptsRequest(this.runtime.state);
        onProgress('syncing', 'Checking your private balance…');
        const path = await this.treePath(this.runtime.state.note_id, true, null, signal);
        throwIfAborted(signal);
        const now = Date.now();
        const quote = await this.nativeBillingQuote(signal);
        throwIfAborted(signal);
        // C2: every request proof at a state carries the state's one bound.
        // Once a request at this state left the device, a later one reuses
        // its bound (a different bound would be refused by the prover).
        const selectedLimitCredits = this.leaseBudget(spendingLimitUsd, quote, { checkBalance: true });
        const boundAtState = Number(this.runtime.state.bound_at_state || 0);
        const spendingLimitCredits = boundAtState > 0 ? boundAtState : selectedLimitCredits;
        onProgress('proving', 'Proving this chat is funded…');
        const prepared = await this.worker.call('prepareRequest', {
            config: {
                ...this.config.wallet_core,
                request_charge_cap: spendingLimitCredits,
                policy_charge_cap: this.config.policy_enabled
                    ? spendingLimitCredits
                    : this.config.wallet_core.policy_charge_cap
            },
            state: this.runtime.state,
            args: {
                payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote }),
                active_root: path.active_root,
                merkle_siblings: path.siblings,
                client_request_id: uuid(),
                request_time: Math.floor(now / 1000),
                created_at_ms: now
            },
            provingKey: this.config.proving_keys.request
        });
        throwIfAborted(signal);
        const requestNullifier = prepared.request?.public_inputs?.request_nullifier;
        const record = this.tryRequestJournalRecord(prepared.journal, this.runtime.state);
        if (!record || (requestNullifier != null && !sameFelt(requestNullifier, prepared.journal.nullifier))
            || !sameStateExceptBound(prepared.state, this.runtime.state)
            || Number(prepared.state.bound_at_state) !== Number(prepared.request?.public_inputs?.solvency_bound)) {
            throw new Error('The prepared request journal is incomplete.');
        }
        // The state with its bound, the journal and its append-only archive
        // record land in ONE durable write before any POST can carry the
        // proof off this device (design §6.2).
        await this.commit({ ...this.runtime, state: withDepositPath(prepared.state, this.runtime.state),
            journal: prepared.journal }, { requestArchive: [record] });
        return prepared.request;
    }

    assertAnchorAcceptsRequest(state) {
        const key = this.archiveKey(state);
        // A signed successor archived as invalid (or held back by an exit
        // lock) means the server finalized this state's nullifier: a new
        // request would only replay it. Only withdrawing remains.
        if (key && requestRecordsAtState(this.requestArchive, key).some(entry =>
            [INVALID_SUCCESSOR_DISPOSITION, LATE_SUCCESSOR_DISPOSITION].includes(entry.disposition))) {
            throw new BrowserWalletHttpError(INVALID_SUCCESSOR_MESSAGE, 409, 'invalid_successor');
        }
        const journals = this.archivedRequestsAt(state)
            .filter(entry => entry.type === REQUEST_JOURNAL_TYPE);
        const finalized = journals.map(lastDefinitiveObservation)
            .find(observed => observed?.status === 'finalized');
        if (finalized) {
            const installable = journals.some(entry => entry.clientRequestId === finalized.clientRequestId
                && entry.journal?.user_rerandomization != null && entry.journal?.prepared_request);
            throw new BrowserWalletHttpError(installable
                ? 'A settled private request receipt must be applied to this balance first. Try again in a moment.'
                : RECEIPT_UNRECOVERABLE_MESSAGE,
            409, installable ? 'receipt_pending_install' : 'receipt_unrecoverable',
            { nullifier_status: 'finalized' });
        }
        // Every request at one state shares its nullifier, so a new proof would
        // only be a replay of a reservation the server already holds.
        if (journals.some(entry => lastDefinitiveObservation(entry)?.status === 'reserved')) {
            throw new BrowserWalletHttpError(
                'The server is still settling an earlier private request for this balance. Try again after it settles.',
                409,
                'request_settlement_pending',
                { nullifier_status: 'reserved' }
            );
        }
        if (key && !anchorArchiveCapacity(this.requestArchive, key).available) {
            throw new BrowserWalletHttpError(REQUEST_ARCHIVE_LIMIT_MESSAGE, 409, 'request_archive_limit');
        }
    }

    async verifyLease(lease, expectedLimitCredits, expectedRequestId, onProgress = () => {}, signal = null, expectedQuote = null, {
        proofBoundQuote = false
    } = {}) {
        throwIfAborted(signal);
        if (lease.status !== 'active'
            || lease.client_request_id !== expectedRequestId
            || !lease.api_key
            || Number(lease.expires_at) <= Math.floor(Date.now() / 1000)) {
            throw new Error('The zkAPI server returned an unusable OpenRouter lease.');
        }
        // A durable proof made under older price-feed pins keeps its own quote;
        // it is never re-validated against the current pins, only matched.
        if (proofBoundQuote) validateProofBoundQuote(expectedQuote, this.config.funding);
        else validateNativeQuote(expectedQuote, this.config.funding, { allowExpired: true });
        if (!sameNativeQuote(lease.billing_quote, expectedQuote)
            || Number(lease.spending_limit_usd) !== Number(nativeUsdMicros(expectedLimitCredits, expectedQuote)) / 1_000_000) {
            throw new Error('The zkAPI server returned a child key with the wrong native ETH spending cap or quote.');
        }
        exactTrustedUrl(lease.openrouter_api_base, this.config.openrouter.inference_base, 'OpenRouter inference origin');
        if (this.config.openrouter.require_oa_key_source && lease.key_source !== 'oa_org') {
            throw new Error('Client policy requires an OA verifier-backed ephemeral key.');
        }
        if (lease.key_source === 'oa_org') {
            onProgress('verifying', 'Verifying the new private key with OA…');
            const evidence = lease.verification;
            if (!evidence?.station_id || !evidence.station_signature || !evidence.org_signature) {
                throw new Error('The OA lease omitted its verification evidence.');
            }
            exactTrustedUrl(evidence.verifier_url, this.config.openrouter.verifier_url, 'OA verifier');
            if (Number(evidence.key_valid_till) < Number(lease.expires_at)
                || Number(evidence.key_valid_till) - Number(lease.expires_at) > 60) {
                throw new Error('The OA evidence expiry does not safely cover the lease.');
            }
            const verification = await this.remoteJson(`${this.config.openrouter.verifier_url}/submit_key`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                signal,
                body: JSON.stringify({
                    station_id: evidence.station_id,
                    api_key: lease.api_key,
                    key_valid_till: evidence.key_valid_till,
                    station_signature: evidence.station_signature,
                    org_signature: evidence.org_signature
                })
            });
            if (verification.status !== 'verified') throw new Error('The trusted OA verifier rejected the ephemeral key.');
        }
    }

    async requestLeaseWithRetry(request, onProgress = () => {}, signal = null, retryOptions = {}) {
        const maxWaitMs = retryOptions.maxWaitMs ?? LEASE_ISSUE_MAX_WAIT_MS;
        const maxAttempts = retryOptions.maxAttempts ?? LEASE_ISSUE_MAX_ATTEMPTS;
        const initialRetryMs = retryOptions.initialRetryMs ?? LEASE_ISSUE_INITIAL_RETRY_MS;
        const maxRetryMs = retryOptions.maxRetryMs ?? LEASE_ISSUE_MAX_RETRY_MS;
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;

        while (true) {
            throwIfAborted(signal);
            onProgress(
                'requesting',
                attempt === 1
                    ? 'Creating a temporary key for this chat…'
                    : 'Retrying temporary key creation…'
            );
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    signal,
                    body
                });
            } catch (error) {
                throwIfAborted(signal);
                const backoffDelayMs = Math.min(
                    initialRetryMs * (2 ** Math.max(0, attempt - 1)),
                    maxRetryMs
                );
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseError(error)
                    || attempt >= maxAttempts
                    || now() + retryDelayMs > deadline) {
                    makeLeaseRateLimitActionable(error, advertisedRetryMs);
                    throw error;
                }

                const waitLabel = retryDelayMs < 1_000 ? 'a moment' : describeRetryDelay(retryDelayMs);
                onProgress(
                    'waiting',
                    isLeaseRateLimit(error)
                        ? `OA is briefly limiting new temporary keys. Retrying in ${waitLabel}…`
                        : `The temporary-key service is briefly unavailable. Retrying in ${waitLabel}…`
                );
                throwIfAborted(signal);
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async requestLeaseWithQuoteRecovery(request, onProgress, signal) {
        try {
            return await this.requestLeaseWithRetry(request, onProgress, signal);
        } catch (error) {
            if (['native_quote_expired', 'native_quote_superseded'].includes(error?.code)) {
                await this.recoverUnacceptedNativeQuote(request, signal);
            } else if (error?.code === 'stale_root') {
                return this.recoverStaleRootRequest(request, error, onProgress, signal);
            }
            throw error;
        }
    }

    /** One word of the pinned vault, read over the trusted deployment RPC. */
    async vaultWord(data, signal = null) {
        const timeout = AbortSignal.timeout(this.exitTiming().callTimeoutMs);
        const callSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
        return abortable(readVaultWord(this.config.funding, data, { signal: callSignal }), callSignal);
    }

    /**
     * An unsigned stale_root reply alone never discards a transmitted journal.
     * The pinned chain is the first witness: while the vault still has this
     * proof's root, the server lags (or misreports), so the byte-identical
     * request is retried. Only when the chain confirms the root moved (or
     * cannot be read) is the server's own nullifier record consulted, and only
     * an "unknown" reading discards the journal, into the archive.
     */
    async recoverStaleRootRequest(request, error, onProgress = () => {}, signal = null, {
        delays = STALE_ROOT_RETRY_DELAYS_MS,
        sleep = delay
    } = {}) {
        const journal = this.runtime?.journal;
        if (!journal || JSON.stringify(request) !== JSON.stringify(journal.prepared_request)) throw error;
        let failure = error;
        for (const wait of [...delays, null]) {
            let chainRoot = null;
            try {
                chainRoot = await this.vaultWord(VAULT_SELECTORS.currentRoot, signal);
            } catch (readError) {
                if (isAbortError(readError, signal)) throw readError;
            }
            if (chainRoot == null || !sameFelt(chainRoot, request.public_inputs?.active_root)) break;
            if (wait == null) {
                failure.journalRetained = true;
                throw failure;
            }
            onProgress('waiting', 'The private service is catching up with the vault. Retrying the same request…');
            await sleep(wait, signal);
            try {
                return await this.requestLeaseWithRetry(request, onProgress, signal);
            } catch (retryError) {
                if (['native_quote_expired', 'native_quote_superseded'].includes(retryError?.code)) {
                    await this.recoverUnacceptedNativeQuote(request, signal);
                }
                if (retryError?.code !== 'stale_root') throw retryError;
                failure = retryError;
            }
        }
        const state = this.runtime.state;
        const observed = await this.nullifierServerStatus(journal.nullifier, signal);
        const record = this.tryRequestJournalRecord(journal, state);
        if (observed.status === 'finalized' && observed.response) {
            // Install the verified receipt; the caller then proves at the new state.
            await this.saveRequestObservations(this.archivedRequestsAt(state), observed, 'stale_root');
            failure.receiptInstalled = await this.installRecoveredResponse(
                observed.response.client_request_id || journalClientRequestId(journal),
                onProgress,
                { response: observed.response }
            );
            throw failure;
        }
        if (observed.status === 'unknown' && record) {
            await this.commit({ ...this.runtime, journal: null }, { requestArchive: [{
                ...record,
                disposition: 'discarded_stale_root',
                serverObservations: [requestObservation('unknown', 'stale_root')]
            }] });
            throw failure;
        }
        await this.saveRequestObservations(this.archivedRequestsAt(state), observed, 'stale_root');
        failure.journalRetained = true;
        failure.nullifierStatus = observed.status;
        throw failure;
    }

    /**
     * The server's own record for a nullifier. Only 'unknown', 'reserved',
     * 'finalized' (with its response) and 'clearance_reserved' are readings;
     * every failure is 'unavailable'. A 401 maps to testnet_password_required
     * when the caller can prompt for the password.
     */
    async nullifierServerStatus(nullifier, signal = null, { propagateAuth = false } = {}) {
        let recovery;
        try {
            recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(nullifier)}`, { signal });
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            if (propagateAuth && (error?.code === 'testnet_password_required'
                || (error?.status === 401 && this.testnetAuth?.enabled))) {
                throw error?.code === 'testnet_password_required' ? error : testnetPasswordRequired();
            }
            return { status: 'unavailable', response: null };
        }
        return nullifierReading(recovery);
    }

    async issueLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        // Exit-only mode refuses new private chats (initialize()).
        await this.assertServiceAvailable();
        throwIfAborted(signal);
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            throwIfAborted(signal);
            await this.reload();
            throwIfAborted(signal);
            onProgress('checking', 'Checking for unfinished private activity…');
            const reportRecovery = (phase, message) => onProgress(phase, message, 'recovery');
            await this.recoverPendingLocked({
                retireLostKey: true,
                onProgress: reportRecovery,
                signal,
                sweep: true
            });
            let request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);

            // A browser can restart with a durable proof made under an older
            // spending policy or older price-feed pins. Finish that
            // byte-identical request safely, but never expose its key to the
            // host application. Settle it unused, install the signed receipt,
            // then prove the selected budget.
            let desiredLimitCredits = null;
            try {
                desiredLimitCredits = this.leaseBudget(spendingLimitUsd, requestBillingQuote(request));
            } catch {
                // Its proof-bound quote predates the current pins.
            }
            if (desiredLimitCredits == null
                || Number(request.public_inputs.solvency_bound) !== desiredLimitCredits) {
                try {
                    this.legacyMigrationInProgress = true;
                    reportRecovery('settling', 'Updating an unfinished temporary key…');
                    const legacyLease = await this.requestLeaseWithQuoteRecovery(request, reportRecovery, signal);
                    await this.verifyLease(
                        legacyLease,
                        request.public_inputs.solvency_bound,
                        request.client_request_id,
                        reportRecovery,
                        signal,
                        requestBillingQuote(request),
                        { proofBoundQuote: true }
                    );
                    // Persist recovery metadata, but deliberately never assign
                    // this legacy-cap key to activeLease. It cannot be returned
                    // to inference even if settlement needs a later retry.
                    await this.commit({
                        ...this.runtime,
                        lease: {
                            ownerId: this.ownerId,
                            sessionId,
                            client_request_id: legacyLease.client_request_id,
                            expires_at: Number(legacyLease.expires_at),
                            settle_after: Number(legacyLease.settle_after),
                            spending_limit_usd: Number(legacyLease.spending_limit_usd)
                        }
                    });
                    reportRecovery('usage', 'Closing the unfinished temporary key…');
                    const status = await this.retireRequest(
                        legacyLease.client_request_id,
                        request,
                        signal
                    );
                    if (status.status !== 'finalized') {
                        throw new Error(`Lease is still ${status.status}.`);
                    }
                    const installed = await this.installRecoveredResponse(
                        legacyLease.client_request_id,
                        reportRecovery,
                        { signal }
                    );
                    if (!installed) throw new Error('The legacy private-key receipt is not ready yet.');
                } finally {
                    this.legacyMigrationInProgress = false;
                }
                await this.reload();
                request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);
            }
            // stale_root is reconciled inside (chain witness, then corroboration);
            // a server error string alone never clears the transmitted journal.
            const lease = await this.requestLeaseWithQuoteRecovery(request, onProgress, signal);
            await this.verifyLease(
                lease,
                request.public_inputs.solvency_bound,
                request.client_request_id,
                onProgress,
                signal,
                requestBillingQuote(request)
            );
            throwIfAborted(signal);
            const activeLease = {
                ...lease,
                sessionId,
                selectedSpendingLimitUsd: Number(spendingLimitUsd),
                inFlight: 0
            };
            await this.commit({
                ...this.runtime,
                lease: {
                    ownerId: this.ownerId,
                    sessionId,
                    client_request_id: lease.client_request_id,
                    expires_at: Number(lease.expires_at),
                    settle_after: Number(lease.settle_after),
                    spending_limit_usd: Number(lease.spending_limit_usd)
                }
            });
            this.activeLease = activeLease;
            this.settlementFailures = 0;
            this.dispatchEvent(new Event('change'));
            this.scheduleSettlement();
            onProgress('ready', 'Private chat ready.');
            return this.activeLease;
        });
    }

    addLeaseProgressListener(listener, { replay = true } = {}) {
        if (typeof listener !== 'function') return () => {};
        // Each registration gets a distinct token so two callers that happen
        // to pass the same callback can unsubscribe independently.
        const registration = (phase, message, kind) => listener(phase, message, kind);
        this.leaseProgressListeners.add(registration);
        if (replay && this.lastLeaseProgress) {
            const { phase, message, kind } = this.lastLeaseProgress;
            try {
                registration(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
        return () => this.leaseProgressListeners.delete(registration);
    }

    reportLeaseProgress(phase, message, kind = 'access') {
        this.lastLeaseProgress = { phase, message, kind };
        for (const listener of this.leaseProgressListeners) {
            try {
                listener(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
    }

    async waitForLeasePromise(normalizedSessionId, onProgress, signal, spendingLimitUsd = 1) {
        const leasePromise = this.leasePromise;
        if (!leasePromise) return null;
        if (this.leasePromiseSession !== normalizedSessionId) {
            throw new BrowserWalletHttpError(
                `Chat ${this.leasePromiseSession} is creating the current private key.`,
                409,
                'lease_session_conflict'
            );
        }

        if (this.leasePromiseSpendingLimitUsd !== spendingLimitUsd) {
            throw new BrowserWalletHttpError(
                'A different model budget is being prepared. Retry when the current request finishes.',
                409,
                'lease_budget_conflict'
            );
        }

        throwIfAborted(signal);
        const unsubscribe = this.addLeaseProgressListener(onProgress);
        this.leaseWaiterCount += 1;
        let abortHandler = null;
        try {
            if (!signal) return await leasePromise;
            const canceled = new Promise((_, reject) => {
                abortHandler = () => {
                    try {
                        throwIfAborted(signal);
                    } catch (error) {
                        reject(error);
                    }
                };
                signal.addEventListener('abort', abortHandler, { once: true });
            });
            return await Promise.race([leasePromise, canceled]);
        } finally {
            if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
            unsubscribe();
            this.leaseWaiterCount = Math.max(0, this.leaseWaiterCount - 1);
            if (signal?.aborted
                && this.leasePromise === leasePromise
                && this.leaseWaiterCount === 0) {
                this.leaseAbortController?.abort();
            }
        }
    }

    async ensureLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        throwIfAborted(signal);
        await this.init();
        throwIfAborted(signal);
        const normalized = String(sessionId || 'default').slice(0, 160);
        spendingLimitUsd = Number(spendingLimitUsd);
        if (!CHAT_SPENDING_TIER_USD.includes(spendingLimitUsd)) throw new Error('Invalid private-balance model budget configuration.');
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        const now = Math.floor(Date.now() / 1000);
        const isSafeForNewRequest = this.activeLease
            && Number(this.activeLease.expires_at) > now + MIN_REQUEST_LEASE_REMAINING_SECONDS;
        const activeLeaseMatchesPolicy = this.activeLease?.selectedSpendingLimitUsd === spendingLimitUsd;
        if (this.activeLease
            && isSafeForNewRequest
            && activeLeaseMatchesPolicy
            && !this.activeLease.retiring
            && !this.activeLease.retired) {
            if (this.activeLease.sessionId !== normalized) {
                throw new BrowserWalletHttpError(
                    `Chat ${this.activeLease.sessionId} owns the current private key until it settles.`,
                    409,
                    'lease_session_conflict'
                );
            }
            onProgress('ready', 'Private chat ready.', 'access');
            return this.activeLease;
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the current requests to finish before renewing or changing the private key budget.',
                409,
                'lease_requests_in_flight'
            );
        }
        await this.reload();
        if (this.runtime.lease
            && Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) > now
            && this.runtime.lease.ownerId !== this.ownerId) {
            throw new BrowserWalletHttpError(
                `Another browser tab owns the current private key until ${new Date(Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) * 1000).toLocaleTimeString()}.`,
                409,
                'lease_tab_conflict'
            );
        }
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        this.leasePromiseSession = normalized;
        this.leasePromiseSpendingLimitUsd = spendingLimitUsd;
        this.lastLeaseProgress = null;
        const jobKind = this.activeLease ? 'renewal' : 'access';
        const controller = new AbortController();
        this.leaseAbortController = controller;
        let leasePromise;
        leasePromise = (async () => {
            if (this.activeLease) {
                await this.retireActiveLease(
                    (phase, message) => this.reportLeaseProgress(phase, message, 'renewal')
                );
            }
            return this.issueLease(
                normalized,
                (phase, message, kind = 'access') => this.reportLeaseProgress(
                    phase,
                    message,
                    kind === 'access' ? jobKind : kind
                ),
                controller.signal,
                spendingLimitUsd
            );
        })().finally(() => {
            if (this.leasePromise === leasePromise) {
                this.leasePromise = null;
                this.leasePromiseSession = null;
                this.leasePromiseSpendingLimitUsd = null;
                this.leaseAbortController = null;
                this.lastLeaseProgress = null;
            }
        });
        this.leasePromise = leasePromise;
        return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
    }

    scheduleSettlement(delayOverrideMs = null) {
        if (!this.activeLease) return;
        if (this.settlementTimer) clearTimeout(this.settlementTimer);
        const delayMs = delayOverrideMs ?? Math.max(
            0,
            Number(this.activeLease.settle_after) * 1000 - Date.now() + 250
        );
        this.settlementTimer = setTimeout(() => {
            this.settlementTimer = null;
            if (!this.activeLease) return;
            if (this.activeLease.inFlight > 0) {
                this.scheduleSettlement(500);
                return;
            }
            void this.retireActiveLease().then(() => {
                this.settlementFailures = 0;
            }, () => {
                // A settlement that keeps failing backs off instead of
                // polling the server every two seconds forever.
                this.settlementFailures += 1;
                if (this.activeLease) {
                    this.scheduleSettlement(Math.min(SETTLEMENT_RETRY_MAX_MS,
                        SETTLEMENT_RETRY_MIN_MS * (2 ** Math.min(this.settlementFailures - 1, 5))));
                }
            });
        }, Math.min(delayMs, 2_147_000_000));
    }

    async retireRequest(clientRequestId, request, signal, retryOptions = {}) {
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const maxWaitMs = retryOptions.maxWaitMs ?? MAX_RECOVERY_WAIT_MS;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;
        while (true) {
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(clientRequestId)}`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body,
                    signal
                });
            } catch (error) {
                const backoffDelayMs = Math.min(1_000 * (2 ** Math.max(0, attempt - 1)), 10_000);
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseRetirementError(error)
                    || now() + retryDelayMs > deadline) {
                    throw error;
                }
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async retireActiveLease(onProgress = () => {}) {
        if (this.retirementPromise) return this.retirementPromise;
        if (!this.activeLease || !this.runtime?.journal) return;
        if (this.activeLease.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        const lease = this.activeLease;
        lease.retiring = true;
        onProgress('settling', 'Closing the temporary key from the previous chat…');
        const retireWithinLock = async () => {
            await this.reload();
            const request = this.runtime.journal?.prepared_request;
            if (!request || request.client_request_id !== lease.client_request_id) return;
            onProgress('usage', 'Confirming the previous chat’s usage…');
            const status = await this.retireRequest(lease.client_request_id, request);
            if (status.status !== 'finalized') throw new Error(`Lease is still ${status.status}.`);
            // The remote key is now disabled. Make that transition
            // irreversible locally before receipt installation, which can
            // still fail independently and be retried from the durable journal.
            lease.retired = true;
            if (this.activeLease === lease) this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            this.dispatchEvent(new Event('change'));
            return this.installRecoveredResponse(lease.client_request_id, onProgress);
        };
        const retirement = (async () => {
            const installed = await withBrowserWalletLock(
                this.manifest.deployment_id,
                retireWithinLock
            );
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            // installRecoveredResponse commits and notifies. Only publish here
            // when there was no recovered response (and therefore no commit).
            if (!installed) this.dispatchEvent(new Event('change'));
            return installed;
        })();
        this.retirementPromise = retirement;
        try {
            return await retirement;
        } finally {
            if (this.activeLease === lease) lease.retiring = false;
            if (this.retirementPromise === retirement) this.retirementPromise = null;
        }
    }

    async settleActiveLease(onProgress = () => {}) {
        await this.init();
        if (this.retirementPromise) {
            try {
                await this.retirementPromise;
            } catch {
                // The durable journal remains recoverable below even if the
                // first receipt-installation attempt failed.
            }
        }
        if (this.legacyMigrationInProgress) {
            throw new BrowserWalletHttpError(
                'An unfinished private key is already being updated. Try settling again in a moment.',
                409,
                'lease_pending'
            );
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        if (this.activeLease) {
            await this.retireActiveLease(onProgress);
        } else {
            await this.reload();
            await this.recoverPending({ retireLostKey: true, onProgress });
        }
        await this.reload();
        if (this.runtime.journal) {
            throw new BrowserWalletHttpError(
                'The private key usage receipt is still being finalized. Try settling again shortly.',
                409,
                'lease_pending'
            );
        }
        this.activeLease = null;
        return this.walletStatus();
    }

    async settleSessionLease(sessionId, onProgress = () => {}) {
        await this.init();
        if (this.activeLease?.sessionId === sessionId) {
            // retireActiveLease captures the exact request and checks it again
            // under the wallet lock before publishing its settlement.
            await this.retireActiveLease(onProgress);
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            // A different tab may have opened a key after our first owner read.
            // Recovery must never retire that tab's new lease.
            if (this.runtime?.lease?.sessionId !== sessionId) return;
            await this.recoverPendingLocked({ retireLostKey: true, onProgress });
            if (this.runtime?.journal && this.runtime?.lease?.sessionId === sessionId) {
                throw new BrowserWalletHttpError('This chat’s private key is still being finalized. Try again shortly.',
                    409, 'lease_pending');
            }
        });
    }

    /**
     * Install a finalized, signed receipt. The response selects its journal:
     * the live one, or an archived one at this state that still holds its
     * private rerandomization (a discarded, evicted, abandoned or late request
     * the server finalized later). completeResponse checks S1–S6 (design
     * §6.1) before the ONE commit that installs it. A correctly signed
     * successor that fails S3, S4 or S5 is archived as invalid_successor and
     * treated as withheld. While an exit proof released from this state can
     * still land, a valid successor is archived as late_successor instead and
     * installs when the exit lock is released (E4.6, E6); this returns
     * LATE_SUCCESSOR then. An install moves an exit lock that released no
     * exit proof to the new state.
     */
    async installRecoveredResponse(clientRequestId, onProgress = () => {}, { response = null, signal = null } = {}) {
        onProgress('applying', 'Updating your private balance…');
        let receipt = response;
        const fetched = !receipt;
        if (fetched) {
            const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/requests/${encodeURIComponent(clientRequestId)}`, { signal });
            if (!recovery.request_response) return false;
            receipt = recovery.request_response;
        }
        const state = this.runtime.state;
        const current = this.runtime.journal;
        const responseId = typeof receipt.client_request_id === 'string' && receipt.client_request_id
            ? receipt.client_request_id
            : null;
        let journal = null;
        if (current && (!responseId || journalClientRequestId(current) === responseId)) {
            journal = current;
        } else if (responseId) {
            journal = this.archivedRequestsAt(state).find(entry => entry.type === REQUEST_JOURNAL_TYPE
                && entry.clientRequestId === responseId && entry.journal?.user_rerandomization != null
                && entry.journal?.prepared_request)?.journal || null;
        }
        if (!journal) {
            // A caller that passed the receipt saved the nullifier reading it
            // came with. One fetched by request id is saved here, so the
            // snapshot's override warning follows this claim too.
            if (fetched) {
                await this.saveRequestObservations(this.archivedRequestsAt(state),
                    { status: 'finalized', response: receipt }, 'recovery');
            }
            throw new BrowserWalletHttpError(RECEIPT_UNRECOVERABLE_MESSAGE, 409, 'receipt_unrecoverable',
                { nullifier_status: 'finalized' });
        }
        // The quote was validated against the pins when the proof was made; a
        // receipt only has to carry exactly that proof-bound quote.
        const quote = requestBillingQuote(journal.prepared_request);
        validateProofBoundQuote(quote, this.config.funding);
        let payload;
        try { payload = JSON.parse(receipt.response_payload); } catch { /* Reject below. */ }
        if (!sameNativeQuote(payload?.billing_quote, quote)) throw new Error('The settlement receipt changed the authorized ETH/USD quote.');
        const lock = this.runtime.exitLock;
        const lockHere = Boolean(lock && state && Number(lock.noteId) === Number(state.note_id)
            && sameFelt(lock.anchor, state.current_anchor));
        const exitProofLive = lockHere && releasedExitProofs(lock).length > 0;
        const prepared = this.runtime.preparedWithdrawal;
        if (!exitProofLive && (preparedWithdrawalHasSubmission(prepared)
            || (state && unresolvedLateWithdrawalForNote(this.runtime, state.note_id)))) {
            throw new BrowserWalletHttpError(
                'A withdrawal transaction for this balance is still unresolved. Check it before applying a settled private request.',
                409,
                'withdrawal_submission_pending'
            );
        }
        let next;
        try {
            next = await this.worker.call('completeResponse', {
                config: this.config.wallet_core,
                args: {
                    state,
                    journal,
                    response: receipt
                }
            });
        } catch (error) {
            throw await this.successorRefusal(error, { state, journal, current, receipt });
        }
        const live = Boolean(current) && journalClientRequestId(current) === journalClientRequestId(journal);
        if (exitProofLive) {
            // C3: while a released exit proof can land, the client never
            // spends this state's successor. It installs after E6.
            const record = this.tryRequestJournalRecord(journal, state, { disposition: LATE_SUCCESSOR_DISPOSITION });
            if (!record) throw new Error('The late private request journal is incomplete.');
            await this.commit({ ...this.runtime, ...(live ? { journal: null, lease: null } : {}) },
                { requestArchive: [{ ...record, lateResponse: receipt, lateAt: Date.now() }] });
            return LATE_SUCCESSOR;
        }
        // An unsubmitted withdrawal plan or clearance marker was bound to the
        // consumed state's nullifier; the next state starts clean. A lock that
        // released no exit proof moves with the note (E3.2, E4.3).
        const exitLock = lockHere
            ? { ...lock, anchor: next.current_anchor, since: nowSeconds(), released: [] }
            : lock || null;
        await this.commit({
            ...this.runtime,
            state: withDepositPath(next, state),
            stateSeq: Number(this.runtime.stateSeq || 0) + 1,
            exitLock,
            journal: null,
            lease: null,
            preparedWithdrawal: null
        }, {
            requestArchive: this.installArchiveUpdates({ state, journal, current, next, receipt, payload })
        });
        return true;
    }

    /**
     * The refusal of a successor that failed S1–S6. One that fails S3, S4 or
     * S5 although signed is archived as invalid_successor and treated as
     * withheld (design §6.1); an unsigned one is no operator answer at all.
     */
    async successorRefusal(error, { state, journal, current, receipt }) {
        const message = String(error?.message || error || '');
        if (message.startsWith('invalid_successor')) {
            const check = /^invalid_successor: (S[345])/.exec(message)?.[1] || null;
            const record = this.tryRequestJournalRecord(journal, state, { disposition: INVALID_SUCCESSOR_DISPOSITION });
            const live = Boolean(current) && journalClientRequestId(current) === journalClientRequestId(journal);
            if (record) {
                try {
                    await this.commit({ ...this.runtime, ...(live ? { journal: null, lease: null } : {}) }, {
                        requestArchive: [{ ...record, invalidCheck: check, invalidReason: message.slice(0, 300),
                            chargeApplied: Number.isSafeInteger(Number(receipt?.charge_applied)) ? Number(receipt.charge_applied) : null,
                            invalidAt: Date.now() }]
                    });
                } catch (commitError) {
                    console.warn('Unable to archive an invalid successor.', commitError);
                }
            }
            return new BrowserWalletHttpError(INVALID_SUCCESSOR_MESSAGE, 409, 'invalid_successor', { check });
        }
        if (message.startsWith('successor_signature_invalid')) {
            return new BrowserWalletHttpError('The settlement receipt is not signed by this deployment’s state key.',
                409, 'successor_signature_invalid');
        }
        return error;
    }

    installArchiveUpdates({ state, journal, current, next, receipt, payload }) {
        if (!this.archiveKey(state)) return [];
        const installedId = journalClientRequestId(journal);
        const now = Date.now();
        const updates = [];
        const installed = this.tryRequestJournalRecord(journal, state, { disposition: 'installed' });
        if (installed) {
            let nextAnchor = null;
            try { nextAnchor = feltKey(next?.current_anchor); } catch { /* Keep the audit field empty. */ }
            updates.push({
                ...installed,
                installedNextAnchor: nextAnchor,
                chargeApplied: Number.isSafeInteger(Number(receipt?.charge_applied)) ? Number(receipt.charge_applied) : null,
                chargeBasis: typeof payload?.charge_basis === 'string' ? payload.charge_basis : null,
                settlementReason: typeof payload?.settlement_reason === 'string' ? payload.settlement_reason : null,
                installedAt: now
            });
        }
        if (current && journalClientRequestId(current) !== installedId) {
            const superseded = this.tryRequestJournalRecord(current, state, { disposition: 'superseded' });
            if (superseded) updates.push(superseded);
        }
        // Every request at the consumed state shares its nullifier, which the
        // server has now finalized: none of them can install any more.
        for (const entry of this.archivedRequestsAt(state)) {
            if (!updates.some(update => update.archiveId === entry.archiveId)) {
                updates.push({ archiveId: entry.archiveId, disposition: 'superseded' });
            }
        }
        return updates;
    }

    async recoverPending(options = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.recoverPendingLocked(options);
        });
    }

    async recoverUnacceptedNativeQuote(request, signal = null) {
        const journal = this.runtime?.journal;
        const body = JSON.stringify(request);
        if (!request?.client_request_id || request.payload_hash == null
            || request.public_inputs?.request_nullifier == null
            || !sameFelt(journal?.nullifier, request.public_inputs.request_nullifier)
            || body !== JSON.stringify(journal?.prepared_request)) return false;
        validateProofBoundQuote(requestBillingQuote(request), this.config.funding);
        // This endpoint only observes quote validity and acceptance under the server's
        // issuance lock. Neither local time nor an unknown nullifier proves an
        // older in-flight request can no longer reserve the note.
        let recovery;
        try {
            recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}/expire`, {
                method: 'POST', headers: { 'content-type': 'application/json' }, signal, body
            });
        } catch (error) {
            if (error?.code === 'lease_pending') return false;
            throw error;
        }
        if (!['expired_unaccepted', 'superseded_unaccepted'].includes(recovery?.status)) return false;
        if (recovery.client_request_id !== request.client_request_id
            || recovery.request_nullifier == null || recovery.payload_hash == null
            || !sameFelt(recovery.request_nullifier, request.public_inputs.request_nullifier)
            || !sameFelt(recovery.payload_hash, request.payload_hash)) {
            throw new Error('The quote recovery response does not match the saved private request.');
        }
        if (body !== JSON.stringify(this.runtime?.journal?.prepared_request)
            || !sameFelt(this.runtime.journal.nullifier, request.public_inputs.request_nullifier)) return false;
        // The dedicated endpoint attested non-acceptance under the issuance
        // lock; the archive still remembers that this state was transmitted.
        // The answer only echoes this request's own identifiers, so it is
        // saved as 'unaccepted', never as a nullifier reading.
        const record = this.tryRequestJournalRecord(this.runtime.journal, this.runtime.state, {
            disposition: 'discarded_expired_unaccepted',
            observations: [requestObservation('unaccepted', 'recovery')]
        });
        await this.commit({ ...this.runtime, journal: null, lease: null },
            record ? { requestArchive: [record] } : {});
        return true;
    }

    /**
     * Recover an interrupted request journal. A quiet caller (initialization,
     * the escape override) never fails here, also when a receipt does not
     * install: its own gates decide again from a fresh reading, so an
     * unverifiable 'finalized' claim can neither break initialization nor
     * veto the override.
     */
    async recoverPendingLocked(options = {}) {
        try {
            return await this.recoverPendingJournalLocked(options);
        } catch (error) {
            if (!options?.quiet || isAbortError(error, options?.signal)) throw error;
            return false;
        }
    }

    async recoverPendingJournalLocked({
        retireLostKey = false,
        quiet = false,
        onProgress = () => {},
        signal = null,
        sweep = false
    } = {}) {
        throwIfAborted(signal);
        if (this.activeLease) return false;
        if (!this.runtime?.journal) {
            // User actions also look for a later-finalized receipt of a request
            // whose journal was discarded or abandoned. Never on page load.
            return sweep ? this.recoverArchivedRequestsLocked({ onProgress, signal }) : false;
        }
        const request = this.runtime.journal.prepared_request;
        try {
            const status = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}`, { signal });
            if (status.status === 'active') {
                if (!retireLostKey) return false;
                const ownershipDeadline = Number(
                    this.runtime.lease?.settle_after || this.runtime.lease?.expires_at
                );
                if (this.runtime.lease && ownershipDeadline > Math.floor(Date.now() / 1000)
                    && this.runtime.lease.ownerId !== this.ownerId) {
                    return false;
                }
                onProgress('settling', 'Finishing an interrupted private chat…');
                const retired = await this.retireRequest(request.client_request_id, request, signal);
                if (retired.status !== 'finalized') return false;
            } else if (status.status !== 'finalized') {
                // Revoking, disabled, cancelled or a future status: the nullifier
                // record is authoritative for a finalized receipt.
                return this.installFinalizedNullifierLocked(this.runtime.journal.nullifier, {
                    onProgress, signal, context: 'recovery'
                });
            }
            return this.installRecoveredResponse(request.client_request_id, onProgress, { signal });
        } catch (error) {
            if (error.status === 404) {
                const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(this.runtime.journal.nullifier)}`, { signal });
                const observed = nullifierReading(recovery);
                // Saved with every request at this state, so the snapshot's
                // override warning follows any receipt claim it carries. A
                // clearance reservation is saved below, with its discard.
                if (observed.status !== 'clearance_reserved') {
                    await this.saveRequestObservations(this.archivedRequestsAt(this.runtime.state), observed, 'recovery');
                }
                if (recovery.request_response) {
                    // A replayed request may have been finalized under an
                    // earlier, archived client request id.
                    return this.installRecoveredResponse(
                        recovery.request_response.client_request_id || request.client_request_id,
                        onProgress,
                        { response: recovery.request_response }
                    );
                }
                if (recovery.status === 'not_found'
                    && recovery.nullifier_status === 'unknown' && !recovery.request_response) {
                    try { return await this.recoverUnacceptedNativeQuote(request, signal); }
                    catch (recoveryError) {
                        if (!quiet) throw recoveryError;
                        return false;
                    }
                }
                if (recovery.nullifier_status === 'clearance_reserved') {
                    // Mutual-close preparation owns this deterministic state
                    // nullifier. The lease was never accepted, so discard only
                    // its orphaned request journal (into the archive) and keep
                    // the withdrawal-only note/intent intact.
                    const record = this.tryRequestJournalRecord(this.runtime.journal, this.runtime.state, {
                        disposition: 'discarded_clearance_reserved',
                        observations: [requestObservation('clearance_reserved', 'recovery')]
                    });
                    // The marker is bound to the current state's own nullifier.
                    const withdrawalNullifier = this.runtime.preparedWithdrawal || !this.runtime.state
                        ? null
                        : await this.worker.call('withdrawalNullifier', { state: this.runtime.state });
                    await this.commit({
                        ...this.runtime,
                        journal: null,
                        lease: null,
                        preparedWithdrawal: this.runtime.preparedWithdrawal || {
                            phase: 'reserving',
                            mode: 'mutual',
                            noteId: Number(this.runtime.state?.note_id),
                            destination: null,
                            withdrawalNullifier: withdrawalNullifier ?? this.runtime.journal.nullifier,
                            clearanceReserved: true,
                            createdAt: Date.now()
                        }
                    }, record ? { requestArchive: [record] } : {});
                    return true;
                }
            }
            if (!quiet) throw error;
            return false;
        }
    }

    /** Consult the server's nullifier record and install a finalized receipt. */
    async installFinalizedNullifierLocked(nullifier, { onProgress = () => {}, signal = null, context = 'recovery' } = {}) {
        const observed = await this.nullifierServerStatus(nullifier, signal);
        await this.saveRequestObservations(this.archivedRequestsAt(this.runtime.state), observed, context);
        if (observed.status !== 'finalized' || !observed.response) return false;
        return this.installRecoveredResponse(
            observed.response.client_request_id || journalClientRequestId(this.runtime.journal),
            onProgress,
            { response: observed.response }
        );
    }

    /**
     * Quiet sweep of archived requests at the selected state: one nullifier
     * read, then install if the server finalized one of them. It never
     * blocks the user's action and never runs on page load.
     */
    async recoverArchivedRequestsLocked({ onProgress = () => {}, signal = null } = {}) {
        const entries = this.archivedRequestsAt(this.runtime?.state);
        if (!entries.length) return false;
        try {
            return await this.installFinalizedNullifierLocked(entries[0].nullifier, {
                onProgress, signal, context: 'recovery'
            });
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            return false;
        }
    }

    async acquireEphemeralKey(sessionId, onProgress = () => {}, options = {}) {
        const signal = options.signal || null;
        const lease = await this.ensureLease(sessionId, onProgress, signal, options.spendingLimitUsd);
        throwIfAborted(signal);
        // Rotation may have started between ensureLease resolving and this
        // continuation. Retirement marks the old key synchronously, so check
        // ownership before checking it out and exposing its credential.
        if (this.activeLease !== lease || lease.retiring || lease.retired) {
            throw new BrowserWalletHttpError(
                'The previous private key is closing. Retry when its balance update finishes.',
                409,
                'lease_pending'
            );
        }
        lease.inFlight += 1;
        let released = false;
        return {
            mode: 'ephemeral-key',
            apiKey: lease.api_key,
            baseUrl: normalizeUrl(lease.openrouter_api_base),
            spendingLimitUsd: Number(lease.spending_limit_usd),
            headers: {
                authorization: `Bearer ${lease.api_key}`,
                'content-type': 'application/json',
                'http-referer': location.origin,
                'x-title': 'zkAPI'
            },
            release: () => {
                if (released) return;
                released = true;
                // A fetch resolves when headers arrive, not when an SSE body is
                // finished. Keep the lease checked out for the entire stream.
                lease.inFlight = Math.max(0, lease.inFlight - 1);
                if (lease.inFlight === 0
                    && Number(lease.settle_after) * 1000 <= Date.now()) {
                    this.scheduleSettlement(0);
                }
                this.dispatchEvent(new Event('change'));
            }
        };
    }

    // ---- Exits (design §6.3 C1–C5 and §6.4 E0–E7) ----
    //
    // Every exit decision runs under the one Web Lock (C1) and holds the
    // durable exit lock (runtime.exitLock) from before E1 until the note
    // closes or every released exit proof is dead (E6). While the exit lock
    // is held the wallet makes no request proof (C3). Operator calls in exit
    // mode have a hard timeout, count 5xx, 429 and timeouts as unreachable
    // and ignore Retry-After (E0); nothing waits past must_initiate_by.

    /** E0 timing, overridable per instance (tests shorten the budgets). */
    exitTiming() {
        return { ...EXIT_TIMING, ...(this.exitTimingOverrides || {}) };
    }

    /** The bound of one operator call outside exit mode (overridable per instance, like E0's). */
    operatorCallTimeoutMs() {
        const value = Number(this.exitTimingOverrides?.operatorCallTimeoutMs);
        return Number.isSafeInteger(value) && value > 0 ? value : OPERATOR_CALL_TIMEOUT_MS;
    }

    /** The build-pinned settlement window W (E0, C4). */
    settlementWindowSeconds() {
        const value = Number(this.browserConfig?.trusted_deployment?.settlement_window_seconds);
        return Number.isSafeInteger(value) && value > 0 ? value : DEFAULT_SETTLEMENT_WINDOW_SECONDS;
    }

    /** The build-pinned RPC as an EIP-1193-style request function. */
    pinnedRpc() {
        return pinnedRpcRequest(this.config.funding, { timeoutMs: this.exitTiming().callTimeoutMs });
    }

    /**
     * E4.5: an exit transaction's gas through the user's exit RPC, or null
     * when none is set or it refuses (advisory only).
     */
    async exitRpcEstimateGas(transaction) {
        const exit = this.exitRpcOnVaultChain();
        if (!exit) return null;
        try {
            const estimate = BigInt(await exit({ method: 'eth_estimateGas', params: [{ from: transaction.from,
                to: transaction.to, data: transaction.data }] }));
            return estimate > 0n ? estimate : null;
        } catch {
            return null;
        }
    }

    /** The user's exit RPC (persisted per origin), or null. */
    exitRpc() {
        const url = this.getExitRpcUrl();
        return url ? urlRpcRequest(url, { timeoutMs: this.exitTiming().callTimeoutMs }) : null;
    }

    /**
     * The user's exit RPC for one exit operation, used only on the vault's
     * chain: its first call asks eth_chainId, and an exit RPC on another
     * chain fails every call (exit_rpc_wrong_chain) before anything else is
     * asked, so each reader treats it as unavailable. The snapshot flags it
     * (exit_rpc_wrong_chain). Null when none is set.
     */
    exitRpcOnVaultChain() {
        const exit = this.exitRpc();
        if (!exit) return null;
        const url = this.getExitRpcUrl();
        return onChainRequest(exit, this.config.funding.chain_id, {
            code: 'exit_rpc_wrong_chain',
            message: 'The exit RPC is on another chain than the vault.',
            onChecked: matches => this.noteExitRpcChain(url, matches)
        });
    }

    /** Remember whether the exit RPC at `url` answered on the vault's chain. */
    noteExitRpcChain(url, matches) {
        const before = this.exitRpcChainCheck;
        this.exitRpcChainCheck = { url, matches };
        if (before?.url !== url || before?.matches !== matches) this.dispatchEvent(new Event('change'));
    }

    /**
     * The user's wallet provider (an EIP-1193 request function) for one exit
     * operation: each call bounded by E0's CALL_TIMEOUT, and used only on
     * the vault's chain (wallet_wrong_chain otherwise). Null without one.
     */
    walletOnVaultChain(walletRequest) {
        if (typeof walletRequest !== 'function') return null;
        return onChainRequest(boundedRequest(walletRequest, this.exitTiming().callTimeoutMs,
            'The wallet provider did not answer in time.'), this.config.funding.chain_id, {
            code: 'wallet_wrong_chain',
            message: 'The wallet provider is on another chain than the vault.'
        });
    }

    getExitRpcUrl() {
        try {
            const value = localStorage.getItem(EXIT_RPC_STORAGE_KEY);
            return value ? exitRpcUrl(value) : null;
        } catch {
            return null;
        }
    }

    /** Set (or clear with null) the user's exit RPC for this origin. */
    setExitRpcUrl(value) {
        const url = value == null || value === '' ? null : exitRpcUrl(value);
        try {
            if (url) localStorage.setItem(EXIT_RPC_STORAGE_KEY, url);
            else localStorage.removeItem(EXIT_RPC_STORAGE_KEY);
        } catch {
            throw new BrowserWalletHttpError('This browser cannot save the exit RPC setting.', 409, 'exit_rpc_unsaved');
        }
        this.exitRpcChainCheck = null;
        this.dispatchEvent(new Event('change'));
        return url;
    }

    // ---- gasless withdrawals (design §3.2): the bundler, the read ladder and the operation journal ----

    /** The withdrawal nullifier of the selected state (the attempts key of a sponsored close), or null without a state. */
    async currentWithdrawalNullifier() {
        await this.init();
        const state = this.runtime?.state;
        return state ? this.worker.call('withdrawalNullifier', { state }) : null;
    }

    /** The pinned gasless configuration of the build-pinned profile (§4.3), or null when there is none or it is unusable. */
    gaslessPins() {
        try {
            return gaslessPins(this.browserConfig?.trusted_deployment);
        } catch {
            return null;
        }
    }

    /** The user's bundler URL for this origin, or null. */
    getBundlerUrl() {
        try {
            const value = localStorage.getItem(BUNDLER_URL_STORAGE_KEY);
            return value ? validBundlerUrl(value) : null;
        } catch {
            return null;
        }
    }

    /** The bundler a sponsored operation goes to: the user's, else the profile's `gasless.bundler_url`. */
    effectiveBundlerUrl() {
        return this.getBundlerUrl() || this.gaslessPins()?.bundlerUrl || null;
    }

    /** Set (or clear with null) the user's bundler URL for this origin; the exit RPC's URL rules apply. */
    setBundlerUrl(value) {
        const url = value == null || value === '' ? null : validBundlerUrl(value);
        try {
            if (url) localStorage.setItem(BUNDLER_URL_STORAGE_KEY, url);
            else localStorage.removeItem(BUNDLER_URL_STORAGE_KEY);
        } catch {
            throw gaslessError('bundler_url_unsaved');
        }
        this.bundlerChainCheck = null;
        this.dispatchEvent(new Event('change'));
        return url;
    }

    /**
     * A bundler client: a host transport (`provider.zkapiBundler`) when given,
     * else JSON-RPC over `url` (default: the effective bundler URL). Null
     * without either. Each call is bounded like an exit RPC call.
     */
    bundlerRpc(url = this.effectiveBundlerUrl(), { transport = null } = {}) {
        const timeoutMs = this.exitTiming().callTimeoutMs;
        if (transport) return bundlerClient(transport, { timeoutMs });
        return url ? bundlerClient(url, { timeoutMs }) : null;
    }

    /** Remember whether the bundler at `url` answered on the vault's chain and serves the pinned EntryPoint. */
    noteBundlerChain(url, matches, supportsEntryPoint = null) {
        const before = this.bundlerChainCheck;
        this.bundlerChainCheck = { url, matches, supportsEntryPoint };
        if (before?.url !== url || before?.matches !== matches || before?.supportsEntryPoint !== supportsEntryPoint) {
            this.dispatchEvent(new Event('change'));
        }
    }

    /** The last availability read of the gasless path (the snapshot's `gasless` object). */
    noteGaslessStatus(status) {
        this.gaslessStatus = status ? structuredClone(status) : null;
        this.dispatchEvent(new Event('change'));
    }

    /**
     * The read RPC of the gasless path (§3.1): the exit RPC when set and on
     * the vault's chain, then the pinned RPC, and the wallet provider only
     * when the host opts in with `walletRequest`, so the transit and payout
     * addresses never reach the wallet vendor otherwise. A call moves to the
     * next source when one fails to answer; a revert is an answer.
     */
    gaslessReader({ walletRequest = null } = {}) {
        const sources = [];
        const exit = this.exitRpcOnVaultChain();
        if (exit) sources.push(exit);
        sources.push(this.pinnedRpc());
        const wallet = walletRequest ? this.walletOnVaultChain(walletRequest) : null;
        if (wallet) sources.push(wallet);
        const reverted = error => error?.code === 'rpc_call_reverted' || Number(error?.code) === 3
            || /^0x[0-9a-fA-F]{8}/.test(String(error?.data?.data ?? error?.data ?? ''))
            || /execution reverted|revert/i.test(String(error?.message || ''));
        return async payload => {
            let failure = null;
            for (const source of sources) {
                try {
                    return await source(payload);
                } catch (error) {
                    if (reverted(error)) throw error;
                    failure = error;
                }
            }
            throw failure || new Error('No RPC could be read.');
        };
    }

    /** Whether `submission` is still the prepared plan's live wallet claim (its durable operation identity). */
    preparedSubmissionMatches(prepared, submission, { allowSettled = false } = {}) {
        const reference = submission && typeof submission === 'object' ? submission : null;
        return Boolean(prepared && reference?.operationId && reference.operationId === prepared.operationId
            && (reference.submissionId === prepared.submissionId || (allowSettled && !prepared.submissionId))
            && Number(reference.noteId) === Number(prepared.noteId ?? prepared.public_inputs?.note_id)
            && reference.mode === prepared.mode
            && String(reference.destination || '').toLowerCase() === String(prepared.destination || '').toLowerCase()
            && reference.deploymentId === this.manifest.deployment_id
            && Number(reference.chainId) === Number(this.config.funding.chain_id)
            && String(reference.contractAddress || '').toLowerCase()
                === String(this.config.funding.contract_address || '').toLowerCase());
    }

    /**
     * The wallet claim of a sponsored plan. A plan whose operation is already
     * journaled (op_built / op_submitted) is self-describing: the identical
     * bytes are re-sent without any prompt, so a new tab takes the claim over
     * instead of waiting for a wallet window that no longer exists. Without
     * one the ordinary claim applies.
     */
    async claimPreparedWithdrawalUserOp({ liveWindowMs = GASLESS_TIMING.resendAfterMs } = {}) {
        const takeover = await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || !isGaslessWithdrawal(prepared) || !prepared.userOp || preparedWithdrawalHashes(prepared).length) return null;
            // A claim another client is still following is refused like the
            // wallet path's (409 withdrawal_wallet_pending); only a claim no
            // one follows any more is taken over.
            if (prepared.submissionId && this.gaslessClaimLive({
                submissionId: prepared.submissionId, owner: prepared.submissionOwner,
                lastActiveAt: Math.max(Number(prepared.submissionStartedAt || 0), Number(prepared.userOpSubmittedAt || 0),
                    Number(prepared.userOpFollowedAt || 0))
            }, liveWindowMs)) {
                throw new BrowserWalletHttpError('This withdrawal is already awaiting MetaMask in this or another tab.', 409, 'withdrawal_wallet_pending');
            }
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                operationId: prepared.operationId || uuid()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'resumed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier || next.public_inputs?.withdrawal_nullifier || null,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                userOp: structuredClone(next.userOp),
                userOpHash: next.userOpHash,
                userOpHashes: [...(next.userOpHashes || [])],
                userOpPhase: next.userOpPhase || 'op_built',
                userOpAmbiguous: next.userOpAmbiguous === true,
                userOpSubmittedAt: next.userOpSubmittedAt ?? null,
                submittedAtBlock: next.submittedAtBlock ?? null,
                staleUserOpHashes: [...(next.staleUserOpHashes || [])],
                staleSubmittedAtBlock: next.staleSubmittedAtBlock ?? null,
                bundlerUrl: next.bundlerUrl || null
            };
        });
        const claim = takeover || await this.claimPreparedWithdrawalSubmission();
        if (claim?.submissionId && !claim.transactionHash) this.liveGaslessClaims.add(claim.submissionId);
        return claim;
    }

    /**
     * The write-ahead record of a sponsored operation, BEFORE the first
     * eth_sendUserOperation: the full unpacked operation with its signature,
     * its hash, nonce, whether it carries initCode, the bundler it goes to,
     * when it was built and the block it is tracked from (§3.2). After a
     * crash the identical bytes are re-sent (the hash does not change).
     */
    async rememberPreparedWithdrawalUserOp(submission, details) {
        const hash = String(details?.userOpHash || '').toLowerCase();
        if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error('The sponsored operation has no valid hash.');
        if (!details?.userOp || typeof details.userOp !== 'object') throw new Error('The sponsored operation is missing.');
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!this.preparedSubmissionMatches(prepared, submission)) {
                throw new Error('The withdrawal wallet claim changed before its operation was saved.');
            }
            const next = {
                ...prepared,
                feePayer: 'payout',
                userOp: structuredClone(details.userOp),
                userOpHash: hash,
                userOpHashes: [...new Set([...(prepared.userOpHashes || []), hash])],
                userOpNonce: String(details.userOpNonce ?? details.userOp.nonce ?? ''),
                userOpInitCode: Boolean(details.userOpInitCode),
                bundlerUrl: details.bundlerUrl || null,
                userOpBuiltAt: Number(details.userOpBuiltAt || Date.now()),
                // A replacement (a fee bump, a rebuild) at the same nonce can
                // only land after the first op was tracked: keep the earliest block.
                submittedAtBlock: details.submittedAtBlock == null ? (prepared.submittedAtBlock ?? null)
                    : (prepared.submittedAtBlock != null && prepared.userOpHashes?.length
                        ? Math.min(Number(prepared.submittedAtBlock), Number(details.submittedAtBlock)) : Number(details.submittedAtBlock)),
                userOpPhase: 'op_built',
                userOpAmbiguous: prepared.userOpAmbiguous === true
            };
            delete next.userOpSubmittedAt;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    /** After the bundler answered or timed out: the operation is in a mempool under its hash (or ambiguous). */
    async rememberPreparedWithdrawalUserOpSubmission(submission, { hash = null, ambiguous = false, submittedAt = Date.now() } = {}) {
        const lowered = hash ? String(hash).toLowerCase() : null;
        if (lowered && !/^0x[0-9a-f]{64}$/.test(lowered)) throw new Error('The bundler returned an invalid operation hash.');
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!this.preparedSubmissionMatches(prepared, submission)) {
                throw new Error('The withdrawal wallet claim changed before its submission was saved.');
            }
            const next = {
                ...prepared,
                userOpHashes: [...new Set([...(prepared.userOpHashes || []), ...(lowered ? [lowered] : [])])],
                userOpSubmittedAt: Number(submittedAt),
                userOpAmbiguous: Boolean(ambiguous) || prepared.userOpAmbiguous === true,
                userOpPhase: 'op_submitted'
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    /**
     * The heartbeat of the client following the plan's journaled operation
     * (`userOpFollowedAt`), written on each poll while the operation is
     * pending: another tab treats the claim as live for `liveWindowMs` after
     * the last beat, so an operation pending longer than the window (a fee
     * spike) is never taken over while it is still followed.
     */
    async touchPreparedWithdrawalUserOp(submission, followedAt = Date.now()) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || !prepared.userOp || !this.preparedSubmissionMatches(prepared, submission)) return null;
            const next = { ...prepared, userOpFollowedAt: Number(followedAt) };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    /** The settlement amounts of a sponsored operation from its bundle receipt, on the prepared plan. */
    async rememberPreparedWithdrawalUserOpOutcome(submission, outcome) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || !this.preparedSubmissionMatches(prepared, submission, { allowSettled: true })) return null;
            const next = { ...prepared, ...gaslessOutcomeFields(outcome) };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    /**
     * Forget an operation that will not be included (past its proof,
     * replaced by one with other bytes); its hashes stay in
     * `staleUserOpHashes` so a late inclusion is still recognized. The
     * `reverted` hashes (an inclusion already settled as reverted) are
     * dropped instead: a retry builds a new operation rather than settling
     * that inclusion again.
     */
    async releasePreparedWithdrawalUserOp(submission, { reverted = [] } = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || !this.preparedSubmissionMatches(prepared, submission, { allowSettled: true })) return null;
            const staleBlocks = [prepared.staleSubmittedAtBlock, prepared.submittedAtBlock].filter(value => value != null).map(Number);
            const dropped = new Set(reverted.filter(Boolean).map(hash => String(hash).toLowerCase()));
            const next = {
                ...prepared,
                staleUserOpHashes: [...new Set([...(prepared.staleUserOpHashes || []), ...(prepared.userOpHashes || [])])]
                    .filter(hash => !dropped.has(String(hash).toLowerCase())),
                // The earliest block a released operation was tracked from: the inclusion search of its hashes starts there.
                ...(staleBlocks.length ? { staleSubmittedAtBlock: Math.min(...staleBlocks) } : {})
            };
            for (const field of ['userOp', 'userOpHash', 'userOpHashes', 'userOpNonce', 'userOpInitCode', 'userOpBuiltAt', 'submittedAtBlock',
                'userOpPhase', 'userOpAmbiguous', 'userOpSubmittedAt', 'userOpFollowedAt']) delete next[field];
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    /**
     * E_low: the note's own expiry_ts, raised only when the user's exit RPC
     * (on the vault's chain) and the pinned RPC both report a later
     * effectiveExpiry (E0).
     */
    async exitLowExpiry(state) {
        const exit = this.exitRpcOnVaultChain();
        if (!exit) return lowExpiry(state.expiry_ts);
        const read = async request => {
            try {
                const word = await request({ method: 'eth_call', params: [{ to: this.config.funding.contract_address,
                    data: `${VAULT_SELECTORS.effectiveExpiry}${abiWordHex(state.note_id)}` }, 'latest'] });
                return /^0x[0-9a-fA-F]{64}$/.test(word || '') ? Number(BigInt(word)) : null;
            } catch {
                return null;
            }
        };
        const [exitRpcExpiry, pinnedRpcExpiry] = await Promise.all([read(exit), read(this.pinnedRpc())]);
        return lowExpiry(state.expiry_ts, { exitRpcExpiry, pinnedRpcExpiry });
    }

    /**
     * One operator call in exit mode: at most CALL_TIMEOUT (and within
     * `deadline`, ms), no retries. Returns { reachable, ok, status, code, body };
     * a timeout, network failure, 5xx, 429 or 401 is { reachable: false }.
     */
    async exitCall(url, { method = 'GET', body = null, deadline = null, signal = null } = {}) {
        const limit = this.exitTiming().callTimeoutMs;
        const remaining = deadline == null ? limit : Math.min(limit, deadline - Date.now());
        if (remaining <= 0) return { reachable: false, reason: 'budget' };
        const timeout = AbortSignal.timeout(remaining);
        const callSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
        try {
            const payload = await abortable(this.remoteJson(url, {
                method,
                signal: callSignal,
                ...(body == null ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
            }), callSignal);
            return { reachable: true, ok: true, status: 200, body: payload };
        } catch (error) {
            if (signal?.aborted) throw error;
            const status = Number(error?.status);
            if (!Number.isInteger(status) || status >= 500 || status === 429 || status === 401) {
                return { reachable: false, status: Number.isInteger(status) ? status : null, reason: error?.code || 'unreachable' };
            }
            return { reachable: true, ok: false, status, code: error.code || null, body: error.data || null };
        }
    }

    /** Request journal records and challenge evidence at one note state, for exit decisions. */
    exitRecordsAt(state = this.runtime?.state) {
        const key = this.archiveKey(state);
        if (!key) return [];
        return [
            ...requestRecordsAtState(this.requestArchive, key),
            ...unresolvedRequestArchiveAt(this.requestArchive, key).filter(entry => entry.type === REQUEST_EVIDENCE_TYPE)
        ];
    }

    /**
     * E1: one bounded recovery pass. Reads the pending journal's request and
     * the nullifier of every unresolved record at the current state, installs
     * a response that passes S1–S6, and repeats once from the new state.
     * Returns { installed, lateSuccessor, reading, response, installError }.
     */
    async exitRecoveryPassLocked({ signal = null, onProgress = () => {} } = {}) {
        const deadline = Date.now() + this.exitTiming().recoveryBudgetMs;
        const result = { installed: false, lateSuccessor: false, reading: null, response: null, installError: null };
        const server = this.config.funding.protocol_server_url;
        for (let round = 0; round < 2; round += 1) {
            const state = this.runtime?.state;
            if (!state) return result;
            // Every record that can still install (the archive's unresolved
            // records: pending, discarded, evicted, abandoned, late).
            const records = this.archivedRequestsAt(state).filter(entry => entry.type === REQUEST_JOURNAL_TYPE);
            const journal = this.runtime.journal;
            if (!journal && !records.length) return result;
            let response = null;
            if (journal) {
                const id = journalClientRequestId(journal);
                const answer = await this.exitCall(`${server}/v2/requests/${encodeURIComponent(id)}`, { deadline, signal });
                if (answer.ok && answer.body?.request_response) response = answer.body.request_response;
            }
            if (!response) {
                const nullifier = journal?.nullifier ?? records[0]?.nullifier;
                const answer = await this.exitCall(`${server}/v2/nullifiers/${encodeURIComponent(nullifier)}`, { deadline, signal });
                const reading = answer.ok ? nullifierReading(answer.body) : { status: 'unavailable', response: null };
                result.reading = reading;
                await this.saveRequestObservations(this.archivedRequestsAt(state), reading, 'exit');
                response = reading.response;
            }
            if (!response) return result;
            result.response = response;
            let installed;
            try {
                installed = await this.installRecoveredResponse(response.client_request_id || journalClientRequestId(journal),
                    onProgress, { response });
            } catch (error) {
                if (isAbortError(error, signal)) throw error;
                result.installError = error?.code || String(error?.message || error);
                return result;
            }
            if (installed === LATE_SUCCESSOR) {
                result.lateSuccessor = true;
                return result;
            }
            if (!installed) return result;
            result.installed = true;
        }
        return result;
    }

    /**
     * Lost ε (E3): a finalized response at this state that did not install
     * but passes S1, S2, S4 and S6. Its charge may lower the concession to
     * min(charge, bound_at_state).
     */
    async lostEpsilonCharge(state, recovery) {
        const response = recovery?.response;
        if (!response || recovery.installed || recovery.lateSuccessor) return null;
        try {
            const checked = await this.worker.call('checkUnrecoverableResponse', { config: this.config.wallet_core, state, response });
            return checked?.charge_applied ?? null;
        } catch {
            return null;
        }
    }

    /**
     * The vault's currentRoot for the indexer check of E4.1: through the
     * user's exit RPC when one is set and on the vault's chain; when it is
     * not, or fails, through the wallet provider when it is on the vault's
     * chain, then the pinned RPC.
     */
    async exitCurrentRoot(signal = null, walletRequest = null) {
        const call = { method: 'eth_call', params: [{ to: this.config.funding.contract_address,
            data: VAULT_SELECTORS.currentRoot }, 'latest'] };
        const sources = [['exit RPC', this.exitRpcOnVaultChain()], ['wallet provider', this.walletOnVaultChain(walletRequest)]];
        for (const [source, request] of sources) {
            if (!request) continue;
            try {
                const word = await abortable(request(call), signal);
                if (!/^0x[0-9a-fA-F]{64}$/.test(word || '')) throw new Error(`The ${source} returned an invalid vault root.`);
                return BigInt(word);
            } catch (error) {
                if (signal?.aborted) throw error;
            }
        }
        return this.vaultWord(VAULT_SELECTORS.currentRoot, signal);
    }

    /**
     * §6.6: the note's path rebuilt from the vault's logs, through the
     * user's exit RPC when one is set and on the vault's chain, then (when
     * it is not, or fails) through the wallet provider and the pinned RPC,
     * all within one rebuild budget.
     */
    async rebuildExitPath(state, { signal = null, walletRequest = null } = {}) {
        // The wallet provider's calls get E0's per-call bound too (the exit
        // and pinned RPCs have their own), so a silent wallet leaves the
        // pinned RPC time to answer.
        const requests = [this.exitRpcOnVaultChain(), this.walletOnVaultChain(walletRequest), this.pinnedRpc()].filter(Boolean);
        const deadline = Date.now() + this.exitTiming().rebuildBudgetMs;
        const trusted = this.browserConfig?.trusted_deployment || {};
        let failure = null;
        for (const request of requests) {
            try {
                return await rebuildNotePath({
                    request,
                    vault: this.config.funding.contract_address,
                    deployBlock: trusted.deploy_block,
                    noteId: Number(state.note_id),
                    chainId: Number(this.config.funding.chain_id),
                    worker: this.worker,
                    signal,
                    deadline
                });
            } catch (error) {
                if (signal?.aborted || error?.name === 'AbortError') throw error;
                failure = error;
                if (error?.code === 'tree_rebuild_timeout') break;
            }
        }
        throw failure;
    }

    /**
     * E4.1: a path at a root the vault holds. The deposit-time path first
     * (Amendment A1), then the operator's indexer with its root checked
     * against the vault's currentRoot (exitCurrentRoot), then the vault's
     * own logs (§6.6). `sources` narrows the order; after an UnknownRoot
     * refusal no source may return `refusedRoot`.
     */
    async exitPathLocked(state, { signal = null, sources = EXIT_PATH_SOURCES, refusedRoot = null, walletRequest = null,
        currentRoot = null } = {}) {
        const refused = root => refusedRoot != null && sameFelt(root, refusedRoot);
        const saved = state?.deposit_path;
        if (sources.includes('deposit') && saved?.active_root != null && Array.isArray(saved.siblings)
            && saved.siblings.length === 32 && !refused(saved.active_root)) {
            return { active_root: saved.active_root, note_id: Number(state.note_id), siblings: saved.siblings, source: 'deposit' };
        }
        if (sources.includes('indexer')) {
            const timeout = AbortSignal.timeout(this.exitTiming().callTimeoutMs);
            const callSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
            try {
                // A current root the caller read through the wallet provider,
                // or the vault's currentRoot read here.
                const root = currentRoot != null ? currentRoot
                    : await abortable(this.exitCurrentRoot(callSignal, walletRequest), callSignal);
                if (!refused(root)) {
                    const path = await abortable(this.treePath(Number(state.note_id), true, root, callSignal), callSignal);
                    if (sameFelt(path.active_root, root)) return { ...path, source: 'indexer' };
                }
            } catch (error) {
                if (signal?.aborted) throw error;
            }
        }
        let rebuilt;
        try {
            rebuilt = await this.rebuildExitPath(state, { signal, walletRequest });
        } catch (error) {
            if (signal?.aborted || error?.name === 'AbortError') throw error;
            // The code of the rebuild's failure (tree_logs_unavailable,
            // tree_rebuild_timeout, a worker's tree_root_mismatch, …), marked
            // as a path failure: the caller decides whether a proof that
            // already exists is submitted anyway.
            const code = error?.code || /^(?:Error: )?([a-z_]+):/.exec(String(error?.message || ''))?.[1] || 'tree_rebuild_failed';
            throw new BrowserWalletHttpError(error?.message || 'The Merkle path could not be rebuilt.', 503, code,
                { exit_path_unavailable: true });
        }
        if (refused(rebuilt.active_root)) {
            throw new BrowserWalletHttpError('The vault’s own logs end at the root its simulation refused.', 409,
                'tree_root_refused', { exit_path_unavailable: true });
        }
        return { active_root: rebuilt.active_root, note_id: rebuilt.note_id, siblings: rebuilt.siblings, source: 'rebuild' };
    }

    /**
     * E4.2: the stale-device pre-check. Evidence the operator holds at N⁺
     * that verifies under the pinned request VK means another device spent
     * this state's successor: refuse with device_not_newest. Errors and
     * unverifiable answers are ignored, so a lying server cannot block exits.
     */
    async staleDeviceCheckLocked(state, { signal = null } = {}) {
        const successor = await this.worker.call('successorNullifier', { state });
        const answer = await this.exitCall(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(successor)}/evidence`,
            { signal });
        const evidence = answer.ok ? answer.body : null;
        if (!evidence?.public_inputs || !evidence.proof
            || !sameFelt(evidence.public_inputs.request_nullifier, successor)) return { checked: answer.reachable, successor };
        let verified = false;
        try {
            verified = await this.worker.call('verifyRequest', {
                publicInputs: evidence.public_inputs,
                proof: typeof evidence.proof === 'string' ? evidence.proof : evidence.proof?.proof,
                verifyingKey: this.config.verifying_keys?.request
            }) === true;
        } catch {
            verified = false;
        }
        if (verified) {
            throw new BrowserWalletHttpError(DEVICE_NOT_NEWEST_MESSAGE, 409, 'device_not_newest', { successor_nullifier: successor });
        }
        return { checked: true, successor };
    }

    /** E4.5: advisory reads; a disagreement only warns. */
    async exitAdvisoryWarnings(nullifier, successor, { signal = null } = {}) {
        const warnings = [];
        for (const [label, value] of [['withdrawal_nullifier', nullifier], ['next_nullifier', successor]]) {
            try {
                if (await this.vaultWord(`${VAULT_SELECTORS.challengedNullifiers}${abiWordHex(value)}`, signal) !== 0n) {
                    warnings.push({ code: 'nullifier_flagged', field: label,
                        message: 'The RPC reports this balance state as already defeated; the escape may revert.' });
                }
            } catch (error) {
                if (isAbortError(error, signal)) throw error;
            }
        }
        return warnings;
    }

    /** A request refused while the note is frozen by its exit lock (C3). */
    exitLockedError(lock, verdict = null) {
        return new BrowserWalletHttpError(EXIT_LOCKED_MESSAGE, 409, 'exit_locked', {
            mode: lock?.mode || null,
            released: (lock?.released || []).length,
            releasable_after: verdict?.releasableAfter ?? null,
            reason: verdict?.reason || null
        });
    }

    /**
     * The note's chain status and the finalized block's timestamp, read at
     * the finalized block (for E6), from the first of these that answers:
     * - the user's exit RPC, on the vault's chain (`trusted`);
     * - the user's wallet provider, on the vault's chain, each call bounded
     *   by E0's CALL_TIMEOUT;
     * - the pinned RPC, which the operator may run or influence (§2.1).
     * Only a trusted reading releases a lock before the local clock agrees;
     * the wallet provider comes before the pinned RPC so that the pinned RPC
     * failing, or reporting a pending exit, cannot keep a dead lock (and the
     * stale state it freezes) on its own.
     */
    async exitChainStatus(noteId, { walletRequest = null, signal = null } = {}) {
        const sources = [
            { source: 'exit_rpc', trusted: true, request: this.exitRpcOnVaultChain() },
            { source: 'wallet', trusted: false, request: this.walletOnVaultChain(walletRequest) },
            { source: 'pinned_rpc', trusted: false, request: this.pinnedRpc() }
        ].filter(entry => entry.request);
        let failure = null;
        for (const { source, trusted, request } of sources) {
            try {
                return { ...(await this.noteStatusAtFinality(request, noteId, signal)), trusted, source };
            } catch (error) {
                if (signal?.aborted) throw error;
                failure = error;
            }
        }
        throw failure || new Error('No RPC returned the note’s status.');
    }

    /** The note's status at the finalized block, and that block's timestamp, through `request`. */
    async noteStatusAtFinality(request, noteId, signal = null) {
        const block = await abortable(request({ method: 'eth_getBlockByNumber', params: ['finalized', false] }), signal);
        if (!/^0x[0-9a-fA-F]+$/.test(String(block?.number || '')) || !/^0x[0-9a-fA-F]+$/.test(String(block?.timestamp || ''))) {
            throw new Error('The RPC returned no finalized block.');
        }
        const encoded = await abortable(request({ method: 'eth_call', params: [{ to: this.config.funding.contract_address,
            data: `0x9f18e4ed${abiWordHex(noteId)}` }, block.number] }), signal);
        const words = String(encoded || '').replace(/^0x/, '').match(/.{64}/g) || [];
        if (words.length < 4) throw new Error('The vault returned a truncated note record.');
        const status = Number(BigInt(`0x${words[3]}`));
        return {
            noteStatus: status === 1 ? 'active' : status === 2 ? 'pending_withdrawal' : status === 3 ? 'closed' : 'unknown',
            finalizedTimestamp: Number(BigInt(block.timestamp))
        };
    }

    /**
     * E6: release the exit lock if the note closed, if no kind-0 or kind-1
     * proof was released and the user cancels, or once every released one is
     * dead at a finalized block. A sent ownership proof keeps the state
     * withdrawal-only (C5). Successors archived as late_successor install
     * afterwards, after S1–S6 again. Call under the wallet lock.
     * `walletRequest` (the user's wallet provider) is read for the note's
     * status before the pinned RPC (exitChainStatus).
     */
    async releaseExitLockLocked({ cancel = false, walletRequest = null, signal = null } = {}) {
        const lock = this.runtime?.exitLock;
        if (!lock) return { released: true, reason: 'no_lock' };
        let chain = {};
        if (releasedExitProofs(lock).length) {
            try {
                chain = await this.exitChainStatus(lock.noteId, { walletRequest, signal });
            } catch (error) {
                if (signal?.aborted) throw error;
                chain = {};
            }
        }
        const verdict = exitLockReleasable(lock, { noteStatus: chain.noteStatus ?? null,
            finalizedTimestamp: chain.finalizedTimestamp ?? null, cancel, now: nowSeconds(),
            statusTrusted: chain.trusted === true });
        if (!verdict.releasable) return { released: false, ...verdict, statusSource: chain.source || null };
        const prepared = this.runtime.preparedWithdrawal;
        const ownershipSent = (lock.released || []).some(entry => Number(entry.kind) === WITHDRAWAL_KIND.ownership)
            || prepared?.clearanceReserved === true;
        let nextPrepared = preparedWithdrawalHasSubmission(prepared) ? prepared : null;
        if (!nextPrepared && ownershipSent && this.runtime.state) {
            nextPrepared = {
                phase: 'reserving', mode: 'mutual', operationId: prepared?.operationId || uuid(),
                noteId: Number(this.runtime.state.note_id), destination: prepared?.destination || null,
                withdrawalNullifier: prepared?.withdrawalNullifier || null, clearanceReserved: true,
                ...(prepared?.clearance?.signature ? { clearance: prepared.clearance } : {}),
                ...(prepared?.clearanceOutcome ? { clearanceOutcome: prepared.clearanceOutcome } : {}),
                // C3: the state's ownership proof, sent again while it stays valid.
                ...(prepared?.ownershipProof ? { ownershipProof: prepared.ownershipProof } : {}),
                createdAt: Number(prepared?.createdAt || Date.now())
            };
        }
        await this.commit({ ...this.runtime, exitLock: null, preparedWithdrawal: nextPrepared });
        const installed = await this.installLateSuccessorsLocked(lock);
        return { released: true, reason: verdict.reason, installed };
    }

    /** The successors archived as late_successor at the lock's state, which is the current one. */
    lateSuccessorsAt(lock) {
        const key = this.archiveKey(this.runtime?.state);
        if (!lock || !key || Number(key.noteId) !== Number(lock.noteId) || !sameFelt(key.anchor, lock.anchor)) return [];
        return requestRecordsAtState(this.requestArchive, key)
            .filter(entry => entry.disposition === LATE_SUCCESSOR_DISPOSITION && entry.lateResponse);
    }

    /** Install, after S1–S6 again, a successor archived while the lock was held. */
    async installLateSuccessorsLocked(lock) {
        const late = this.lateSuccessorsAt(lock);
        for (const entry of late) {
            try {
                if (await this.installRecoveredResponse(entry.clientRequestId, () => {}, { response: entry.lateResponse }) === true) {
                    return true;
                }
            } catch {
                // A late successor that no longer passes S1–S6 stays archived.
            }
        }
        return false;
    }

    /**
     * Cancel an exit: release the exit lock now if no escape or close proof
     * was released, otherwise once every released proof is dead (E6).
     */
    async cancelExit({ walletRequest = null } = {}) {
        await this.init();
        if (walletRequest != null && typeof walletRequest !== 'function') throw new Error('The wallet provider must be a request function.');
        this.preemptForExit();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (preparedWithdrawalHasSubmission(prepared) || prepared?.submissionId) {
                throw new BrowserWalletHttpError('A withdrawal transaction for this balance is still unresolved. Check its status first.',
                    409, 'withdrawal_submission_pending');
            }
            const result = await this.releaseExitLockLocked({ cancel: true, walletRequest });
            if (!result.released) throw this.exitLockedError(this.runtime.exitLock, result);
            return result;
        });
    }

    /**
     * E4.6: rerun E1 once more just before a released exit proof is
     * broadcast. A successor that arrives now is archived as late_successor
     * and the lock is kept; it installs when the lock is released.
     */
    async exitBeforeBroadcast({ signal = null } = {}) {
        await this.init();
        this.preemptForExit({ requests: true });
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const state = this.runtime.state;
            const lock = this.runtime.exitLock;
            if (!state || !lock || !releasedExitProofs(lock).length) return { checked: false };
            if (nowSeconds() >= mustInitiateBy(await this.exitLowExpiry(state))) {
                return { checked: false, reason: 'past_must_initiate_by' };
            }
            const recovery = await this.exitRecoveryPassLocked({ signal });
            return { checked: true, lateSuccessor: recovery.lateSuccessor };
        });
    }

    /**
     * Prepare the exit the rules choose for `mode`: 'mutual' (withdraw,
     * cooperatively when the state allows) or 'escape' (unilateral exit now).
     * The returned plan's `mode` is the exit actually prepared: a mutual
     * request becomes an escape when the state, the deadline or the server
     * calls for one (E2, E3). `earlyConcession` ('zero' or 'bound') is the
     * user's choice for an escape forced before T (E3). Throws
     * request_settlement_pending (with escape_at) when a mutual request must
     * wait for T, and device_not_newest when another device spent this state.
     *
     * `refusedRoot` is the root of a proof the vault (or the wallet's
     * simulation) refused with UnknownRoot: the next proof takes its path
     * from the indexer or the vault's logs at any other root (E4.1, §6.6).
     * `walletRequest` is the user's wallet provider (an EIP-1193 request
     * function); without an exit RPC it is read before the pinned RPC for
     * the vault's root and logs.
     */
    async prepareWithdrawal(mode, destination, {
        expectedActiveRoot = null,
        reprove = false,
        earlyConcession = 'zero',
        refusedRoot = null,
        walletRequest = null,
        signal = null,
        gasless = null,
        onProgress = () => {}
    } = {}) {
        await this.init();
        if (!['mutual', 'escape'].includes(mode)) throw new Error('Choose a valid withdrawal mode.');
        // A sponsored plan (§3.2) is prepared with the transit account S as
        // its destination and journals the payout address Y and the transit
        // identity beside the proof, so a resume derives the same S.
        if (gasless != null && (!/^0x[0-9a-fA-F]{40}$/.test(gasless.payout || '')
            || !/^0x[0-9a-fA-F]{40}$/.test(gasless.transit?.account || '')
            || gasless.transit.account.toLowerCase() !== String(destination || '').toLowerCase())) {
            throw new Error('A sponsored withdrawal names its payout address and its transit account as the destination.');
        }
        if (refusedRoot != null) {
            try {
                BigInt(refusedRoot);
            } catch {
                throw new Error('Choose a valid refused Merkle root.');
            }
        }
        if (walletRequest != null && typeof walletRequest !== 'function') throw new Error('The wallet provider must be a request function.');
        if (!['zero', 'bound'].includes(earlyConcession)) {
            throw new BrowserWalletHttpError('Choose zero or bound for a forced escape.', 400, 'invalid_concession_choice');
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError('Wait for the active model requests to finish before withdrawing.',
                409, 'lease_requests_in_flight');
        }
        this.preemptForExit({ requests: true });
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const lockBefore = this.runtime.exitLock;
            try {
                // A verified install or a released lock moves the decision
                // to a new state or a fresh lock, and preparation restarts
                // there (E1, E3.2, E4.3, E6).
                for (let pass = 0; pass < 4; pass += 1) {
                    const plan = await this.prepareExitLocked(mode, destination, {
                        expectedActiveRoot, reprove, earlyConcession, refusedRoot, walletRequest, signal, gasless, onProgress
                    });
                    if (plan !== WITHDRAWAL_RESTART) return plan;
                }
                throw new Error('The private balance changed repeatedly while the withdrawal was being prepared. Try again.');
            } catch (error) {
                // An attempt that failed before releasing any proof leaves the
                // note as it was: the lock it set is released (E6, cancel).
                await this.reload().catch(() => null);
                const lock = this.runtime?.exitLock;
                if (!lockBefore && lock && !(lock.released || []).length) {
                    await this.commit({ ...this.runtime, exitLock: null }).catch(() => null);
                }
                throw error;
            }
        });
    }

    /** A saved plan that already releases this decision's proof at this state. */
    reusablePlan(existing, { mode, destination, state, nullifier, conceded }) {
        const inputs = existing?.public_inputs;
        return Boolean(existing?.proof && inputs && existing.mode === mode
            && existing.destination?.toLowerCase() === destination.toLowerCase()
            && Number(inputs.kind) === WITHDRAWAL_KIND[mode]
            && Number(inputs.note_id) === Number(state.note_id)
            && sameFelt(inputs.withdrawal_nullifier, nullifier)
            && BigInt(inputs.final_balance) + BigInt(inputs.conceded ?? 0) === BigInt(state.current_balance)
            && BigInt(inputs.conceded ?? 0) === BigInt(conceded)
            && withdrawalProofStillValid(inputs));
    }

    async prepareExitLocked(requested, destination, { expectedActiveRoot, reprove, earlyConcession, refusedRoot = null,
        walletRequest = null, signal, gasless = null,
        onProgress }) {
        await this.reload();
        const state = this.runtime.state;
        if (!state) throw new Error('There is no active private note to withdraw.');
        if (unresolvedLateWithdrawalForNote(this.runtime, state.note_id)) {
            throw new BrowserWalletHttpError(
                'A withdrawal from another tab may already be on-chain. Check its status before starting another withdrawal.',
                409,
                'late_withdrawal_pending'
            );
        }
        let existing = this.runtime.preparedWithdrawal;
        this.validateExistingWithdrawal(existing, requested, destination, state);
        const existingHashes = preparedWithdrawalHashes(existing);
        if (existing?.submissionId && !existingHashes.length) {
            throw new BrowserWalletHttpError(
                existing.phase === 'ambiguous'
                    ? 'MetaMask did not return a transaction ID. Check the chain, then explicitly retry if this balance is still active.'
                    : 'This withdrawal is awaiting MetaMask in this or another tab.',
                409,
                existing.phase === 'ambiguous' ? 'withdrawal_submission_ambiguous' : 'withdrawal_wallet_pending'
            );
        }
        if (existingHashes.length) {
            // A broadcast is never gated or re-proved.
            if (!existing.public_inputs || !existing.proof) {
                throw new Error('The submitted withdrawal proof is missing from this browser.');
            }
            return existing;
        }
        const now = nowSeconds();
        const deadline = mustInitiateBy(await this.exitLowExpiry(state));
        // E6 before any decision: a lock whose released escape or close
        // proofs are all dead is released, and a successor archived as
        // late_successor meanwhile installs (§7.5). The decision then starts
        // again at the newest state with a fresh lock, so a dead escape
        // neither forces another escape nor keeps the stale state.
        const held = this.runtime.exitLock;
        const deadAfter = exitLockDeadAfter(held);
        if (deadAfter != null && now > deadAfter) {
            const release = await this.releaseExitLockLocked({ walletRequest, signal });
            if (release.released) return WITHDRAWAL_RESTART;
            // A verified successor waits at the lock's state, and no reading
            // let the lock go yet: deciding here would exit from the stale
            // state, conceding up to its bound instead of the successor's
            // charge. Before must_initiate_by the user is told when to retry
            // instead; from then on the exit goes ahead from this state.
            if (now < deadline && this.lateSuccessorsAt(held).length) {
                throw new BrowserWalletHttpError(EXIT_RELEASE_PENDING_MESSAGE, 409, 'exit_release_pending', {
                    reason: release.reason || null,
                    status_source: release.statusSource || null,
                    releasable_after: release.releasableAfter ?? deadAfter,
                    must_initiate_by: deadline
                });
            }
        }
        const nullifier = await this.worker.call('withdrawalNullifier', { state });
        if (existing && preparedWithdrawalNullifier(existing) != null
            && !sameFelt(preparedWithdrawalNullifier(existing), nullifier)) existing = null;

        // C3, E2.1, E3.2: the exit lock is held at this state before E1.
        let lock = this.runtime.exitLock;
        if (lock && (Number(lock.noteId) !== Number(state.note_id) || !sameFelt(lock.anchor, state.current_anchor))) {
            if (releasedExitProofs(lock).length) {
                throw new BrowserWalletHttpError('An exit proof of another balance state may still land. Check its status first.',
                    409, 'exit_lock_state');
            }
            lock = null;
        }
        const lockSetHere = !lock;
        if (!lock) {
            lock = newExitLock({ noteId: state.note_id, anchor: state.current_anchor, mode: requested, now });
            await this.commit({ ...this.runtime, exitLock: lock });
        }
        // A released escape keeps the note on escapes until it is dead.
        const request = lock.mode === 'escape' && releasedExitProofs(lock).length ? 'escape' : requested;

        // E1, bounded, and skipped once must_initiate_by has passed. An active
        // key of this tab is closed first, in one bounded call, so that a
        // finished chat settles into a fresh state (E2).
        let recovery = { installed: false, lateSuccessor: false, reading: null, response: null };
        if (now < deadline) {
            await this.exitRetireLeaseLocked({ signal });
            onProgress('recovering', 'Checking for a settled private request…');
            recovery = await this.exitRecoveryPassLocked({ signal, onProgress });
            if (recovery.installed) return WITHDRAWAL_RESTART;
        }
        await this.reload();
        const records = this.exitRecordsAt(state);
        const status = stateExitStatus({ boundAtState: state.bound_at_state || 0, records });
        if (status.challenged) {
            throw new BrowserWalletHttpError(DEVICE_NOT_NEWEST_MESSAGE, 409, 'device_not_newest', { reason: 'defeated' });
        }
        // E4.7: a released close proof of this state stays the exit until
        // its valid_until; a successor that arrived meanwhile waits (E6).
        if (request === 'mutual' && !reprove
            && this.reusablePlan(existing, { mode: 'mutual', destination, state, nullifier, conceded: 0n })) {
            return existing;
        }
        // E2.4 on a retry: once the server answered this state's ownership
        // proof with nullifier_used (kept with the lock, or with the
        // withdrawal-only marker after a cancel), the state is decided as
        // unresolved (E3) and no clearance is asked again. Lost ε (E3) is
        // decided at once, whatever the records say. decideExit is the
        // companion's decision too (the shared vectors pin both).
        const clearance = this.clearanceAnswerAt(state, nullifier);
        const lostEpsilonCharge = await this.lostEpsilonCharge(state, recovery);
        const decide = (decisionRequest, clearanceOutcome) => decideExit({ request: decisionRequest, now,
            mustInitiateBy: deadline, status, settlementWindowSeconds: this.settlementWindowSeconds(),
            unsettledAfterSeconds: this.browserConfig?.unsettled_request_escape_after_seconds,
            settlementDeadline: recovery.reading?.settlementDeadline ?? null, lostEpsilonCharge, earlyConcession,
            clearanceOutcome });
        let decision = decide(request, clearance.claimed ? 'nullifier_used' : null);
        if (decision.action === 'wait') {
            if (lockSetHere && !(this.runtime.exitLock?.released || []).length) {
                await this.commit({ ...this.runtime, exitLock: null });
            }
            throw this.settlementPendingError(decision, status, deadline,
                clearance.claimed ? { code: 'nullifier_used' } : null);
        }
        if (decision.action === 'mutual' && clearance.sent && !validClearance(existing, nullifier)) {
            // C3 allows one ownership proof per lock, and this one was
            // answered without a clearance (E2.5), or its answer was lost.
            decision = { action: 'escape', conceded: 0n, rule: 'E2.fallback', clearanceError: clearance.outcome };
        }
        if (decision.action === 'mutual') {
            if (!reprove && this.reusablePlan(existing, { mode: 'mutual', destination, state, nullifier, conceded: 0n })) {
                return existing;
            }
            if (this.runtime.exitLock.mode !== 'mutual') {
                // Nothing was released yet (else the request is an escape).
                await this.commit({ ...this.runtime, exitLock: switchExitLock(this.runtime.exitLock, 'mutual') });
            }
            const outcome = await this.prepareMutualCloseLocked({ state, destination, nullifier, existing, expectedActiveRoot,
                refusedRoot, walletRequest, signal, gasless });
            if (outcome === WITHDRAWAL_RESTART) return outcome;
            if (outcome.plan) return outcome.plan;
            const next = afterClearanceFailure(outcome.error);
            if (next.action === 'refuse') {
                if (outcome.error?.code === 'ownership_proof_wait') {
                    // C3: the state's ownership proof expires within seconds.
                    throw new BrowserWalletHttpError('This balance’s ownership proof expires in a few seconds. Try again then.',
                        409, 'ownership_proof_wait', { retry_after: outcome.error.retryAfterSeconds });
                }
                throw new BrowserWalletHttpError('This balance’s exit is frozen at another step (C3).', 409,
                    outcome.error?.code || 'exit_locked');
            }
            if (next.action === 'reconsider') {
                // E2.4: the server claims a reservation; decide as at an
                // unresolved state, from the newest released record.
                decision = decide('mutual', 'nullifier_used');
                if (decision.action === 'wait') throw this.settlementPendingError(decision, status, deadline, outcome.error);
            } else {
                decision = { ...next, clearanceError: outcome.error?.code || null };
            }
        }
        return this.prepareEscapeLocked({ state, destination, nullifier, decision, existing, deadline, reprove, refusedRoot,
            walletRequest,
            signal, gasless, onProgress });
    }

    /** The refusal of a mutual request that waits for T (E3). */
    settlementPendingError(decision, status, deadline, clearanceError = null) {
        return new BrowserWalletHttpError(
            'The server may still settle a private request sent from this balance. A mutual close waits for it; an escape is available now (conceding nothing by default) and concedes at most the request’s bound from the time shown.',
            409,
            'request_settlement_pending',
            {
                escape_at: decision.escapeAt == null ? null : decision.escapeAt * 1_000,
                must_initiate_by: deadline * 1_000,
                bound_at_state: String(status.boundAtState),
                forced_escape: { zero: '0', bound: String(status.boundAtState) },
                ...(clearanceError?.code ? { clearance_error_code: clearanceError.code } : {})
            }
        );
    }

    /**
     * Close this tab's active key in one bounded call before an exit decision,
     * so a finished chat can settle into a fresh state. Failures are ignored:
     * E1 and E3 decide without the operator.
     */
    async exitRetireLeaseLocked({ signal = null } = {}) {
        const journal = this.runtime.journal;
        const lease = this.runtime.lease;
        if (!journal?.prepared_request || !lease || lease.client_request_id !== journal.prepared_request.client_request_id) return;
        if (lease.ownerId !== this.ownerId && Number(lease.settle_after || lease.expires_at) > nowSeconds()) return;
        const request = journal.prepared_request;
        await this.exitCall(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}`,
            { method: 'POST', body: request, signal });
        if (this.activeLease?.client_request_id === request.client_request_id) {
            this.activeLease.retired = true;
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
        }
    }

    /**
     * E2: a mutual close at a fresh state: the kind-2 ownership proof (at most
     * one per lock, journaled before it leaves), the server clearance, then
     * the kind-1 close proof, journaled with its plan. Returns { plan },
     * WITHDRAWAL_RESTART, or { error } when the clearance failed.
     */
    async prepareMutualCloseLocked({ state, destination, nullifier, existing, expectedActiveRoot, refusedRoot = null,
        walletRequest = null, signal, gasless = null }) {
        let clearance = validClearance(existing, nullifier) ? existing.clearance : null;
        let path;
        // After UnknownRoot (with the clearance kept), the close proof takes
        // a path at another root; a failure reaches the caller, which may
        // still submit the existing proof (E4.5 is advisory).
        if (refusedRoot != null && clearance) {
            path = await this.exitPathLocked(state, { signal, sources: AFTER_UNKNOWN_ROOT_SOURCES, refusedRoot, walletRequest });
        }
        if (!path) {
            try {
                const timeout = AbortSignal.timeout(this.exitTiming().callTimeoutMs);
                const callSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
                const root = expectedActiveRoot ?? await abortable(this.vaultWord(VAULT_SELECTORS.currentRoot, callSignal), callSignal);
                path = await abortable(this.treePath(Number(state.note_id), true, root, callSignal), callSignal);
            } catch (error) {
                if (signal?.aborted) throw error;
                return { error: { code: 'indexer_unavailable', message: error?.message || null } };
            }
        }
        if (!clearance) {
            const result = await this.requestClearanceLocked({ state, destination, nullifier, path, existing, signal });
            if (result === WITHDRAWAL_RESTART || result.error) return result;
            clearance = result.clearance;
        }
        const lock = this.runtime.exitLock;
        const refusal = exitLockRefusal(lock, { noteId: state.note_id, anchor: state.current_anchor, proof: 'mutual' });
        if (refusal) throw new BrowserWalletHttpError('This balance is exiting by escape.', 409, refusal);
        const validUntil = nowSeconds() + this.exitTiming().exitProofValiditySeconds;
        const plan = await this.worker.call('prepareWithdrawal', {
            config: this.config.wallet_core,
            state,
            args: { mode: 'mutual', destination, valid_until: validUntil, active_root: path.active_root,
                merkle_siblings: path.siblings, clearance },
            provingKey: this.withdrawalProvingKey()
        });
        if (Number(plan?.public_inputs?.kind) !== WITHDRAWAL_KIND.mutual || Number(plan.public_inputs.conceded) !== 0) {
            throw new Error('The generated withdrawal proof is of another kind.');
        }
        const decorated = this.decoratePlan(plan, { mode: 'mutual', destination, state, nullifier, existing,
            decision: { rule: 'E2', conceded: 0n }, clearance, validUntil, pathSource: path.source || 'indexer', gasless });
        await this.commit({ ...this.runtime, preparedWithdrawal: decorated,
            exitLock: recordReleasedProof(this.runtime.exitLock, { kind: WITHDRAWAL_KIND.mutual, validUntil, nullifier, at: nowSeconds() }) });
        return { plan: decorated };
    }

    /**
     * The clearance of a mutual close (G6): one kind-2 ownership proof at the
     * current root, journaled in the exit lock and the withdrawal-only marker
     * before it is sent (C5), then one bounded POST. C3: at most one live
     * ownership proof per state, across exit locks (a cancel releases a lock
     * that released only an ownership proof). The marker keeps the state's
     * newest one: it is sent again while it stays valid, the client waits
     * while it is about to expire (ownership_proof_wait), and a new one is
     * made only once it expired (ownershipProofAction, pinned by the shared
     * vectors).
     */
    async requestClearanceLocked({ state, destination, nullifier, path, existing, signal }) {
        const lock = this.runtime.exitLock;
        const refusal = exitLockRefusal(lock, { noteId: state.note_id, anchor: state.current_anchor, proof: 'ownership' });
        if (refusal) return { error: { code: refusal } };
        const kept = keptOwnershipProof(this.runtime.preparedWithdrawal, nullifier);
        const action = ownershipProofAction(kept?.public_inputs?.valid_until ?? null, nowSeconds());
        if (action === 'wait') {
            return { error: { code: 'ownership_proof_wait',
                retryAfterSeconds: Number(kept.public_inputs.valid_until) + 1 - nowSeconds() } };
        }
        let ownership;
        if (action === 'resend') {
            this.assertOwnershipProof({ mode: 'ownership', ...kept }, { state, nullifier, activeRoot: kept.public_inputs.active_root });
            ownership = kept;
        } else {
            ownership = await this.generateOwnershipProof({ state, nullifier, path });
        }
        await this.commit({
            ...this.runtime,
            exitLock: recordReleasedProof(lock, { kind: WITHDRAWAL_KIND.ownership,
                validUntil: ownership.public_inputs.valid_until, nullifier, at: nowSeconds() }),
            // C5: never request from this state after its ownership proof.
            preparedWithdrawal: {
                phase: 'reserving', mode: 'mutual', operationId: existing?.operationId || uuid(),
                noteId: Number(state.note_id), destination, withdrawalNullifier: nullifier, clearanceReserved: true,
                ownershipProof: { public_inputs: ownership.public_inputs, proof: ownership.proof },
                createdAt: Number(existing?.createdAt || Date.now())
            }
        });
        const answer = await this.exitCall(`${this.config.funding.protocol_server_url}/v2/withdraw/clearance`, {
            method: 'POST', body: { withdrawal_nullifier: nullifier, ownership_proof: ownership }, signal
        });
        let result;
        let outcome;
        if (!answer.reachable) {
            result = { error: { code: 'unreachable', status: answer.status ?? null } };
            outcome = 'unreachable';
        } else if (!answer.ok) {
            result = { error: { code: answer.code, status: answer.status } };
            outcome = answer.code === 'nullifier_used' ? 'nullifier_used' : 'refused';
        } else if (!answer.body?.signature || answer.body.withdrawal_nullifier == null
            || !sameFelt(answer.body.withdrawal_nullifier, nullifier)) {
            result = { error: { code: 'clearance_invalid' } };
            outcome = 'invalid';
        } else {
            result = { clearance: answer.body };
            outcome = 'granted';
        }
        // The answer is kept with the lock and the withdrawal-only marker, so
        // a retry decides as this attempt does (E2.4, E2.5) without a second
        // ownership proof; a clearance is kept for a later close proof.
        await this.commit({
            ...this.runtime,
            exitLock: recordClearanceOutcome(this.runtime.exitLock, { outcome, code: result.error?.code || null }),
            preparedWithdrawal: { ...this.runtime.preparedWithdrawal, clearanceOutcome: outcome,
                ...(result.clearance ? { clearance: result.clearance } : {}) }
        });
        return result;
    }

    /**
     * The server's answer to this state's ownership proof: { sent, outcome,
     * claimed }. `claimed` (nullifier_used) also survives a cancel, through
     * the withdrawal-only marker bound to this state's nullifier.
     */
    clearanceAnswerAt(state, nullifier) {
        const lock = this.runtime?.exitLock;
        const here = Boolean(lock && Number(lock.noteId) === Number(state.note_id) && sameFelt(lock.anchor, state.current_anchor));
        const outcome = here ? ownershipOutcome(lock) : null;
        const marker = this.runtime?.preparedWithdrawal;
        const markerClaim = marker?.clearanceOutcome === 'nullifier_used' && preparedWithdrawalNullifier(marker) != null
            && sameFelt(preparedWithdrawalNullifier(marker), nullifier);
        return { sent: outcome != null, outcome, claimed: outcome === 'nullifier_used' || markerClaim };
    }

    /**
     * E4: an escape conceding `decision.conceded` (at most bound_at_state):
     * a path at a known root, the stale-device pre-check, E1 again, advisory
     * reads, then the kind-0 proof, journaled in the exit lock with its plan
     * before the plan leaves this function. A live request journal moves to
     * the archive (abandoned_for_escape), where a later receipt can still
     * install once the lock is released.
     */
    async prepareEscapeLocked({ state, destination, nullifier, decision, existing, deadline, reprove, refusedRoot = null,
        walletRequest = null, signal, gasless = null, onProgress }) {
        let lock = this.runtime.exitLock;
        if (lock.mode !== 'escape') {
            lock = switchExitLock(lock, 'escape');
            await this.commit({ ...this.runtime, exitLock: lock });
        }
        const conceded = BigInt(decision.conceded);
        const bound = BigInt(state.bound_at_state || 0);
        const refusal = exitLockRefusal(lock, { noteId: state.note_id, anchor: state.current_anchor, proof: 'escape',
            conceded, boundAtState: bound });
        if (refusal) throw new BrowserWalletHttpError('This escape is not allowed at this balance state.', 409, refusal);
        if (!reprove && this.reusablePlan(existing, { mode: 'escape', destination, state, nullifier, conceded })) return existing;
        onProgress('path', 'Finding this balance’s Merkle path…');
        const path = await this.exitPathLocked(state, { signal, walletRequest,
            ...(refusedRoot != null ? { sources: AFTER_UNKNOWN_ROOT_SOURCES, refusedRoot } : {}) });
        onProgress('checking', 'Checking that this device holds the newest balance state…');
        const { successor } = await this.staleDeviceCheckLocked(state, { signal });
        if (nowSeconds() < deadline) {
            const again = await this.exitRecoveryPassLocked({ signal, onProgress });
            if (again.installed) return WITHDRAWAL_RESTART;
        }
        const warnings = await this.exitAdvisoryWarnings(nullifier, successor, { signal });
        const validUntil = nowSeconds() + this.exitTiming().exitProofValiditySeconds;
        onProgress('proving', 'Generating the escape proof locally…');
        if (conceded > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('The conceded amount exceeds the safe ledger range.');
        const plan = await this.worker.call('prepareWithdrawal', {
            config: this.config.wallet_core,
            state,
            args: { mode: 'escape', destination, conceded: Number(conceded), valid_until: validUntil,
                active_root: path.active_root, merkle_siblings: path.siblings },
            provingKey: this.withdrawalProvingKey()
        });
        const inputs = plan?.public_inputs;
        if (Number(inputs?.kind) !== WITHDRAWAL_KIND.escape || BigInt(inputs.conceded ?? 0) !== conceded
            || BigInt(inputs.final_balance) + conceded !== BigInt(state.current_balance)) {
            throw new Error('The generated escape proof does not match its decision.');
        }
        await this.reload();
        // The withdrawal-only marker of a clearance attempt (E2.5) may be newer
        // than the plan read at the start.
        const marker = this.runtime.preparedWithdrawal;
        const base = marker && sameFelt(preparedWithdrawalNullifier(marker) ?? nullifier, nullifier) ? marker : existing;
        const decorated = this.decoratePlan(plan, { mode: 'escape', destination, state, nullifier, existing: base, decision,
            validUntil, pathSource: path.source, warnings, gasless });
        const journal = this.runtime.journal;
        const abandoned = journal ? this.tryRequestJournalRecord(journal, state, { disposition: 'abandoned_for_escape' }) : null;
        if (journal && !abandoned) throw new Error('The unsettled private request journal is incomplete.');
        await this.commit({
            ...this.runtime,
            journal: null,
            lease: null,
            preparedWithdrawal: decorated,
            exitLock: recordReleasedProof(this.runtime.exitLock, { kind: WITHDRAWAL_KIND.escape, validUntil,
                conceded, nullifier, at: nowSeconds() })
        }, abandoned ? { requestArchive: [abandoned] } : {});
        if (this.activeLease) {
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
        }
        return decorated;
    }

    /**
     * The withdrawal key descriptor. A host's provingKeysBaseUrlOverride
     * (design §6.4 E7) moves only its URL: the build-pinned SHA-256 stays.
     */
    withdrawalProvingKey() {
        const pinned = this.config.proving_keys.withdrawal;
        const override = browserSdkOptions().provingKeysBaseUrlOverride;
        return override ? { ...pinned, url: new URL('withdrawal.pk', override).href } : pinned;
    }

    /** A proof plan with the record fields the payout matchers need (E5). */
    decoratePlan(plan, { mode, destination, state, nullifier, existing, decision, clearance = null, validUntil,
        pathSource = null, warnings = [], gasless = null }) {
        const conceded = BigInt(decision.conceded ?? 0);
        // A sponsored plan (§3.2) carries its fee payer, payout address and
        // transit identity through every re-proof; a wallet-paid one none.
        const sponsored = gasless || (isGaslessWithdrawal(existing) ? { payout: existing.payout, transit: existing.transit } : null);
        const staleUserOpHashes = [...new Set([...(existing?.staleUserOpHashes || []), ...(existing?.userOpHashes || [])])];
        const staleBlocks = [existing?.staleSubmittedAtBlock, existing?.submittedAtBlock].filter(value => value != null).map(Number);
        const decorated = {
            ...(sponsored ? { feePayer: 'payout', payout: sponsored.payout.toLowerCase(), transit: structuredClone(sponsored.transit) } : {}),
            // The hashes of this plan's earlier sponsored operations stay
            // recognizable after a re-proof (a late inclusion lands on them),
            // with the earliest block their inclusion is searched from.
            ...(sponsored && staleUserOpHashes.length ? { staleUserOpHashes } : {}),
            ...(sponsored && staleUserOpHashes.length && staleBlocks.length ? { staleSubmittedAtBlock: Math.min(...staleBlocks) } : {}),
            ...plan,
            mode,
            destination,
            phase: 'prepared',
            operationId: existing?.operationId || uuid(),
            noteId: Number(state.note_id),
            withdrawalNullifier: nullifier,
            clearanceReserved: mode === 'mutual' || existing?.clearanceReserved === true,
            createdAt: Number(existing?.createdAt || Date.now()),
            decision: { rule: decision.rule, conceded: conceded.toString(),
                ...(decision.clearanceError ? { clearance_error_code: decision.clearanceError } : {}) },
            stateBalance: String(state.current_balance),
            concededAtInit: conceded.toString(),
            boundAtState: String(state.bound_at_state || 0),
            validUntil,
            ...(pathSource ? { pathSource } : {}),
            ...(warnings.length ? { warnings } : {}),
            ...(existing?.clearanceOutcome ? { clearanceOutcome: existing.clearanceOutcome } : {})
        };
        const carried = clearance || (validClearance(existing, nullifier) ? existing.clearance : null);
        if (carried?.signature) decorated.clearance = carried;
        return decorated;
    }

    validateExistingWithdrawal(prepared, mode, destination, state) {
        if (!prepared) return;
        if (Number(prepared.noteId ?? prepared.note_id ?? prepared.public_inputs?.note_id) !== Number(state.note_id)) {
            throw new Error('The prepared withdrawal belongs to a different private balance.');
        }
        const existingDestination = prepared.destination?.toLowerCase();
        const hasSubmission = Boolean(prepared.submissionId || preparedWithdrawalHashes(prepared).length);
        // Before a submission, a mutual plan may become an escape (E2.5) and
        // back; the destination never changes.
        if (existingDestination && existingDestination !== destination.toLowerCase()) {
            throw new Error('A different withdrawal is already prepared in this browser.');
        }
        if (hasSubmission && prepared.mode && prepared.mode !== mode && !(prepared.mode === 'escape' && mode === 'mutual')) {
            throw new Error('A different withdrawal is already prepared in this browser.');
        }
    }

    /**
     * A kind-2 ownership proof of exactly this state, vault, keys, root and
     * balance: no destination, no concession, no successor nullifier, and a
     * fresh valid_until. Every vault entry point rejects kind 2, so it can
     * never be submitted as an exit. Never a request proof.
     */
    assertOwnershipProof(plan, { state, nullifier, activeRoot }) {
        const inputs = plan?.public_inputs;
        const core = this.config.wallet_core || {};
        const funding = this.config.funding || {};
        const validUntil = Number(inputs?.valid_until);
        const valid = Boolean(inputs) && typeof inputs === 'object'
            && plan.mode === 'ownership'
            && plan.proof?.backend === 'groth16_bn254'
            && typeof plan.proof.proof === 'string' && plan.proof.proof.length > 0
            && inputs.kind === 2
            && Number(inputs.conceded) === 0
            && sameFelt(inputs.next_nullifier, 0)
            && Number.isSafeInteger(validUntil) && validUntil > nowSeconds()
            && validUntil <= nowSeconds() + this.exitTiming().ownershipProofValiditySeconds
            && Number(inputs.protocol_version) === 2
            && Number(inputs.chain_id) === Number(funding.chain_id)
            && sameFelt(inputs.contract_address, funding.contract_address)
            && sameFelt(inputs.state_signing_key_x, core.state_signing_key?.x)
            && sameFelt(inputs.state_signing_key_y, core.state_signing_key?.y)
            && sameFelt(inputs.clearance_signing_key_x, core.clearance_signing_key?.x)
            && sameFelt(inputs.clearance_signing_key_y, core.clearance_signing_key?.y)
            && Number(inputs.note_id) === Number(state.note_id)
            && sameFelt(inputs.withdrawal_nullifier, nullifier)
            && sameFelt(inputs.active_root, activeRoot)
            && sameFelt(inputs.final_balance, state.current_balance)
            && withdrawalDestinationHex(inputs.destination) === `0x${'0'.repeat(40)}`
            && !REQUEST_PUBLIC_INPUT_FIELDS.some(field => field in inputs);
        if (!valid) throw new Error('The generated ownership proof does not match its saved balance and vault.');
    }

    async generateOwnershipProof({ state, nullifier, path }) {
        const ownership = await this.worker.call('prepareWithdrawal', {
            config: this.config.wallet_core,
            state,
            args: {
                mode: 'ownership',
                valid_until: nowSeconds() + this.exitTiming().ownershipProofValiditySeconds
                    - this.exitTiming().ownershipProofSkewMarginSeconds,
                active_root: path.active_root,
                merkle_siblings: path.siblings
            },
            provingKey: this.withdrawalProvingKey()
        });
        this.assertOwnershipProof(ownership, { state, nullifier, activeRoot: path.active_root });
        // Only the public inputs and proof travel; nothing is persisted.
        return { public_inputs: ownership.public_inputs, proof: ownership.proof };
    }

    /**
     * The clearance of a set-aside (background) mutual close: one ownership
     * proof and one bounded POST. Its record is withdrawal-only already.
     */
    async backgroundClearance({ state, nullifier, path, signal = null }) {
        const ownership = await this.generateOwnershipProof({ state, nullifier, path });
        const answer = await this.exitCall(`${this.config.funding.protocol_server_url}/v2/withdraw/clearance`, {
            method: 'POST', body: { withdrawal_nullifier: nullifier, ownership_proof: ownership }, signal
        });
        if (!answer.ok) {
            throw new BrowserWalletHttpError(answer.reachable
                ? 'The server refused the mutual close of this set-aside balance.'
                : 'The server did not answer. The set-aside balance can still be withdrawn later.',
            answer.status || 503, answer.code || 'clearance_unavailable');
        }
        const clearance = answer.body;
        if (!clearance?.signature || clearance.withdrawal_nullifier == null || !sameFelt(clearance.withdrawal_nullifier, nullifier)) {
            throw new Error('The server returned a clearance for a different private balance state.');
        }
        return clearance;
    }

    /**
     * E7: an encrypted exit kit of the selected balance (zkapi-exit-kit-v1):
     * the build-pinned deployment profile, the state an escape needs, its
     * bound and its deposit-time Merkle path. Returns the kit as JSON for the
     * host to save; it is never uploaded.
     */
    async exportExitKit({ passphrase } = {}) {
        await this.init();
        this.preemptForExit();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const state = this.runtime.state;
            if (!state) throw new Error('There is no private balance to export.');
            const stateSeq = Number(this.runtime.stateSeq || 0);
            const payload = buildExitKitPayload({ trustedDeployment: this.browserConfig?.trusted_deployment,
                state, stateSeq, exportedAt: nowSeconds(), merklePath: state.deposit_path || null });
            const kit = await sealExitKit(payload, passphrase);
            await this.commit({ ...this.runtime, exitKitExportedSeq: stateSeq });
            return JSON.stringify(kit);
        });
    }

    /**
     * Deployment verification before a deposit (design §6.5): codehashes,
     * adapter and getters through the wallet provider that will sign, and
     * through the pinned RPC; then the canary caps with the vault balance
     * read through the wallet provider. Throws deployment_mismatch (or a
     * canary refusal); exits never depend on it.
     */
    async verifyDeploymentForDeposit({ walletRequest, depositWei }) {
        await this.assertServiceAvailable();
        const trusted = this.browserConfig?.trusted_deployment;
        const chainId = Number(this.config.funding.chain_id);
        const results = await Promise.all([
            verifyDeployment({ request: walletRequest, trusted, chainId, source: 'wallet' }),
            verifyDeployment({ request: this.pinnedRpc(), trusted, chainId, source: 'pinned_rpc' })
        ]);
        this.deploymentVerification = { checkedAt: Date.now(), ok: results.every(result => result.ok), results };
        if (!this.deploymentVerification.ok) throw deploymentMismatchError(results);
        const limits = canaryLimits(trusted, nowSeconds());
        if (limits) {
            let balance = null;
            try {
                balance = BigInt(await walletRequest({ method: 'eth_getBalance',
                    params: [this.config.funding.contract_address, 'latest'] }));
            } catch {
                balance = null;
            }
            const refusal = canaryRefusal({ limits, depositWei, vaultBalanceWei: balance });
            if (refusal) throw refusal;
        }
        return this.deploymentVerification;
    }

    async claimPreparedWithdrawalSubmission() {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            let prepared = this.runtime.preparedWithdrawal;
            if (!prepared) throw new Error('The durable prepared withdrawal is missing.');
            if (!prepared.operationId) {
                prepared = { ...prepared, operationId: uuid() };
                await this.commit({ ...this.runtime, preparedWithdrawal: prepared });
            }
            const knownHashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (knownHashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: knownHashes[0],
                    submissionId: prepared.submissionId || null,
                    operationId: prepared.operationId,
                    noteId: Number(prepared.noteId ?? prepared.public_inputs?.note_id),
                    mode: prepared.mode,
                    destination: prepared.destination,
                    finalBalance: Number(prepared.public_inputs?.final_balance
                        ?? this.runtime.state?.current_balance),
                    clearanceReserved: prepared.clearanceReserved === true
                        || prepared.mode === 'mutual',
                    withdrawalNullifier: prepared.withdrawalNullifier
                        || prepared.public_inputs?.withdrawal_nullifier
                        || null,
                    deploymentId: this.manifest.deployment_id,
                    chainId: Number(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (prepared.submissionId) {
                throw new BrowserWalletHttpError(
                    prepared.phase === 'ambiguous'
                        ? 'The previous wallet request has no transaction ID. Check its status before retrying.'
                        : 'This withdrawal is already awaiting MetaMask in this or another tab.',
                    409,
                    prepared.phase === 'ambiguous'
                        ? 'withdrawal_submission_ambiguous'
                        : 'withdrawal_wallet_pending'
                );
            }
            const now = Date.now();
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: now,
                submissionNonceJournalRequired: true
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async rememberPreparedWithdrawalSubmissionMetadata(submission, metadata) {
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The withdrawal transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            const matches = prepared
                && reference?.operationId === prepared.operationId
                && reference?.submissionId === prepared.submissionId
                && Number(reference.noteId) === Number(
                    prepared.noteId ?? prepared.public_inputs?.note_id
                )
                && reference.mode === prepared.mode
                && String(reference.destination || '').toLowerCase()
                    === String(prepared.destination || '').toLowerCase()
                && reference.deploymentId === this.manifest.deployment_id
                && Number(reference.chainId) === Number(this.config.funding.chain_id)
                && String(reference.contractAddress || '').toLowerCase()
                    === String(this.config.funding.contract_address || '').toLowerCase();
            if (!matches) {
                throw new Error('The withdrawal wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...prepared,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async claimPreparedWithdrawalReplacement(expectedFrom) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted withdrawal before replacing it.');
            }
            if (prepared.submissionId) {
                throw new Error('A replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((prepared.transactionAttempts || [])
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
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved withdrawal has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved withdrawal has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this withdrawal.`);
            }
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                submissionNonceJournalRequired: true,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPreparedWithdrawalTransaction(
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid withdrawal transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!reference?.operationId || !reference.submissionId
                || reference.deploymentId !== this.manifest.deployment_id
                || Number(reference.chainId) !== Number(this.config.funding.chain_id)
                || String(reference.contractAddress || '').toLowerCase()
                    !== String(this.config.funding.contract_address || '').toLowerCase()) {
                throw new Error('The withdrawal transaction is missing its durable operation identity.');
            }
            const sameOperation = prepared && (
                prepared.operationId === reference.operationId
                    && Number(prepared.noteId ?? prepared.public_inputs?.note_id) === Number(reference.noteId)
                    && prepared.mode === reference.mode
                    && prepared.destination?.toLowerCase() === reference.destination?.toLowerCase()
            );
            if (!sameOperation) {
                const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                    ? this.runtime.lateWithdrawalAttempts
                    : [];
                const lateAttempt = {
                    operationId: reference.operationId || null,
                    submissionId: reference.submissionId || null,
                    noteId: Number(reference.noteId),
                    mode: reference.mode || null,
                    destination: reference.destination || null,
                    finalBalance: Number(reference.finalBalance),
                    clearanceReserved: reference.clearanceReserved === true
                        || reference.mode === 'mutual',
                    withdrawalNullifier: reference.withdrawalNullifier || null,
                    deploymentId: reference.deploymentId,
                    chainId: Number(reference.chainId),
                    contractAddress: reference.contractAddress,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared?.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared?.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared?.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared?.submissionNonce)
                        : null,
                    observedAt: Date.now(),
                    status: 'submitted_late'
                };
                const deduplicated = attempts.filter(attempt => !(
                    attempt.operationId === lateAttempt.operationId
                    && attempt.transactionHash === lateAttempt.transactionHash
                ));
                await this.commit({
                    ...this.runtime,
                    lateWithdrawalAttempts: retainAttemptHistory(
                        [...deduplicated, lateAttempt],
                        LATE_WITHDRAWAL_TERMINAL_STATUSES
                    )
                });
                return { late: true, ...lateAttempt };
            }
            // A wallet prompt can outlive its cross-tab ownership claim. Never
            // reject a late valid hash: retaining every broadcast is the only
            // safe way to reconcile a takeover without losing an on-chain tx.
            const transactionHashes = [...new Set([
                ...(Array.isArray(prepared.transactionHashes)
                    ? prepared.transactionHashes
                    : prepared.transactionHash ? [prepared.transactionHash] : []),
                transactionHash
            ].map(value => value.toLowerCase()))];
            const transactionAttempts = [
                ...(Array.isArray(prepared.transactionAttempts)
                    ? prepared.transactionAttempts.filter(attempt => attempt.hash !== transactionHash.toLowerCase())
                    : []),
                {
                    hash: transactionHash.toLowerCase(),
                    submissionId: reference.submissionId || null,
                    operationId: prepared.operationId,
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared.submissionNonce)
                        : null,
                    observedAt: Date.now()
                }
            ];
            const next = {
                ...prepared,
                phase: 'submitted',
                transactionHash: transactionHashes[0],
                transactionHashes,
                transactionAttempts,
                submissionOutcome: 'submitted',
                ...(reference.submissionId && prepared.submissionId !== reference.submissionId
                    ? { concurrentSubmissionObserved: true }
                    : {})
            };
            if (reference.submissionId && prepared.submissionId === reference.submissionId) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async currentLateWithdrawalAttempts() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return (this.runtime.lateWithdrawalAttempts || []).map(attempt => ({ ...attempt }));
        });
    }

    async updateLateWithdrawalAttempt(operationId, transactionHash, changes = {}, {
        expectedStatus = null
    } = {}) {
        await this.init();
        const normalizedHash = String(transactionHash || '').toLowerCase();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(attempt =>
                attempt.operationId === operationId
                && String(attempt.transactionHash || '').toLowerCase() === normalizedHash);
            if (index < 0) return null;
            const current = attempts[index];
            if (expectedStatus != null && current.status !== expectedStatus) {
                throw new Error('The late withdrawal attempt changed while its receipt was being checked.');
            }
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(current.status)
                && changes.status && changes.status !== current.status) {
                return { ...current };
            }
            const nextAttempt = {
                ...current,
                ...changes,
                updatedAt: Date.now()
            };
            const nextAttempts = [...attempts];
            nextAttempts[index] = nextAttempt;
            await this.commit({
                ...this.runtime,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async transferLateWithdrawalAttempt(attempt, record) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const detachesSelectedNote = this.runtime.deploymentId === attempt.deploymentId
                && this.runtime.state
                && Number(this.runtime.state.note_id) === Number(attempt.noteId);
            const result = await transferBrowserLateWithdrawalAttempt({
                operationId: attempt.operationId,
                transactionHash: attempt.transactionHash,
                deploymentId: attempt.deploymentId,
                chainId: Number(attempt.chainId),
                contractAddress: attempt.contractAddress,
                noteId: Number(attempt.noteId)
            }, record);
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (detachesSelectedNote) this.activeLease = null;
            this.notify();
            return result;
        });
    }

    async releaseBackgroundWithdrawalStartSubmission(submission, options = {}) {
        await this.init();
        const recordId = this.withdrawalRecordId(submission?.noteId);
        let result = await releaseBrowserWithdrawalStartSubmission(
            recordId,
            submission,
            options
        );
        // Test adapters and older embedders may provide a runtime persistence
        // layer without the shared IndexedDB stores. The production path above
        // atomically checks both owners; this fallback preserves that adapter
        // contract without creating a gap between production ownership checks.
        if (!result) {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (prepared?.submissionId === submission?.submissionId
                && prepared.operationId === submission?.operationId) {
                const released = options.replacementUnknown
                    ? await this.releasePreparedWithdrawalReplacementClaim(
                        submission,
                        options.message || null
                    )
                    : await this.markPreparedWithdrawalRetryable(null, submission);
                result = released ? { location: 'selected', runtime: this.runtime } : null;
            }
        }
        await this.reload();
        this.notify();
        return result;
    }

    async resolveLateChallengedWithdrawalAttempt(attempt) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(entry =>
                entry.operationId === attempt.operationId
                && String(entry.transactionHash || '').toLowerCase()
                    === String(attempt.transactionHash || '').toLowerCase()
                && Number(entry.noteId) === Number(attempt.noteId));
            if (index < 0) throw new Error('The challenged withdrawal attempt is no longer available.');
            const currentAttempt = attempts[index];
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(currentAttempt.status)) {
                return { ...currentAttempt };
            }
            const selectedOwns = Number(this.runtime.state?.note_id) === Number(attempt.noteId);
            const backgroundOwns = this.withdrawals.some(record =>
                Number(record.noteId) === Number(attempt.noteId) && record.state);
            if (!selectedOwns && !backgroundOwns) {
                throw new Error('The challenged withdrawal has no recoverable private note.');
            }
            const clearanceReserved = currentAttempt.clearanceReserved === true
                || currentAttempt.mode === 'mutual';
            const preparedWithdrawal = selectedOwns && clearanceReserved
                ? this.runtime.preparedWithdrawal || {
                    phase: 'prepared',
                    mode: currentAttempt.mode === 'mutual' ? 'mutual' : 'escape',
                    operationId: currentAttempt.operationId,
                    noteId: Number(currentAttempt.noteId),
                    destination: currentAttempt.destination,
                    withdrawalNullifier: currentAttempt.withdrawalNullifier || null,
                    clearanceReserved: true,
                    submissionOutcome: 'challenged',
                    createdAt: Number(currentAttempt.observedAt || Date.now())
                }
                : this.runtime.preparedWithdrawal;
            const nextAttempt = {
                ...currentAttempt,
                status: 'challenged',
                resolvedAt: Date.now(),
                error: null
            };
            const nextAttempts = attempts.map((entry, entryIndex) => {
                if (entryIndex === index) return nextAttempt;
                return Number(entry.noteId) === Number(currentAttempt.noteId)
                    && entry.deploymentId === currentAttempt.deploymentId
                    && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status)
                    ? {
                        ...entry,
                        status: 'superseded',
                        supersededBy: currentAttempt.transactionHash,
                        resolvedAt: Date.now(),
                        error: null
                    }
                    : entry;
            });
            await this.commit({
                ...this.runtime,
                preparedWithdrawal,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async markPreparedWithdrawalRetryable(expectedTransactionHash = null, submission = null) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!expectedTransactionHash && (!reference?.operationId || !reference.submissionId)) {
                throw new Error('The withdrawal retry is missing its durable operation identity.');
            }
            if (reference?.operationId && prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The withdrawal transaction changed while its receipt was being checked.');
            }
            if (!expectedTransactionHash && reference.submissionId
                && prepared.submissionId !== reference.submissionId) {
                throw new Error('The withdrawal submission changed while MetaMask was open.');
            }
            const remainingHashes = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const remainingAttempts = Array.isArray(prepared.transactionAttempts)
                ? prepared.transactionAttempts.filter(attempt => !expectedTransactionHash
                    || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : [];
            const releasesClaim = !expectedTransactionHash
                && reference?.submissionId
                && prepared.submissionId === reference.submissionId;
            const survivingClaimPhase = prepared.submissionId && !releasesClaim
                ? (prepared.submissionOutcome === 'ambiguous' || prepared.phase === 'ambiguous'
                    ? 'ambiguous'
                    : 'awaiting_wallet')
                : 'prepared';
            const next = {
                ...prepared,
                phase: remainingHashes.length
                    ? 'submitted'
                    : survivingClaimPhase,
                transactionHashes: remainingHashes,
                transactionAttempts: remainingAttempts,
                submissionOutcome: remainingHashes.length
                    ? 'submitted'
                    : releasesClaim
                        ? 'explicitly_rejected'
                        : prepared.submissionId
                            ? prepared.submissionOutcome
                            : expectedTransactionHash ? 'reverted' : prepared.submissionOutcome
            };
            if (remainingHashes.length) {
                next.transactionHash = remainingHashes[0];
            } else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The withdrawal transactions changed while their receipts were checked.');
            }
            // A second tab may already be replacing this transaction. Preserve
            // that live claim rather than regressing its UI/state phase.
            if (prepared.submissionId) return prepared;
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!prepared || !reference?.submissionId || !reference.operationId
                || prepared.submissionId !== reference.submissionId
                || prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed before its ambiguous result could be saved.');
            }
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async releasePreparedWithdrawalReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.submissionId !== submission?.submissionId
                || prepared.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The replacement wallet request changed before it could be released.');
            }
            const history = Array.isArray(prepared.ambiguousReplacements)
                ? prepared.ambiguousReplacements
                : [];
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: prepared.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: prepared.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async authorizePreparedWithdrawalRetry() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'ambiguous' || !prepared.submissionId) {
                throw new Error('There is no ambiguous wallet request to retry.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) throw new Error('Check the submitted transaction before retrying.');
            const history = Array.isArray(prepared.ambiguousSubmissions)
                ? prepared.ambiguousSubmissions
                : [];
            const next = {
                ...prepared,
                phase: 'prepared',
                submissionOutcome: 'retry_authorized',
                ambiguousSubmissions: [...history, {
                    submissionId: prepared.submissionId,
                    startedAt: prepared.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async clearPreparedWithdrawal({
        force = false,
        expectedNoteId = null,
        expectedTransactionHashes = null
    } = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            if (expectedNoteId != null
                && Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(expectedNoteId)) {
                throw new Error('The selected withdrawal changed before it could be cleared.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHashes) {
                const normalize = values => [...values].map(value => value.toLowerCase()).sort();
                if (JSON.stringify(normalize(hashes))
                    !== JSON.stringify(normalize(expectedTransactionHashes))) {
                    throw new Error('The withdrawal transactions changed before recovery completed.');
                }
            }
            if (!force && (prepared.mode === 'mutual' || prepared.clearanceReserved === true)) {
                throw new Error('This balance already has a mutual-close authorization and must remain withdrawal-only.');
            }
            // Even force recovery must preserve a hashless MetaMask claim: its
            // delayed callback still needs a durable owner in this exact note.
            if (prepared.submissionId) {
                throw new Error('A MetaMask withdrawal request is still unresolved. Close or finish that prompt before clearing this balance.');
            }
            if (!force && hashes.length) {
                throw new Error('This withdrawal may already be in MetaMask. Check its transaction status before canceling it.');
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: null });
            return null;
        });
    }

    async recoverPreparedWithdrawalSubmissionClaim() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) return prepared || null;
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) return prepared;
            // A reload cannot prove whether another tab still has MetaMask
            // open. Preserve the claim until the provider returns a definite
            // rejection or the user explicitly starts recovery.
            return prepared;
        });
    }

    async markPreparedWithdrawalUnknown(message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) {
                throw new Error('There is no wallet request waiting to be recovered.');
            }
            if (prepared.phase === 'ambiguous') return prepared;
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async resolveChallengedPreparedEscape(noteId, expectedTransactionHashes = []) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.mode !== 'escape' || prepared.clearanceReserved !== true
                || Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(noteId)) {
                throw new Error('The challenged escape no longer matches the selected balance.');
            }
            if (prepared.submissionId) {
                throw new Error('A wallet request is still unresolved for this balance.');
            }
            const normalize = values => [...values].map(value => value.toLowerCase()).sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes)) !== JSON.stringify(normalize(expectedTransactionHashes))) {
                throw new Error('The withdrawal transactions changed while the challenge was being checked.');
            }
            const next = {
                phase: 'prepared',
                mode: 'escape',
                operationId: prepared.operationId,
                noteId: Number(noteId),
                destination: prepared.destination,
                withdrawalNullifier: prepared.withdrawalNullifier
                    || prepared.public_inputs?.withdrawal_nullifier
                    || null,
                clearanceReserved: true,
                submissionOutcome: 'challenged',
                createdAt: Number(prepared.createdAt || Date.now())
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    withdrawalRecordId(noteId) {
        return [
            this.manifest.deployment_id,
            Number(this.config?.funding?.chain_id),
            String(this.config?.funding?.contract_address || '').toLowerCase(),
            Number(noteId)
        ].join(':');
    }

    async detachEscapeWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const phase = details.phase === 'challenged_unconfirmed'
                ? 'challenged_unconfirmed'
                : 'pending';
            // E5: what the payout matchers need, from the escape's plan (B, its
            // initial concession, the state's bound) unless given.
            const prepared = this.runtime.preparedWithdrawal;
            const concession = Object.fromEntries(['stateBalance', 'concededAtInit', 'boundAtState', 'validUntil']
                .map(field => [field, details[field] ?? prepared?.[field] ?? null])
                .filter(([, value]) => value != null)
                .map(([field, value]) => [field, field === 'validUntil' ? Number(value) : String(value)]));
            const result = await detachBrowserEscapeWithdrawal({
                ...concession,
                // A sponsored escape keeps its transit identity and the debt
                // its initiation recorded (§3.2); a wallet-paid one adds nothing.
                ...gaslessRecordFields(details.feePayer ? details : prepared),
                ...gaslessOutcomeFields(details),
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: 'escape',
                phase,
                chainStatus: details.chainStatus
                    || (phase === 'challenged_unconfirmed' ? 'active' : 'pending_withdrawal'),
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                challengeDeadline: Number(details.challengeDeadline),
                transactionHash: details.transactionHash || null,
                startBlockNumber: Number(details.startBlockNumber || 0),
                challengeObservedBlock: Number(details.challengeObservedBlock || 0),
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                createdAt: Number(details.createdAt || Date.now())
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async detachClosedWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const result = await detachBrowserClosedWithdrawal({
                // A sponsored close keeps its transit identity and settlement
                // amounts (§3.2); a wallet-paid one adds nothing.
                ...gaslessRecordFields(details.feePayer ? details : this.runtime.preparedWithdrawal),
                ...gaslessOutcomeFields(details),
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: details.mode,
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                transactionHash: details.transactionHash || null,
                closeBlockNumber: Number(details.closeBlockNumber || 0),
                payoutVerified: details.payoutVerified === true,
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                clearanceReserved: details.clearanceReserved === true,
                createdAt: Number(details.createdAt || Date.now()),
                closedAt: Date.now()
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    backgroundWithdrawalIdentity(record) {
        return { recordId: record?.recordId, deploymentId: this.manifest.deployment_id,
            chainId: Number(this.config.funding.chain_id), contractAddress: this.config.funding.contract_address,
            noteId: Number(record?.noteId), mode: record?.mode, destination: record?.destination };
    }

    async repairUnsubmittedBackgroundWithdrawal(recordId, observedBlock, expectedRevision) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) return null;
        const result = await repairBrowserUnsubmittedBackgroundWithdrawal(
            this.backgroundWithdrawalIdentity(record), Number(observedBlock), expectedRevision);
        await this.reload();
        if (result && Number(result.revision) !== Number(expectedRevision)) this.notify();
        return result;
    }

    async resolveBackgroundWithdrawalForRetry(recordId, evidence) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await resolveBrowserBackgroundWithdrawalForRetry(
            this.backgroundWithdrawalIdentity(record), evidence);
        await this.reload();
        this.notify();
        return result;
    }

    async prepareBackgroundWithdrawal(recordId, { expectedActiveRoot, refusedRoot = null, walletRequest = null } = {}) {
        await this.init();
        await this.reload();
        const record = structuredClone(this.withdrawals.find(entry => entry.recordId === recordId));
        const identity = this.backgroundWithdrawalIdentity(record);
        assertBrowserBackgroundWithdrawalAvailable(record, this.runtime, identity);
        if (expectedActiveRoot == null) throw new Error('A current vault root is required to prepare this withdrawal.');
        const state = record.state;
        const config = this.config;
        if (Number(state.chain_id) !== identity.chainId || !sameFelt(state.contract_address, identity.contractAddress)) {
            throw new Error('The saved private state belongs to a different vault.');
        }
        const nullifier = await this.worker.call('withdrawalNullifier', { state });
        const savedNullifiers = [record.withdrawalNullifier, record.preparedWithdrawal?.withdrawalNullifier,
            record.preparedWithdrawal?.public_inputs?.withdrawal_nullifier].filter(value => value != null);
        if (savedNullifiers.some(value => !sameFelt(value, nullifier))) {
            throw new Error('The saved withdrawal authorization does not match its private balance.');
        }
        // Deliberately outside the global wallet lock: a proof or indexer wait
        // must not stall unrelated deposits, requests, or settlement in another tab.
        // A persisted clearance for this exact nullifier needs no second
        // ownership proof or server request when only the root moved.
        let clearance = validClearance(record.preparedWithdrawal, nullifier)
            ? record.preparedWithdrawal.clearance
            : null;
        let path;
        if (clearance) {
            // The close proof needs only a root the vault ever held (A1):
            // the deposit-time path first, then the indexer at the vault's
            // current root, then the vault's logs; never the operator alone.
            path = await this.exitPathLocked(state, { currentRoot: expectedActiveRoot, walletRequest,
                ...(refusedRoot != null ? { sources: AFTER_UNKNOWN_ROOT_SOURCES, refusedRoot } : {}) });
        } else {
            // A record set aside before its clearance (an earlier build): the
            // ownership proof needs a root within the server's window.
            path = await this.treePath(identity.noteId, true, expectedActiveRoot);
            clearance = await this.backgroundClearance({ state, nullifier, path });
        }
        const plan = await this.worker.call('prepareWithdrawal', {
            config: config.wallet_core, state,
            args: { mode: 'mutual', destination: identity.destination,
                valid_until: nowSeconds() + this.exitTiming().exitProofValiditySeconds, active_root: path.active_root,
                merkle_siblings: path.siblings, clearance }, provingKey: this.withdrawalProvingKey()
        });
        const inputs = plan.public_inputs;
        const encodedDestination = Array.isArray(inputs?.destination)
            ? `0x${inputs.destination.map(value => Number(value).toString(16).padStart(2, '0')).join('')}`
            : inputs?.destination;
        if (!plan.proof || Number(inputs?.note_id) !== identity.noteId
            || Number(inputs?.chain_id) !== identity.chainId
            || !sameFelt(inputs?.contract_address, identity.contractAddress)
            || !sameFelt(inputs?.active_root, path.active_root)
            || !sameFelt(inputs?.withdrawal_nullifier, nullifier)
            || !sameFelt(inputs?.final_balance, state.current_balance)
            || String(encodedDestination || '').toLowerCase() !== identity.destination.toLowerCase()
            || inputs?.kind !== 1 || Number(inputs?.conceded) !== 0 || !sameFelt(inputs?.next_nullifier, 0)) {
            throw new Error('The generated withdrawal proof does not match its saved balance and vault.');
        }
        Object.assign(plan, { destination: identity.destination, mode: 'mutual', phase: 'prepared',
            ...(path.source ? { pathSource: path.source } : {}),
            operationId: uuid(), noteId: identity.noteId, withdrawalNullifier: nullifier,
            clearanceReserved: true, createdAt: Number(record.createdAt || Date.now()),
            ...(clearance?.signature ? { clearance } : {}) });
        await saveBrowserBackgroundWithdrawalPlan(identity, record, plan);
        await this.reload();
        this.notify();
        return plan;
    }

    async claimBackgroundWithdrawalSubmission(recordId, expectedOperationId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await claimBrowserBackgroundWithdrawalSubmission(
            this.backgroundWithdrawalIdentity(record), expectedOperationId, this.ownerId);
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalSubmissionMetadata(submission, metadata) {
        const result = await rememberBrowserBackgroundWithdrawalMetadata(submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async markBackgroundWithdrawalAmbiguous(submission, message) {
        const result = await markBrowserBackgroundWithdrawalAmbiguous(submission, message);
        await this.reload();
        this.notify();
        return result;
    }

    async releaseBackgroundWithdrawalSubmission(submission) {
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission);
        await this.reload();
        this.notify();
        return result;
    }

    async cancelBackgroundWithdrawalPreparation(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) throw new Error('This saved withdrawal is no longer available.');
        const submission = { ...this.backgroundWithdrawalIdentity(record),
            submissionId: record.startSubmissionId, operationId: record.startOperationId };
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission, { requireNoNonce: true });
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalTransaction(hash, submission, metadata = null) {
        const result = await rememberBrowserBackgroundWithdrawalTransaction(hash, submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async parkPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const noteId = Number(this.runtime.state?.note_id);
            if (!prepared || (prepared.mode !== 'mutual' && prepared.clearanceReserved !== true)
                || !Number.isFinite(noteId)) {
                throw new Error('There is no withdrawal-only balance to set aside.');
            }
            // A set-aside note leaves only by its mutual close. Without a
            // granted clearance that close depends on the operator, so the
            // note exits through the exit rules (escape) instead.
            if (!preparedWithdrawalParkable(prepared, this.runtime.exitLock)) {
                throw new BrowserWalletHttpError(PARK_REQUIRES_CLEARANCE_MESSAGE, 409, 'park_requires_clearance');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (!['reserving', 'prepared'].includes(prepared.phase || 'prepared')
                || prepared.submissionId || hashes.length) {
                throw new Error('Check the submitted withdrawal before setting this balance aside.');
            }
            const result = await parkBrowserWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: prepared.mode,
                phase: 'parked',
                noteId,
                destination: prepared.destination,
                finalBalance: Number(prepared.public_inputs?.final_balance
                    ?? this.runtime.state.current_balance),
                createdAt: Number(prepared.createdAt || Date.now())
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async updateWithdrawal(recordId, changes = {}, options = {}) {
        await this.init();
        const updated = await updateBrowserWithdrawal(recordId, changes, options);
        await this.reload();
        this.notify();
        return updated;
    }

    async currentPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.preparedWithdrawal
                ? structuredClone(this.runtime.preparedWithdrawal)
                : null;
        });
    }

    async currentWithdrawal(recordId) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            return record ? structuredClone(record) : null;
        });
    }

    /** Every withdrawal record of this deployment, re-read under the wallet lock. */
    async currentWithdrawals() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return structuredClone(this.withdrawals);
        });
    }

    async claimBackgroundWithdrawalStartReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalStartReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalization(recordId, { resumeUserOp = false, liveWindowMs = GASLESS_TIMING.resendAfterMs } = {}) {
        await this.init();
        // A sponsored finalization journaled earlier (finalizeUserOp) is
        // self-describing: its claim is taken over unless a client still
        // follows it (§3.2), as for a prepared plan's operation.
        const takeOver = resumeUserOp ? record => !this.gaslessClaimLive({
            submissionId: record.finalizeSubmissionId, owner: record.finalizeSubmissionOwner,
            lastActiveAt: Math.max(Number(record.finalizeSubmissionStartedAt || 0), Number(record.finalizeUserOpSubmittedAt || 0),
                Number(record.finalizeUserOpFollowedAt || 0))
        }, liveWindowMs) : null;
        let result;
        try {
            result = await claimBrowserWithdrawalFinalization(
                recordId,
                this.ownerId,
                { takeOver }
            );
        } catch (error) {
            // On the sponsored path a live claim is refused like a prepared
            // plan's (409 withdrawal_wallet_pending), so hosts can branch on
            // the code; the wallet path keeps its refusal unchanged.
            if (resumeUserOp && error?.message === FINALIZATION_CLAIM_LIVE_MESSAGE) {
                throw new BrowserWalletHttpError(error.message, 409, 'withdrawal_wallet_pending');
            }
            throw error;
        }
        if (resumeUserOp && result?.submissionId && !result.transactionHash) this.liveGaslessClaims.add(result.submissionId);
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalizationReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalFinalizationReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalization(
        recordId,
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalization(
            recordId,
            transactionHash,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalizationSubmissionMetadata(
        recordId,
        submission,
        transactionMetadata
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalizationSubmissionMetadata(
            recordId,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalization(recordId, options = {}) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalization(recordId, options);
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationMissingReceipts(recordId, expectedTransactionHashes) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationMissingReceipts(
            recordId,
            expectedTransactionHashes
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalizationReplacementClaim(
        recordId,
        submission,
        message = null
    ) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalizationReplacementClaim(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationAmbiguous(recordId, submission, message = null) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationAmbiguous(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationUnknown(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no finalization wallet request waiting to be recovered.');
        }
        if (record.phase === 'ambiguous') return record;
        return this.markWithdrawalFinalizationAmbiguous(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: Number(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, 'The wallet prompt was closed before a transaction ID was saved.');
    }

    async resolveChallengedWithdrawalFinalization(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no challenged wallet prompt to release.');
        }
        const result = await resolveBrowserChallengedFinalization(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: Number(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, { expectedRevision, observedBlock });
        await this.reload();
        this.notify();
        return result;
    }

    async authorizeWithdrawalFinalizationRetry(recordId) {
        await this.init();
        const result = await authorizeBrowserWithdrawalFinalizationRetry(recordId);
        await this.reload();
        this.notify();
        return result;
    }

    async restoreWithdrawal(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            if (!record) throw new Error('The recoverable private balance is no longer available.');
            if (expectedRevision == null || Number(record.revision) !== Number(expectedRevision)) {
                throw new Error('The withdrawal changed after its on-chain status was checked. Check it again before selecting this balance.');
            }
            const chainFloor = Math.max(
                Number(record.startBlockNumber || 0),
                Number(record.lastObservedBlock || 0)
            );
            if (observedBlock == null || Number(observedBlock) < chainFloor) {
                throw new Error('The connected RPC has not caught up to this withdrawal. Check it again before selecting this balance.');
            }
            const runtime = await restoreBrowserWithdrawal(recordId, {
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            }, expectedRevision);
            this.runtime = runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.notify();
            return this.walletStatus();
        });
    }

    async archiveNote(reason = 'closed', expectedNoteId = null) {
        await this.init();
        if (expectedNoteId == null) {
            throw new Error('Archiving a private note requires its exact note identity.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = expectedNoteId ?? this.runtime.state?.note_id;
            if (reason === 'expiry-claimed' && this.activeLease?.inFlight > 0) {
                throw new Error('Finish the current response before starting a new private balance.');
            }
            this.runtime = await archiveBrowserWallet(reason, noteId);
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (reason === 'expiry-claimed' && this.settlementTimer) {
                clearTimeout(this.settlementTimer);
                this.settlementTimer = null;
            }
            this.activeLease = null;
            this.notify();
            return this.walletStatus();
        });
    }
}

const browserWalletRuntime = new BrowserWalletRuntime();
export { BrowserWalletHttpError, BrowserWalletRuntime };
export default browserWalletRuntime;
