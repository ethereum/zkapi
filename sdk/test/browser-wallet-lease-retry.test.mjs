import { nativeFunding, nativeQuote } from './helpers/native-fixtures.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

// The browser runtime's OA transport installs a diagnostic singleton on
// window at module load time. No DOM is needed for these focused runtime tests.
globalThis.window = { location: { hostname: 'localhost' } };

const {
    BrowserWalletHttpError,
    BrowserWalletRuntime
} = await import('../services/browserWalletRuntime.js');

function retryableError(message = 'internal error: OA returned 429 Too Many Requests') {
    return new BrowserWalletHttpError(message, 500, 'internal_error', {
        status: 'error',
        error_code: 'internal_error',
        error_message: message,
        retriable: true
    });
}

function runtimeForLeaseRequests() {
    const runtime = new BrowserWalletRuntime();
    runtime.config = {
        funding: nativeFunding(),
        request_charge_cap: 50_000,
        credits_per_usd: 1_000_000
    };
    runtime.nativeBillingQuote = async () => nativeQuote(runtime.config.funding);
    return runtime;
}

test('request prover pre-warming coalesces success and retries a failed preload', async () => {
    const runtime = new BrowserWalletRuntime();
    const descriptor = { url: 'https://example.test/request.pk', sha256: 'abc123' };
    runtime.config = { proving_keys: { request: descriptor } };
    let attempts = 0;
    let releaseFirst;
    runtime.worker = {
        call(operation, payload) {
            attempts += 1;
            assert.equal(operation, 'preloadRequestProver');
            assert.equal(payload.provingKey, descriptor);
            if (attempts === 1) {
                return new Promise(resolve => { releaseFirst = resolve; });
            }
            if (attempts === 2) return Promise.reject(new Error('temporary preload failure'));
            return Promise.resolve({ status: 'ready' });
        }
    };

    const first = runtime.prewarmRequestProver();
    const coalesced = runtime.prewarmRequestProver();
    assert.equal(first, coalesced);
    assert.equal(attempts, 1);
    releaseFirst({ status: 'ready' });
    assert.equal(await first, true);
    assert.equal(await runtime.prewarmRequestProver(), true);
    assert.equal(attempts, 1, 'a successful warm-up stays resident for the worker lifetime');

    runtime.requestProverWarmup = null;
    const originalWarn = console.warn;
    const warnings = [];
    console.warn = (...args) => warnings.push(args);
    try {
        assert.equal(await runtime.prewarmRequestProver(), false);
    } finally {
        console.warn = originalWarn;
    }
    assert.equal(attempts, 2);
    assert.equal(warnings.length, 1);
    assert.equal(runtime.requestProverWarmup, null);
    assert.equal(await runtime.prewarmRequestProver(), true);
    assert.equal(attempts, 3);
});

test('funded wallet status resolves before its background prover warm-up starts', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.init = async () => {};
    runtime.runtime = { state: { note_id: 7 }, journal: null };
    let releaseStatus;
    let markStatusStarted;
    const statusStarted = new Promise(resolve => { markStatusStarted = resolve; });
    runtime.worker = {
        call(operation) {
            assert.equal(operation, 'walletStatus');
            markStatusStarted();
            return new Promise(resolve => { releaseStatus = resolve; });
        }
    };
    let warmups = 0;
    runtime.prewarmRequestProver = () => {
        warmups += 1;
        return Promise.resolve(true);
    };

    const pendingStatus = runtime.walletStatus();
    await statusStarted;
    assert.equal(warmups, 0);
    releaseStatus({ has_note: true, note: { note_id: 7 } });
    assert.equal((await pendingStatus).has_note, true);
    assert.equal(warmups, 1);
});

test('same-session lease callers receive the same live private-access progress', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { credits_per_usd: 1_000_000 };
    runtime.ownerId = 'same-tab';
    runtime.runtime = { lease: null };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;

    let markIssuanceStarted;
    const issuanceStarted = new Promise(resolve => { markIssuanceStarted = resolve; });
    let releaseIssuance;
    const issuanceGate = new Promise(resolve => { releaseIssuance = resolve; });
    const lease = {
        sessionId: 'chat-a',
        api_key: 'ephemeral-key',
        expires_at: Math.floor(Date.now() / 1000) + 300,
        spending_limit_usd: 1
    };
    runtime.issueLease = async (sessionId, onProgress) => {
        assert.equal(sessionId, 'chat-a');
        onProgress('checking', 'Checking for unfinished private activity…');
        markIssuanceStarted();
        await issuanceGate;
        onProgress('proving', 'Proving this chat is funded…');
        return lease;
    };

    const firstProgress = [];
    const secondProgress = [];
    let markSecondProgress;
    const secondProgressObserved = new Promise(resolve => { markSecondProgress = resolve; });
    const first = runtime.ensureLease(
        'chat-a',
        (phase, message) => firstProgress.push({ phase, message })
    );
    await issuanceStarted;
    const second = runtime.ensureLease(
        'chat-a',
        (phase, message) => {
            secondProgress.push({ phase, message });
            markSecondProgress();
        }
    );
    await secondProgressObserved;

    assert.deepEqual(secondProgress, [{
        phase: 'checking',
        message: 'Checking for unfinished private activity…'
    }], 'a title/body caller joining the same chat receives the current phase immediately');

    releaseIssuance();
    assert.equal(await first, lease);
    assert.equal(await second, lease);
    assert.deepEqual(firstProgress, [
        { phase: 'checking', message: 'Checking for unfinished private activity…' },
        { phase: 'proving', message: 'Proving this chat is funded…' }
    ]);
    assert.deepEqual(secondProgress, firstProgress);
    assert.equal(runtime.leaseProgressListeners.size, 0);
    assert.equal(runtime.lastLeaseProgress, null);
});

test('canceling one shared lease waiter leaves the other caller and proof job running', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { credits_per_usd: 1_000_000 };
    runtime.ownerId = 'same-tab';
    runtime.runtime = { lease: null };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;

    let markStarted;
    const started = new Promise(resolve => { markStarted = resolve; });
    let releaseIssuance;
    const issuanceGate = new Promise(resolve => { releaseIssuance = resolve; });
    let sharedSignal = null;
    const lease = {
        sessionId: 'chat-a',
        api_key: 'ephemeral-key',
        expires_at: Math.floor(Date.now() / 1000) + 300,
        spending_limit_usd: 1
    };
    runtime.issueLease = async (_sessionId, onProgress, signal) => {
        sharedSignal = signal;
        onProgress('checking', 'Checking for unfinished private activity…');
        markStarted();
        await issuanceGate;
        onProgress('proving', 'Proving this chat is funded…');
        return lease;
    };

    const firstController = new AbortController();
    const secondController = new AbortController();
    const firstProgress = [];
    const secondProgress = [];
    const first = runtime.ensureLease(
        'chat-a',
        phase => firstProgress.push(phase),
        firstController.signal
    );
    await started;
    const second = runtime.ensureLease(
        'chat-a',
        phase => secondProgress.push(phase),
        secondController.signal
    );

    firstController.abort();
    await assert.rejects(first, error => error?.name === 'AbortError');
    assert.equal(sharedSignal.aborted, false, 'the remaining title/body waiter still owns the shared job');
    releaseIssuance();
    assert.equal(await second, lease);
    assert.deepEqual(firstProgress, ['checking'], 'the canceled caller unsubscribes from later proof phases');
    assert.deepEqual(secondProgress, ['checking', 'proving']);
    assert.equal(runtime.leaseWaiterCount, 0);
});

test('the shared lease job aborts once its final waiter cancels', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { credits_per_usd: 1_000_000 };
    runtime.ownerId = 'same-tab';
    runtime.runtime = { lease: null };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;

    let markStarted;
    const started = new Promise(resolve => { markStarted = resolve; });
    let sharedSignal = null;
    runtime.issueLease = async (_sessionId, onProgress, signal) => {
        sharedSignal = signal;
        onProgress('proving', 'Proving this chat is funded…');
        markStarted();
        await new Promise((_, reject) => {
            signal.addEventListener('abort', () => {
                const error = new DOMException('The operation was aborted.', 'AbortError');
                error.isCancelled = true;
                reject(error);
            }, { once: true });
        });
    };

    const controller = new AbortController();
    const pending = runtime.ensureLease('chat-a', () => {}, controller.signal);
    await started;
    controller.abort();
    await assert.rejects(pending, error => error?.name === 'AbortError');
    await Promise.resolve();
    assert.equal(sharedSignal.aborted, true);
    assert.equal(runtime.leaseWaiterCount, 0);
    assert.equal(runtime.leaseProgressListeners.size, 0);
});

test('remoteJson preserves top-level zkAPI error details', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.remoteFetch = async () => new Response(JSON.stringify({
        status: 'error',
        error_code: 'internal_error',
        error_message: 'internal error: upstream returned 429 Too Many Requests',
        retriable: true
    }), {
        status: 500,
        headers: { 'content-type': 'application/json' }
    });

    await assert.rejects(
        runtime.remoteJson('https://protocol.example/v2/openrouter/leases'),
        error => {
            assert.equal(error.name, 'BrowserWalletHttpError');
            assert.equal(error.status, 500);
            assert.equal(error.code, 'internal_error');
            assert.equal(error.message, 'internal error: upstream returned 429 Too Many Requests');
            assert.equal(error.data.retriable, true);
            assert.equal(error.data.retry_after_seconds, undefined);
            return true;
        }
    );
});

test('remoteJson preserves Retry-After when the proxy body omits it', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.remoteFetch = async () => new Response(JSON.stringify({
        status: 'error',
        error_code: 'oa_minute_request_limit',
        error_message: 'OA is limiting new temporary keys.',
        retriable: true
    }), {
        status: 429,
        headers: { 'content-type': 'application/json', 'retry-after': '17' }
    });

    await assert.rejects(
        runtime.remoteJson('https://protocol.example/v2/openrouter/leases'),
        error => {
            assert.equal(error.status, 429);
            assert.equal(error.code, 'oa_minute_request_limit');
            assert.equal(error.data.retry_after_seconds, 17);
            return true;
        }
    );
});

test('lease retries reuse the byte-identical prepared request and report rate-limit waits', async () => {
    const runtime = runtimeForLeaseRequests();
    const request = {
        client_request_id: 'fixed-idempotency-id',
        proof: { a: ['proof-created-once'] },
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: 1_000_000 }
    };
    const attempts = [];
    const waits = [];
    const progress = [];
    let clock = 0;
    runtime.remoteJson = async (url, init) => {
        attempts.push({ url, ...init });
        if (attempts.length < 3) throw retryableError();
        return { status: 'active', client_request_id: request.client_request_id };
    };

    const lease = await runtime.requestLeaseWithRetry(
        request,
        (phase, message) => progress.push({ phase, message }),
        null,
        {
            maxWaitMs: 100,
            maxAttempts: 5,
            initialRetryMs: 10,
            maxRetryMs: 20,
            now: () => clock,
            sleep: async milliseconds => {
                waits.push(milliseconds);
                clock += milliseconds;
            }
        }
    );

    assert.equal(lease.client_request_id, request.client_request_id);
    assert.equal(attempts.length, 3);
    assert.deepEqual(waits, [10, 20]);
    assert.ok(attempts.every(attempt => attempt.url.endsWith('/v2/openrouter/leases')));
    assert.ok(attempts.every(attempt => attempt.body === attempts[0].body));
    assert.deepEqual(JSON.parse(attempts[0].body), request);
    assert.ok(progress.some(entry => entry.phase === 'waiting'
        && /OA is briefly limiting new temporary keys/.test(entry.message)));
    assert.equal(progress.at(-1).message, 'Retrying temporary key creation…');
});

test('lease issuance does not infer retryability from an HTTP 500 status', async () => {
    const runtime = runtimeForLeaseRequests();
    const error = new BrowserWalletHttpError('HTTP 500', 500, 'internal_error', {
        status: 'error',
        error_code: 'internal_error',
        error_message: 'HTTP 500',
        retriable: false
    });
    let attempts = 0;
    let sleeps = 0;
    runtime.remoteJson = async () => {
        attempts += 1;
        throw error;
    };

    await assert.rejects(
        runtime.requestLeaseWithRetry(
            { client_request_id: 'do-not-retry' },
            () => {},
            null,
            { sleep: async () => { sleeps += 1; } }
        ),
        candidate => candidate === error
    );
    assert.equal(attempts, 1);
    assert.equal(sleeps, 0);
});

test('lease retry backoff is bounded by its deadline', async () => {
    const runtime = runtimeForLeaseRequests();
    const error = retryableError('internal error: temporary OA failure');
    let attempts = 0;
    let clock = 0;
    const waits = [];
    runtime.remoteJson = async () => {
        attempts += 1;
        throw error;
    };

    await assert.rejects(
        runtime.requestLeaseWithRetry(
            { client_request_id: 'bounded-retry' },
            () => {},
            null,
            {
                maxWaitMs: 25,
                maxAttempts: 20,
                initialRetryMs: 10,
                maxRetryMs: 10,
                now: () => clock,
                sleep: async milliseconds => {
                    waits.push(milliseconds);
                    clock += milliseconds;
                }
            }
        ),
        candidate => candidate === error
    );
    assert.equal(attempts, 3);
    assert.deepEqual(waits, [10, 10]);
    assert.equal(clock, 20);
});

test('an hourly Retry-After beyond the wait budget fails immediately with saved-message guidance', async () => {
    const runtime = runtimeForLeaseRequests();
    const error = new BrowserWalletHttpError(
        'OA org key issuance was rate limited.',
        429,
        'oa_hourly_issuance_budget',
        {
            status: 'error',
            error_code: 'oa_hourly_issuance_budget',
            retriable: true,
            retry_after_seconds: 2_700
        }
    );
    let attempts = 0;
    let sleeps = 0;
    runtime.remoteJson = async () => {
        attempts += 1;
        throw error;
    };

    await assert.rejects(
        runtime.requestLeaseWithRetry(
            { client_request_id: 'hourly-capacity' },
            () => {},
            null,
            { maxWaitMs: 75_000, sleep: async () => { sleeps += 1; } }
        ),
        candidate => {
            assert.equal(candidate, error);
            assert.match(candidate.shortMessage, /message is saved and was not sent/i);
            assert.match(candidate.shortMessage, /about 45 minutes/i);
            return true;
        }
    );
    assert.equal(attempts, 1);
    assert.equal(sleeps, 0);
});

test('an exhausted legacy 429 without Retry-After never invents a one-second retry', async () => {
    const runtime = runtimeForLeaseRequests();
    const error = retryableError();
    runtime.remoteJson = async () => { throw error; };

    await assert.rejects(
        runtime.requestLeaseWithRetry(
            { client_request_id: 'legacy-no-retry-after' },
            () => {},
            null,
            { maxAttempts: 1 }
        ),
        candidate => {
            assert.equal(candidate, error);
            assert.match(candidate.shortMessage, /use Retry in a moment/i);
            assert.doesNotMatch(candidate.shortMessage, /1 second/i);
            return true;
        }
    );
});

test('lease retry backoff stops promptly when its signal is aborted', async () => {
    const runtime = runtimeForLeaseRequests();
    const controller = new AbortController();
    let attempts = 0;
    runtime.remoteJson = async () => {
        attempts += 1;
        throw retryableError();
    };

    const pending = runtime.requestLeaseWithRetry(
        { client_request_id: 'abort-retry' },
        () => {},
        controller.signal,
        { initialRetryMs: 1_000, maxRetryMs: 1_000 }
    );
    setTimeout(() => controller.abort(), 5);

    await assert.rejects(pending, error => error.name === 'AbortError');
    assert.equal(attempts, 1);
});

test('issueLease prepares one proof before delegating all transport attempts', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.runtime = { state: { note_id: 44, current_balance: 5_000_000 }, journal: null };
    runtime.ownerId = 'test-owner';
    runtime.reload = async () => runtime.runtime;
    runtime.recoverPendingLocked = async () => {};
    let prepareCalls = 0;
    const prepared = {
        client_request_id: 'single-prepared-request',
        proof: { a: ['single-proof'] },
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: 1_000_000 }
    };
    runtime.prepareLeaseRequest = async () => {
        prepareCalls += 1;
        return prepared;
    };
    let delegatedRequest = null;
    runtime.requestLeaseWithRetry = async request => {
        delegatedRequest = request;
        return {
            client_request_id: request.client_request_id,
            status: 'active',
            api_key: 'one-show-key',
            expires_at: 2_000_000_000,
            settle_after: 2_000_000_060,
            spending_limit_usd: 1
        };
    };
    runtime.verifyLease = async () => {};
    runtime.commit = async next => {
        runtime.runtime = next;
        return next;
    };
    runtime.scheduleSettlement = () => {};

    const lease = await runtime.issueLease('chat-session');

    assert.equal(prepareCalls, 1);
    assert.equal(delegatedRequest, prepared);
    assert.equal(lease.client_request_id, prepared.client_request_id);
    assert.equal(runtime.activeLease.sessionId, 'chat-session');
});

for (const selectedCap of [1, 4.5, 6]) test(`issueLease settles the original journal before exposing a selected $${selectedCap} key`, { timeout: 2_000 }, async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.runtime = {
        state: { note_id: 44, current_balance: 8_000_000 },
        journal: { prepared_request: { client_request_id: 'legacy-request' } }
    };
    runtime.ownerId = 'test-owner';
    runtime.reload = async () => runtime.runtime;
    runtime.recoverPendingLocked = async () => {};
    const legacyRequest = {
        client_request_id: 'legacy-request',
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: 5_000_000 }
    };
    const currentRequest = {
        client_request_id: 'fixed-request',
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: selectedCap * 1_000_000 }
    };
    const prepared = [legacyRequest, currentRequest];
    runtime.prepareLeaseRequest = async () => prepared.shift();
    const issued = [];
    runtime.requestLeaseWithRetry = async request => {
        issued.push(request.client_request_id);
        return {
            status: 'active',
            client_request_id: request.client_request_id,
            api_key: `${request.client_request_id}-key`,
            expires_at: 2_000_000_000,
            settle_after: 2_000_000_060,
            spending_limit_usd: request.public_inputs.solvency_bound / 1_000_000
        };
    };
    const verified = [];
    runtime.verifyLease = async (_lease, limit, requestId) => {
        verified.push({ limit, requestId });
    };
    runtime.commit = async next => {
        runtime.runtime = next;
        return next;
    };
    let retiredLegacyRequestId = null;
    runtime.retireRequest = async requestId => {
        retiredLegacyRequestId = requestId;
        assert.equal(requestId, 'legacy-request');
        return { status: 'finalized' };
    };
    runtime.installRecoveredResponse = async requestId => {
        assert.equal(requestId, 'legacy-request');
        runtime.runtime = { ...runtime.runtime, journal: null, lease: null };
        return true;
    };
    runtime.scheduleSettlement = () => {};

    const lease = await runtime.issueLease('chat-session', undefined, null, selectedCap);

    assert.deepEqual(issued, ['legacy-request', 'fixed-request']);
    assert.equal(retiredLegacyRequestId, 'legacy-request');
    assert.notEqual(runtime.activeLease?.api_key, 'legacy-request-key');
    assert.equal(lease.api_key, 'fixed-request-key');
    assert.equal(lease.spending_limit_usd, selectedCap);
    assert.deepEqual(verified, [
        { limit: 5_000_000, requestId: 'legacy-request' },
        { limit: selectedCap * 1_000_000, requestId: 'fixed-request' }
    ]);
});

test('a failed legacy-cap migration can never return the legacy key on retry', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.runtime = {
        state: { note_id: 44, current_balance: 5_000_000 },
        journal: {
            prepared_request: {
                client_request_id: 'legacy-request',
                payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
                public_inputs: { solvency_bound: 5_000_000 }
            }
        }
    };
    runtime.ownerId = 'test-owner';
    runtime.reload = async () => runtime.runtime;
    runtime.recoverPendingLocked = async () => {};
    runtime.prepareLeaseRequest = async () => runtime.runtime.journal.prepared_request;
    runtime.requestLeaseWithRetry = async request => ({
        status: 'active',
        client_request_id: request.client_request_id,
        api_key: 'legacy-five-dollar-key',
        expires_at: 2_000_000_000,
        settle_after: 2_000_000_060,
        spending_limit_usd: 5
    });
    runtime.verifyLease = async () => {};
    runtime.commit = async next => {
        runtime.runtime = next;
        return next;
    };
    runtime.retireRequest = async () => { throw new Error('temporary retirement failure'); };
    runtime.scheduleSettlement = () => {};

    await assert.rejects(runtime.issueLease('chat-session'), /temporary retirement failure/);
    assert.equal(runtime.activeLease, null, 'the legacy key must never become returnable');

    runtime.init = async () => {};
    runtime.issueLease = async sessionId => ({
        status: 'active',
        sessionId,
        api_key: 'fixed-one-dollar-key',
        expires_at: 2_000_000_000,
        spending_limit_usd: 1,
        inFlight: 0
    });

    const retried = await runtime.ensureLease('chat-session');
    assert.equal(retried.api_key, 'fixed-one-dollar-key');
});

test('lease verification requires active status and the submitted request identity', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.config.openrouter = {
        inference_base: 'https://openrouter.ai/api/v1',
        require_oa_key_source: false
    };
    const lease = {
        status: 'active',
        client_request_id: 'expected-request',
        api_key: 'one-show-key',
        expires_at: 2_000_000_000,
        spending_limit_usd: 1,
        openrouter_api_base: 'https://openrouter.ai/api/v1',
        key_source: 'direct',
        billing_quote: nativeQuote(runtime.config.funding)
    };

    await runtime.verifyLease(lease, 1_000_000, 'expected-request', undefined, null, lease.billing_quote);
    await assert.rejects(
        runtime.verifyLease({ ...lease, status: 'provisioning' }, 1_000_000, 'expected-request'),
        /unusable OpenRouter lease/
    );
    await assert.rejects(
        runtime.verifyLease({ ...lease, client_request_id: 'swapped-request' }, 1_000_000, 'expected-request'),
        /unusable OpenRouter lease/
    );
});

test('automatic settlement waits until a streaming request releases the key', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.activeLease = {
        client_request_id: 'streaming-request',
        settle_after: 0,
        inFlight: 1
    };
    let retirementCalls = 0;
    runtime.retireActiveLease = async () => {
        retirementCalls += 1;
        runtime.activeLease = null;
    };

    runtime.scheduleSettlement(0);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(retirementCalls, 0);
    runtime.activeLease.inFlight = 0;
    await new Promise(resolve => setTimeout(resolve, 520));
    assert.equal(retirementCalls, 1);
});

test('a send arriving after retirement starts waits for a fresh key', { timeout: 2_000 }, async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.ownerId = 'test-owner';
    runtime.runtime = {
        state: { note_id: 44, current_balance: 5_000_000 },
        journal: { prepared_request: { client_request_id: 'expiring-key' } },
        lease: null
    };
    runtime.activeLease = {
        status: 'active',
        sessionId: 'chat-session',
        client_request_id: 'expiring-key',
        api_key: 'key-being-retired',
        expires_at: 2_000_000_000,
        settle_after: 0,
        spending_limit_usd: 1,
        inFlight: 0
    };
    runtime.init = async () => {};
    let releaseReload;
    const reloadGate = new Promise(resolve => { releaseReload = resolve; });
    runtime.reload = async () => {
        await reloadGate;
        return runtime.runtime;
    };
    runtime.retireRequest = async () => ({ status: 'finalized' });
    runtime.installRecoveredResponse = async () => {
        runtime.runtime = { ...runtime.runtime, journal: null, lease: null };
        return true;
    };
    runtime.scheduleSettlement = () => {};
    runtime.issueLease = async sessionId => ({
        status: 'active',
        sessionId,
        api_key: 'fresh-key',
        expires_at: 2_000_000_000,
        spending_limit_usd: 1,
        inFlight: 0
    });

    const retiring = runtime.retireActiveLease();
    assert.equal(runtime.activeLease.retiring, true);
    let sendResolved = false;
    const sending = runtime.ensureLease('chat-session').then(lease => {
        sendResolved = true;
        return lease;
    });
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(sendResolved, false, 'the retiring key must not be handed to the new send');

    releaseReload();
    await retiring;
    const lease = await sending;
    assert.equal(lease.api_key, 'fresh-key');
});

test('a finalized key is never reusable when receipt installation fails', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.ownerId = 'test-owner';
    runtime.runtime = {
        state: { note_id: 44, current_balance: 5_000_000 },
        journal: { prepared_request: { client_request_id: 'finalized-key' } },
        lease: null
    };
    runtime.activeLease = {
        status: 'active',
        sessionId: 'chat-session',
        client_request_id: 'finalized-key',
        api_key: 'revoked-key',
        expires_at: 2_000_000_000,
        spending_limit_usd: 1,
        inFlight: 0
    };
    runtime.reload = async () => runtime.runtime;
    runtime.retireRequest = async () => ({ status: 'finalized' });
    runtime.installRecoveredResponse = async () => {
        throw new Error('receipt installation failed');
    };

    await assert.rejects(runtime.retireActiveLease(), /receipt installation failed/);
    assert.equal(runtime.activeLease, null);

    runtime.init = async () => {};
    runtime.issueLease = async sessionId => ({
        status: 'active',
        sessionId,
        api_key: 'fresh-after-recovery',
        expires_at: 2_000_000_000,
        spending_limit_usd: 1,
        inFlight: 0
    });
    const lease = await runtime.ensureLease('chat-session');
    assert.equal(lease.api_key, 'fresh-after-recovery');
});

test('a key near server settlement is renewed before starting a long stream', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;
    runtime.ownerId = 'test-owner';
    runtime.runtime = { lease: null };
    runtime.activeLease = {
        status: 'active',
        sessionId: 'chat-session',
        api_key: 'nearly-expired-key',
        expires_at: Math.floor(Date.now() / 1000) + 60,
        settle_after: Math.floor(Date.now() / 1000) + 65,
        spending_limit_usd: 1,
        inFlight: 0
    };
    let retired = false;
    runtime.retireActiveLease = async () => {
        retired = true;
        runtime.activeLease = null;
    };
    runtime.issueLease = async sessionId => ({
        status: 'active',
        sessionId,
        api_key: 'fresh-safe-key',
        expires_at: Math.floor(Date.now() / 1000) + 300,
        spending_limit_usd: 1,
        inFlight: 0
    });

    const lease = await runtime.ensureLease('chat-session');
    assert.equal(retired, true);
    assert.equal(lease.api_key, 'fresh-safe-key');
});

test('cross-tab ownership lasts through settlement, not merely usable expiry', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;
    runtime.ownerId = 'this-tab';
    runtime.runtime = {
        lease: {
            ownerId: 'other-tab',
            expires_at: Math.floor(Date.now() / 1000) - 1,
            settle_after: Math.floor(Date.now() / 1000) + 30
        }
    };

    await assert.rejects(
        runtime.ensureLease('chat-session'),
        error => error.code === 'lease_tab_conflict'
    );
});

test('startup recovery does not retire another tab during its settlement window', async () => {
    const runtime = runtimeForLeaseRequests();
    const now = Math.floor(Date.now() / 1000);
    runtime.manifest = { deployment_id: 'focused-test' };
    runtime.ownerId = 'this-tab';
    runtime.runtime = {
        journal: {
            prepared_request: { client_request_id: 'other-tab-request' },
            nullifier: 'other-tab-nullifier'
        },
        lease: {
            ownerId: 'other-tab',
            expires_at: now - 1,
            settle_after: now + 30
        }
    };
    runtime.activeLease = null;
    runtime.reload = async () => runtime.runtime;
    runtime.remoteJson = async () => ({ status: 'active' });
    let retireCalls = 0;
    runtime.retireRequest = async () => {
        retireCalls += 1;
        return { status: 'finalized' };
    };

    const recovered = await runtime.recoverPending({ retireLostKey: true });

    assert.equal(recovered, false);
    assert.equal(retireCalls, 0);
});

test('lease retirement honors Retry-After without changing the settlement request', async () => {
    const runtime = runtimeForLeaseRequests();
    const request = {
        client_request_id: 'settlement-request',
        proof: { a: ['original-proof'] },
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: 5_000_000 }
    };
    const error = new BrowserWalletHttpError(
        'OA usage reporting is rate limited.',
        429,
        'oa_minute_request_limit',
        { retriable: true, retry_after_seconds: 7 }
    );
    const bodies = [];
    const waits = [];
    let attempts = 0;
    let clock = 0;
    runtime.remoteJson = async (_url, init) => {
        attempts += 1;
        bodies.push(init.body);
        if (attempts === 1) throw error;
        return { status: 'finalized' };
    };

    const result = await runtime.retireRequest(request.client_request_id, request, null, {
        maxWaitMs: 10_000,
        now: () => clock,
        sleep: async milliseconds => {
            waits.push(milliseconds);
            clock += milliseconds;
        }
    });

    assert.equal(result.status, 'finalized');
    assert.deepEqual(waits, [7_000]);
    assert.equal(bodies.length, 2);
    assert.ok(bodies.every(body => body === bodies[0]));
    assert.deepEqual(JSON.parse(bodies[0]), request);
});

test('lease retirement crosses the OA finalization boundary with the exact original request', async () => {
    const runtime = runtimeForLeaseRequests();
    const request = {
        client_request_id: 'settlement-boundary-request',
        proof: { a: ['proof-must-not-change'] },
        payload: JSON.stringify({ billing_quote: nativeQuote(runtime.config.funding) }),
        public_inputs: { solvency_bound: 25_000_000 }
    };
    const pending = [
        new BrowserWalletHttpError(
            'OpenRouter lease is already active or awaiting settlement',
            409,
            'lease_pending',
            { retriable: true, retry_after_seconds: 4 }
        ),
        new BrowserWalletHttpError(
            'OpenRouter lease settlement is still pending',
            409,
            'lease_settlement_pending',
            { retriable: true, retry_after_seconds: 11 }
        )
    ];
    const bodies = [];
    const waits = [];
    let clock = 0;
    runtime.remoteJson = async (_url, init) => {
        bodies.push(init.body);
        const error = pending.shift();
        if (error) throw error;
        return { status: 'finalized' };
    };

    const result = await runtime.retireRequest(request.client_request_id, request, null, {
        maxWaitMs: 45_000,
        now: () => clock,
        sleep: async milliseconds => {
            waits.push(milliseconds);
            clock += milliseconds;
        }
    });

    assert.equal(result.status, 'finalized');
    assert.deepEqual(waits, [4_000, 11_000]);
    assert.equal(clock, 15_000);
    assert.equal(bodies.length, 3);
    assert.ok(bodies.every(body => body === bodies[0]));
    assert.deepEqual(JSON.parse(bodies[0]), request);
});

for (const code of ['lease_pending', 'lease_settlement_pending', 'native_quote_expired', 'native_quote_superseded']) {
    test(`lease issuance never retries a proof requiring reconciliation: ${code}`, async () => {
        const runtime = runtimeForLeaseRequests();
        const error = new BrowserWalletHttpError(
            'The previous lease is still settling.',
            409,
            code,
            { retriable: true, retry_after_seconds: 15 }
        );
        let attempts = 0;
        let sleeps = 0;
        runtime.remoteJson = async () => {
            attempts += 1;
            throw error;
        };

        await assert.rejects(
            runtime.requestLeaseWithRetry(
                { client_request_id: `issuance-${code}` },
                () => {},
                null,
                { sleep: async () => { sleeps += 1; } }
            ),
            candidate => candidate === error
        );
        assert.equal(attempts, 1);
        assert.equal(sleeps, 0);
    });
}


test('model budget upgrades and downgrades settle before rekeying; same caps reuse', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.ownerId = 'tier-owner';
    runtime.runtime = { lease: null };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;
    const events = [];
    runtime.issueLease = async (sessionId, _progress, _signal, spendingLimitUsd) => {
        events.push(`issue:${spendingLimitUsd}`);
        runtime.activeLease = { sessionId, spending_limit_usd: spendingLimitUsd, selectedSpendingLimitUsd: spendingLimitUsd,
            api_key: 'test-key', expires_at: Date.now() / 1000 + 300, inFlight: 0 };
        return runtime.activeLease;
    };
    runtime.retireActiveLease = async () => {
        events.push(`settle:${runtime.activeLease.spending_limit_usd}`);
        runtime.activeLease = null;
    };
    const first = await runtime.ensureLease('chat', undefined, null, 1);
    assert.equal(await runtime.ensureLease('chat', undefined, null, 1), first);
    assert.equal((await runtime.ensureLease('chat', undefined, null, 4.5)).spending_limit_usd, 4.5);
    assert.equal((await runtime.ensureLease('chat', undefined, null, 2)).spending_limit_usd, 2);
    assert.deepEqual(events, ['issue:1', 'settle:1', 'issue:4.5', 'settle:4.5', 'issue:2']);
    runtime.activeLease.inFlight = 1;
    await assert.rejects(runtime.ensureLease('chat', undefined, null, 6), error => error.code === 'lease_requests_in_flight');
    assert.equal(runtime.activeLease.spending_limit_usd, 2);
});

test('concurrent same-chat requests with different budgets never share the wrong proof', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.ownerId = 'tier-owner';
    runtime.runtime = { lease: null };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;
    let release;
    let started;
    const issued = new Promise(resolve => { started = resolve; });
    runtime.issueLease = async (_session, _progress, _signal, dollars) => {
        assert.equal(dollars, 3);
        started();
        return new Promise(resolve => { release = () => resolve({ spending_limit_usd: 3 }); });
    };
    const first = runtime.ensureLease('chat', undefined, null, 3);
    await issued;
    await assert.rejects(runtime.ensureLease('chat', undefined, null, 1), error => error.code === 'lease_budget_conflict');
    const second = runtime.ensureLease('chat', undefined, null, 3);
    release();
    assert.equal((await first).spending_limit_usd, 3);
    assert.equal((await second).spending_limit_usd, 3);
});

test('selected cap reaches proof inputs and insufficient funds never start proving', async () => {
    const runtime = runtimeForLeaseRequests();
    runtime.manifest = { deployment_id: 'selected-cap-test' };
    runtime.config.wallet_core = { policy_charge_cap: 50_000 };
    runtime.config.policy_enabled = true;
    runtime.config.proving_keys = { request: {} };
    runtime.runtime = { state: { note_id: 44, current_balance: 5_000_000, current_anchor: '0x2c', expiry_ts: 2_000_000_000 } };
    runtime.treePath = async () => ({ active_root: 'root', siblings: [] });
    runtime.commit = async next => { runtime.runtime = next; };
    const proofInputs = [];
    runtime.worker = { call: async (operation, payload) => {
        assert.equal(operation, 'prepareRequest');
        proofInputs.push(payload);
        const request = { client_request_id: payload.args.client_request_id, payload: payload.args.payload,
            public_inputs: { request_nullifier: '0x44', solvency_bound: payload.config.request_charge_cap } };
        return { journal: { client_request_id: request.client_request_id, nullifier: '0x44', prepared_request: request }, request,
            state: { ...payload.state, bound_at_state: payload.config.request_charge_cap } };
    } };
    await assert.rejects(runtime.prepareLeaseRequest(undefined, null, 6), error => error.required_credits === 6_000_000);
    assert.equal(proofInputs.length, 0);
    const prepared = await runtime.prepareLeaseRequest(undefined, null, 4.5);
    assert.equal(prepared.public_inputs.solvency_bound, 4_500_000);
    assert.equal(proofInputs[0].config.policy_charge_cap, 4_500_000);
    assert.deepEqual(JSON.parse(proofInputs[0].args.payload), { mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: nativeQuote(runtime.config.funding) });
    const original = runtime.runtime.journal.prepared_request;
    assert.equal(await runtime.prepareLeaseRequest(undefined, null, 1), original,
        'durable proof must stay identical across a changed selection until recovery settles it');
});

test('checkout never exposes a key retired while ensureLease was resolving', async () => {
    const runtime = runtimeForLeaseRequests();
    const lease = { api_key: 'must-not-be-returned', inFlight: 0 };
    runtime.activeLease = lease;
    runtime.ensureLease = async () => {
        queueMicrotask(() => { lease.retiring = true; });
        return lease;
    };
    await assert.rejects(runtime.acquireEphemeralKey('chat', undefined, { spendingLimitUsd: 3 }),
        error => error.code === 'lease_pending');
    assert.equal(lease.inFlight, 0);
    lease.retiring = false;
    runtime.activeLease = { ...lease };
    runtime.ensureLease = async () => lease;
    await assert.rejects(runtime.acquireEphemeralKey('chat'), error => error.code === 'lease_pending');
    assert.equal(lease.inFlight, 0);
});
