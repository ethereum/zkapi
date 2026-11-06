// Trusted zkAPI server clock for new request timestamps and lease checks.
// GET /v2/time is additive: a server without it answers 404/405, and only that
// definite absence selects the legacy device clock. Authentication failures,
// other HTTP errors, malformed bodies, slow samples and transport failures
// never downgrade. Observations live in memory for one runtime/deployment only.
const SERVER_TIME_SAMPLE_TIMEOUT_MS = 10_000;
const SERVER_TIME_MAX_ROUND_TRIP_MS = 5_000;
// A wall-clock change or an OS suspend that pauses performance.now() shows up
// as elapsed wall time disagreeing with elapsed monotonic time.
const SERVER_TIME_MAX_DISCONTINUITY_MS = 2_000;
// Three uses, deliberately distinct:
// - nowMs(): authoritative for authorization; resamples a suspect, aged or
//   discontinuous anchor and never falls back after a failed sample.
// - authorizationNowMs(): strict synchronous check inside one authorization
//   (host callbacks, checkout); fails closed with Infinity.
// - estimateMs(): display and settlement timers only; never authorizes.
const SERVER_TIME_ESTIMATE_MAX_AGE_MS = 15 * 60_000;
const SERVER_TIME_MIN_MS = Date.UTC(2024, 0, 1);
const SERVER_TIME_MAX_MS = Date.UTC(2200, 0, 1);
const SERVER_TIME_MAX_WINDOW_SECONDS = 3_600;

class ZkapiServerTimeError extends Error {
    constructor(message, { status = null, retrySample = false, cause } = {}) {
        super(message, cause ? { cause } : undefined);
        this.name = 'ZkapiServerTimeError';
        this.code = 'server_time_unavailable';
        this.status = status;
        this.retrySample = retrySample;
    }
}

function serverTimeWindowSeconds(value) {
    return Number.isSafeInteger(value) && value > 0 && value <= SERVER_TIME_MAX_WINDOW_SECONDS;
}

class ZkapiServerClock {
    #anchor = null;
    #suspect = false;
    #refresh = null;

    constructor({ baseUrl, chainId, fetch, monotonicNow = () => performance.now(), wallNow = () => Date.now() }) {
        if (typeof fetch !== 'function') throw new TypeError('A server-time fetch function is required.');
        this.url = new URL('v2/time', `${String(baseUrl).replace(/\/+$/, '')}/`).href;
        this.chainId = Number(chainId);
        this.fetch = fetch;
        this.monotonicNow = monotonicNow;
        this.wallNow = wallNow;
        this.mode = 'unknown';
    }

    // Lifecycle events can follow a suspend: the next nowMs() resamples. A
    // strict synchronous check relies on discontinuity detection instead.
    attachLifecycle(win = globalThis.window, doc = globalThis.document) {
        const invalidate = () => this.invalidate();
        doc?.addEventListener?.('resume', invalidate);
        doc?.addEventListener?.('visibilitychange', () => {
            if (doc.visibilityState === 'visible') invalidate();
        });
        win?.addEventListener?.('pageshow', event => { if (event?.persisted) invalidate(); });
        win?.addEventListener?.('online', invalidate);
    }

    invalidate() {
        this.#suspect = true;
    }

    #elapsed(anchor) {
        const elapsed = this.monotonicNow() - anchor.monotonicAt;
        const wallElapsed = this.wallNow() - anchor.wallAt;
        if (!Number.isFinite(elapsed) || elapsed < 0) return null;
        return { elapsed, continuous: Math.abs(wallElapsed - elapsed) <= SERVER_TIME_MAX_DISCONTINUITY_MS };
    }

    // The sample's server time was produced before the response arrived, so
    // anchoring it at arrival is a lower bound: estimates never run ahead of
    // the server and cannot create a future-dated request.
    #validEstimate(maxAgeMs) {
        if (this.mode !== 'server' || !this.#anchor || this.#suspect) return null;
        const elapsed = this.#elapsed(this.#anchor);
        if (!elapsed?.continuous || elapsed.elapsed > maxAgeMs) {
            this.#suspect = true;
            return null;
        }
        return this.#anchor.serverMs + Math.floor(elapsed.elapsed);
    }

    async sample(signal = null) {
        signal?.throwIfAborted?.();
        const timeout = AbortSignal.timeout(SERVER_TIME_SAMPLE_TIMEOUT_MS);
        const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
        const monotonicStart = this.monotonicNow();
        const wallStart = this.wallNow();
        let response;
        let body;
        try {
            response = await this.fetch(this.url, {
                method: 'GET', cache: 'no-store', credentials: 'omit',
                headers: { accept: 'application/json' }, signal: requestSignal
            });
            if (response.status === 404 || response.status === 405) {
                // Endpoint absence is the only legacy signal (rolling upgrade).
                this.#anchor = null;
                this.#suspect = false;
                this.mode = 'legacy';
                return null;
            }
            if (!response.ok) {
                throw new ZkapiServerTimeError(`The zkAPI server clock is unavailable (HTTP ${response.status}).`,
                    { status: response.status });
            }
            body = await response.json();
        } catch (error) {
            signal?.throwIfAborted?.();
            if (error instanceof ZkapiServerTimeError || error?.code === 'testnet_password_required') throw error;
            throw new ZkapiServerTimeError('The zkAPI server clock could not be read. Check your connection and try again.',
                { cause: error });
        }
        const monotonicAt = this.monotonicNow();
        const wallAt = this.wallNow();
        const roundTrip = monotonicAt - monotonicStart;
        if (!Number.isFinite(roundTrip) || roundTrip < 0 || roundTrip > SERVER_TIME_MAX_ROUND_TRIP_MS) {
            throw new ZkapiServerTimeError('The zkAPI server clock answered too slowly. Try again.', { retrySample: true });
        }
        if (Math.abs((wallAt - wallStart) - roundTrip) > SERVER_TIME_MAX_DISCONTINUITY_MS) {
            throw new ZkapiServerTimeError('The device clock changed while checking the zkAPI server clock. Try again.',
                { retrySample: true });
        }
        const serverMs = body?.server_time_ms;
        if (!body || typeof body !== 'object' || Array.isArray(body)
            || !Number.isSafeInteger(serverMs) || serverMs < SERVER_TIME_MIN_MS || serverMs > SERVER_TIME_MAX_MS
            || body.chain_id !== this.chainId
            || !serverTimeWindowSeconds(body.max_request_age_seconds)
            || !serverTimeWindowSeconds(body.max_future_skew_seconds)) {
            throw new ZkapiServerTimeError('The zkAPI server returned an invalid clock response.');
        }
        this.#anchor = { serverMs, monotonicAt, wallAt };
        this.#suspect = false;
        this.mode = 'server';
        return serverMs;
    }

    /** Server milliseconds for authorization, sampled when the anchor is older
     * than maxAgeMs or discontinuous. Legacy servers return the device clock. */
    async nowMs({ signal = null, maxAgeMs = 30_000 } = {}) {
        const current = this.#validEstimate(maxAgeMs);
        if (current != null) return current;
        for (let attempt = 0; ; attempt += 1) {
            try {
                await this.sample(signal);
                break;
            } catch (error) {
                if (!error?.retrySample || attempt >= 1) throw error;
            }
        }
        if (this.mode === 'legacy') return this.wallNow();
        const sampled = this.#validEstimate(Number.POSITIVE_INFINITY);
        if (sampled == null) throw new ZkapiServerTimeError('The device clock changed while checking the zkAPI server clock. Try again.');
        return sampled;
    }

    /** Best available non-authorizing estimate, or null before any sample.
     * A suspect anchor schedules one background resample. */
    estimateMs() {
        if (this.mode === 'legacy') return this.wallNow();
        const valid = this.#validEstimate(SERVER_TIME_ESTIMATE_MAX_AGE_MS);
        if (valid != null) return valid;
        if (!this.#anchor) return null;
        if (!this.#refresh) {
            this.#refresh = this.sample().catch(() => null).finally(() => { this.#refresh = null; });
        }
        const elapsed = this.#elapsed(this.#anchor);
        return elapsed ? this.#anchor.serverMs + Math.floor(elapsed.elapsed) : null;
    }

    /** Strict synchronous check for callbacks inside one authorization. Any
     * wall/monotonic discontinuity (OS suspend or clock change) since the
     * anchor, an anchor older than maxAgeMs, or no anchor fails closed with
     * Infinity, so an expiry comparison treats the key as expired. */
    authorizationNowMs(maxAgeMs = 60_000) {
        if (this.mode === 'legacy') return this.wallNow();
        if (this.mode !== 'server' || !this.#anchor) return Number.POSITIVE_INFINITY;
        const elapsed = this.#elapsed(this.#anchor);
        if (!elapsed?.continuous || elapsed.elapsed > maxAgeMs) {
            this.#suspect = true;
            return Number.POSITIVE_INFINITY;
        }
        return this.#anchor.serverMs + Math.floor(elapsed.elapsed);
    }
}

export { ZkapiServerClock, ZkapiServerTimeError };
