import assert from 'node:assert/strict';
import test from 'node:test';
import { nativeFunding } from './helpers/native-fixtures.mjs';
import { createServerTimeWorld, serverTimeRuntime } from './helpers/server-time-world.mjs';

globalThis.window = { location: { hostname: 'localhost' } };
const { ZkapiServerClock } = await import('../services/zkapiServerClock.mjs');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const { nativeUsdMicros } = await import('../services/zkapiNativeEth.mjs');

const funding = nativeFunding({ chain_id: 1 });
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const SKEWS = [-3 * DAY, -3 * HOUR, -10 * 60_000, 0, 45_000, 3 * HOUR, 3 * DAY];

function worldFor(t, options = {}) {
    const world = createServerTimeWorld({ funding, ...options });
    world.spendingLimitUsd = request => Number(nativeUsdMicros(request.public_inputs.solvency_bound,
        JSON.parse(request.payload).billing_quote)) / 1_000_000;
    t.mock.method(globalThis, 'fetch', world.fetch);
    t.mock.method(Date, 'now', () => world.deviceNow());
    return world;
}

function clockFor(world) {
    return new ZkapiServerClock({ baseUrl: funding.protocol_server_url, chainId: funding.chain_id,
        fetch: (url, init) => world.fetch(url, init),
        monotonicNow: () => world.monotonicMs, wallNow: () => world.deviceNow() });
}

function assertAdmissible(world, requestTime) {
    const now = world.serverSeconds();
    assert.ok(requestTime <= now, `request_time ${requestTime} must not be ahead of server ${now}`);
    assert.ok(requestTime + 300 >= now, `request_time ${requestTime} must be within the age window of ${now}`);
}

test('server clock ignores device clocks hours and days fast or slow and never runs ahead', async t => {
    for (const skewMs of SKEWS) {
        const world = worldFor(t, { skewMs });
        world.latencyBeforeMs = 900; // asymmetric: the server answered late in the round trip
        world.latencyAfterMs = 50;
        const clock = clockFor(world);
        const sampled = await clock.nowMs();
        assert.ok(sampled <= world.serverMs && sampled >= world.serverMs - 1_000, `skew ${skewMs}`);
        world.advance(10_000);
        assert.ok(await clock.nowMs() <= world.serverMs);
        assert.equal(world.timeRequests.length, 1, 'a bounded continuous anchor is reused');
        const init = world.timeRequests[0].init;
        assert.equal(init.method, 'GET');
        assert.equal(init.cache, 'no-store');
        assert.equal(init.credentials, 'omit');
        assert.ok(init.signal instanceof AbortSignal);
    }
});

test('aged anchors, device clock jumps, OS suspend and lifecycle events force a fresh sample', async t => {
    const world = worldFor(t, { skewMs: 3 * HOUR });
    const clock = clockFor(world);
    await clock.nowMs();
    world.advance(31_000);
    await clock.nowMs({ maxAgeMs: 30_000 });
    assert.equal(world.timeRequests.length, 2, 'an anchor older than the bound is resampled');

    world.jumpDevice(-2 * DAY); // OS clock changed; monotonic time unaffected
    assert.ok(Math.abs(await clock.nowMs() - world.serverMs) < 100);
    assert.equal(world.timeRequests.length, 3, 'a wall-clock discontinuity invalidates the anchor');

    world.suspend(10 * 60_000); // performance.now() paused while the device slept
    assert.ok(Math.abs(await clock.nowMs() - world.serverMs) < 100, 'suspend never yields a stale timestamp');
    assert.equal(world.timeRequests.length, 4);

    clock.invalidate(); // visibility/resume/pageshow/online
    await clock.nowMs();
    assert.equal(world.timeRequests.length, 5);

    const events = {};
    const target = { addEventListener: (name, listener) => { events[name] = listener; }, visibilityState: 'visible' };
    clock.attachLifecycle(target, target);
    for (const [name, event] of [['resume'], ['visibilitychange'], ['pageshow', { persisted: true }], ['online']]) {
        await clock.nowMs();
        const before = world.timeRequests.length;
        events[name](event);
        await clock.nowMs();
        assert.equal(world.timeRequests.length, before + 1, name);
    }
});

test('a suspended anchor gives a non-authorizing estimate but schedules one background resample', async t => {
    const world = worldFor(t);
    const clock = clockFor(world);
    assert.equal(clock.estimateMs(), null, 'no observation before the first sample');
    await clock.nowMs();
    world.suspend(5 * 60_000);
    const lagging = clock.estimateMs();
    assert.ok(lagging < world.serverMs);
    clock.estimateMs();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(world.timeRequests.length, 2, 'only one coalesced refresh');
    assert.ok(Math.abs(clock.estimateMs() - world.serverMs) < 100);
});

test('slow samples and clock changes during a sample are retried once, then fail closed', async t => {
    const world = worldFor(t);
    const clock = clockFor(world);
    world.timeEndpoint = 'slow';
    await assert.rejects(clock.nowMs(), { code: 'server_time_unavailable' });
    assert.equal(world.timeRequests.length, 2);
    assert.equal(clock.mode, 'unknown');

    world.timeEndpoint = 'v2';
    let jumps = 1;
    world.onTimeRequest = w => { if (jumps-- > 0) w.jumpDevice(5 * HOUR); };
    assert.ok(Math.abs(await clock.nowMs() - world.serverMs) < 100);
    assert.equal(world.timeRequests.length, 4, 'the discontinuous sample was discarded and retried');
});

test('only 404/405 select the legacy device clock; auth, server, malformed and transport failures never downgrade', async t => {
    for (const status of [404, 405]) {
        const world = worldFor(t, { skewMs: 3 * HOUR, timeEndpoint: status });
        const clock = clockFor(world);
        assert.equal(await clock.nowMs(), world.deviceNow());
        assert.equal(clock.mode, 'legacy');
        world.timeEndpoint = 'v2';
        await clock.nowMs();
        assert.equal(clock.mode, 'server', 'an upgraded server is detected on the next authorization');
    }
    const malformed = [{}, { server_time_ms: 1 }, { server_time_ms: 1.5e12 + 0.5 }, [], 'malformed',
        { server_time_ms: Date.UTC(2026, 0, 1), chain_id: 5, max_request_age_seconds: 300, max_future_skew_seconds: 30 },
        { server_time_ms: Date.UTC(2026, 0, 1), chain_id: 1, max_request_age_seconds: 1e9, max_future_skew_seconds: 30 },
        { server_time_ms: Date.UTC(2026, 0, 1), chain_id: 1, max_request_age_seconds: 300 }];
    for (const timeEndpoint of [401, 403, 429, 500, 502, 503, 'network', ...malformed]) {
        const world = worldFor(t, { timeEndpoint });
        const clock = clockFor(world);
        await assert.rejects(clock.nowMs(), error => error.code === 'server_time_unavailable', JSON.stringify(timeEndpoint));
        assert.notEqual(clock.mode, 'legacy');
        assert.equal(clock.estimateMs(), null);
    }
    const world = worldFor(t);
    const controller = new AbortController();
    controller.abort(new DOMException('stopped', 'AbortError'));
    await assert.rejects(clockFor(world).nowMs({ signal: controller.signal }), { name: 'AbortError' });
});

for (const skewMs of SKEWS) test(`a new key is authorized once with a server timestamp when the device clock is off by ${skewMs} ms`, async t => {
    const world = worldFor(t, { skewMs });
    world.preloadMs = 7 * 60_000; // a slow proving-key download precedes the timestamp
    world.provingMs = 2_000;
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const lease = await runtime.issueLease('chat', undefined, null, 1);
    assert.equal(world.leasePosts.length, 1, 'exactly one authorization');
    assert.equal(world.preloads, 1);
    assertAdmissible(world, world.proofs[0].args.request_time);
    assert.equal(lease.client_request_id, 'request-1');
    assert.equal(runtime.activeLease, lease);
    world.advance(60_000);
    assert.equal(await runtime.ensureLease('chat', undefined, null, 1), lease, 'reuse needs no second authorization');
    assert.equal(world.leasePosts.length, 1);
});

test('device clock jumps and suspend during proof work still produce an admissible timestamp', async t => {
    const world = worldFor(t, { skewMs: -2 * HOUR });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const preload = runtime.worker.call;
    runtime.worker.call = async (operation, input) => {
        if (operation === 'preloadRequestProver') {
            world.jumpDevice(5 * HOUR);
            world.suspend(8 * 60_000);
        }
        return preload(operation, input);
    };
    await runtime.issueLease('chat', undefined, null, 1);
    assert.equal(world.leasePosts.length, 1);
    assertAdmissible(world, world.proofs[0].args.request_time);
});

test('a suspend after the quote sample but before the timestamp is detected and resampled', async t => {
    const world = worldFor(t, { skewMs: 3 * HOUR });
    let suspended = false;
    world.onRpc = w => {
        if (suspended) return;
        suspended = true;
        w.suspend(8 * 60_000); // performance.now() pauses; anchor age looks tiny
    };
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    await runtime.issueLease('chat', undefined, null, 1);
    assert.equal(world.timeRequests.length, 2, 'the discontinuous anchor was replaced before request_time');
    assertAdmissible(world, world.proofs[0].args.request_time);
    assert.ok(world.proofs[0].args.request_time >= world.serverSeconds() - 5);
});

test('new client against an old server uses the narrowly defined 404 legacy fallback', async t => {
    const world = worldFor(t, { timeEndpoint: 404 });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const before = Math.floor(world.deviceNow() / 1000);
    await runtime.issueLease('chat', undefined, null, 1);
    const requestTime = world.proofs[0].args.request_time;
    assert.ok(requestTime >= before && requestTime <= Math.floor(world.deviceNow() / 1000), 'legacy device timestamp');
    assert.equal(runtime.serverClock.mode, 'legacy');
    assert.equal(world.leasePosts.length, 1);
    // Skew protection requires the new endpoint: a fast device fails exactly as before.
    const fast = worldFor(t, { timeEndpoint: 404, skewMs: 3 * HOUR });
    const legacy = serverTimeRuntime(BrowserWalletRuntime, fast, { funding });
    await assert.rejects(legacy.issueLease('chat', undefined, null, 1), /invalid or stale|freshness/);
});

for (const timeEndpoint of [401, 403, 500, 'malformed', 'network', 'slow']) test(`time endpoint ${timeEndpoint} blocks a new authorization before any proof or journal`, async t => {
    const world = worldFor(t, { timeEndpoint, skewMs: 3 * HOUR });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    await assert.rejects(runtime.issueLease('chat', undefined, null, 1), { code: 'server_time_unavailable' });
    assert.notEqual(runtime.serverClock.mode, 'legacy');
    assert.equal(world.proofs.length, 0);
    assert.equal(world.leasePosts.length, 0);
    assert.equal(runtime.runtime.journal, undefined);
    assert.equal(runtime.commits.length, 0);
});

function savedJournal(world, requestTime) {
    const quote = world.quote();
    const request = { client_request_id: 'saved-request', payload_hash: '0x99',
        payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote }),
        public_inputs: { request_time: requestTime, request_nullifier: '0x77', solvency_bound: 1_000_000 },
        proof: { backend: 'groth16_bn254', proof: 'saved-proof' } };
    return { request, bytes: JSON.stringify(request), journal: { nullifier: '0x77', prepared_request: request } };
}

test('a server-proven aged journal is replaced only after the exact saved bytes are declared expired', async t => {
    const world = worldFor(t, { skewMs: 3 * HOUR });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const saved = savedJournal(world, world.serverSeconds() - 400);
    runtime.runtime = { ...runtime.runtime, journal: saved.journal };
    await runtime.issueLease('chat', undefined, null, 1);
    assert.equal(world.expireCalls.length, 1);
    assert.equal(JSON.stringify(world.expireCalls[0].request), saved.bytes, 'byte-identical recovery request');
    assert.equal(JSON.stringify(saved.request), saved.bytes, 'the saved proof was never rewritten');
    assert.equal(runtime.commits[0].journal, null);
    assert.equal(world.leasePosts.length, 1, 'only the fresh request is authorized');
    assertAdmissible(world, world.proofs[0].args.request_time);
});

test('old-server and future-dated journals are replayed byte-identically and never discarded locally', async t => {
    for (const [label, offset, expireKnowsAge] of [['aged on an old server', -400, false], ['future-dated', 600, true]]) {
        const world = worldFor(t, { skewMs: -3 * HOUR });
        world.expireKnowsAge = expireKnowsAge;
        const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
        const saved = savedJournal(world, world.serverSeconds() + offset);
        runtime.runtime = { ...runtime.runtime, journal: saved.journal };
        await assert.rejects(runtime.issueLease('chat', undefined, null, 1), /freshness window/, label);
        assert.equal(world.proofs.length, 0, `${label}: no new proof`);
        assert.equal(world.leasePosts.length, 1);
        assert.equal(JSON.stringify(world.leasePosts[0].request), saved.bytes, `${label}: exact replay`);
        assert.equal(world.expireCalls.length, 2, `${label}: startup recovery and the rejection both ask the server`);
        assert.equal(runtime.runtime.journal, saved.journal, `${label}: journal kept`);
        assert.equal(runtime.commits.length, 0);
    }
});

const VERIFIER = 'https://verifier.example';
function oaWorld(t, options = {}) {
    const world = worldFor(t, options);
    world.verifierUrl = VERIFIER;
    world.keySource = 'oa_org';
    world.leaseExtras = now => ({ expires_at: now + 600, verification: { verifier_url: VERIFIER, station_id: 'oa-station',
        station_signature: '12'.repeat(64), org_signature: '34'.repeat(64), key_valid_till: now + 630 } });
    return world;
}
const oaRouter = { inference_base: 'https://openrouter.ai/api/v1', verifier_url: VERIFIER, require_oa_key_source: true };

for (const [label, verifierSleepMs, expectExpired] of [['20 minutes', 20 * 60_000, true], ['2 minutes', 2 * 60_000, false]]) {
    test(`a ${label} suspend during asynchronous verification is rechecked against fresh server time`, async t => {
        const world = oaWorld(t, { skewMs: 3 * HOUR });
        world.onVerify = w => w.suspend(verifierSleepMs); // performance.now() pauses during sleep
        const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding, openrouter: oaRouter });
        const issuing = runtime.issueLease('chat', undefined, null, 1);
        if (!expectExpired) {
            const lease = await issuing;
            assert.ok(lease.expires_at > world.serverSeconds());
            assert.equal(runtime.activeLease, lease);
            return;
        }
        await assert.rejects(issuing, { code: 'lease_expired' });
        assert.equal(runtime.activeLease, null, 'an expired key is never installed');
        assert.equal(world.leasePosts.length, 1, 'no second authorization');
        assert.equal(world.verifications, 1);
        const saved = runtime.runtime.journal.prepared_request;
        assert.equal(JSON.stringify(saved), JSON.stringify(world.leasePosts[0].request), 'exact journal kept for recovery');
        assert.ok(world.timeRequests.length >= 2, 'the post-verification check resampled after the discontinuity');
    });
}

test('after a suspend, an active key is not reused or checked out when the server clock cannot be resampled', async t => {
    const world = oaWorld(t, { skewMs: -3 * HOUR });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding, openrouter: oaRouter });
    const lease = await runtime.issueLease('chat', undefined, null, 1);
    world.suspend(20 * 60_000);
    world.timeEndpoint = 500;
    await assert.rejects(runtime.ensureLease('chat', undefined, null, 1), { code: 'server_time_unavailable' });
    await assert.rejects(runtime.acquireEphemeralKey('chat', undefined, { spendingLimitUsd: 1 }), { code: 'server_time_unavailable' });
    assert.equal(lease.inFlight, 0, 'the expired credential was never checked out');
    assert.equal(world.leasePosts.length, 1);
    assert.ok(runtime.protocolEstimateMs() < world.serverMs, 'only the display estimate lags');
    assert.equal(runtime.protocolAuthorizationNowMs(), Number.POSITIVE_INFINITY, 'strict time fails closed');
});

test('checkout itself refuses an expired key under the strict clock even when reuse was skipped', async t => {
    const world = oaWorld(t);
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding, openrouter: oaRouter });
    const lease = await runtime.issueLease('chat', undefined, null, 1);
    runtime.ensureLease = async () => lease;
    world.suspend(20 * 60_000);
    await assert.rejects(runtime.acquireEphemeralKey('chat'), { code: 'lease_expired' });
    assert.equal(lease.inFlight, 0);
});

test('strict authorization time fails closed without an anchor, after discontinuity or age, and not on lifecycle hints alone', async t => {
    const world = worldFor(t, { skewMs: 3 * HOUR });
    const clock = clockFor(world);
    assert.equal(clock.authorizationNowMs(), Number.POSITIVE_INFINITY);
    await clock.nowMs();
    assert.ok(Math.abs(clock.authorizationNowMs() - world.serverMs) < 100);
    clock.invalidate(); // visibility change: next nowMs() resamples, strict check stays usable
    assert.ok(Number.isFinite(clock.authorizationNowMs()));
    world.advance(61_000);
    assert.equal(clock.authorizationNowMs(60_000), Number.POSITIVE_INFINITY, 'aged anchor');
    await clock.nowMs();
    world.suspend(60_000);
    assert.equal(clock.authorizationNowMs(), Number.POSITIVE_INFINITY, 'suspend');
    await clock.nowMs();
    world.jumpDevice(-DAY);
    assert.equal(clock.authorizationNowMs(), Number.POSITIVE_INFINITY, 'device clock change');
    const legacy = worldFor(t, { timeEndpoint: 404, skewMs: 3 * HOUR });
    const legacyClock = clockFor(legacy);
    await legacyClock.nowMs();
    assert.equal(legacyClock.authorizationNowMs(), legacy.deviceNow(), 'legacy servers keep the device clock');
});

// Finding 3: saved-request recovery is decided by the server's exact /expire
// answer or signed receipt, never by device time or a /v2/time sample.
test('an aged saved request recovers through exact /expire on a slow device while /v2/time fails', async t => {
    const world = worldFor(t, { skewMs: -3 * HOUR, timeEndpoint: 'network' });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const saved = savedJournal(world, world.serverSeconds() - 400);
    runtime.runtime = { ...runtime.runtime, journal: saved.journal };
    assert.ok(world.quote().updated_at > Math.floor(Date.now() / 1000), 'the device sees the saved quote in its future');
    assert.equal(await runtime.recoverPendingLocked({ retireLostKey: true }), true);
    assert.equal(world.expireCalls.length, 1);
    assert.equal(JSON.stringify(world.expireCalls[0].request), saved.bytes, 'exact saved bytes');
    assert.equal(JSON.stringify(saved.request), saved.bytes);
    assert.equal(world.timeRequests.length, 0, 'recovery never needs /v2/time');
    assert.equal(runtime.runtime.journal, null, 'cleared only on the server answer');
    // A new authorization still requires trusted time.
    await assert.rejects(runtime.prepareLeaseRequest(undefined, null, 1), { code: 'server_time_unavailable' });
    assert.equal(world.proofs.length, 0);
});

test('without a server expiry answer the saved journal is kept: future-dated, accepted-unknown and failed handshakes', async t => {
    for (const [label, offset, configure] of [['future-dated', 600, () => {}], ['handshake failure', -400, w => { w.expireFails = true; }]]) {
        const world = worldFor(t, { skewMs: -3 * HOUR, timeEndpoint: 'network' });
        configure(world);
        const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
        const saved = savedJournal(world, world.serverSeconds() + offset);
        runtime.runtime = { ...runtime.runtime, journal: saved.journal };
        if (label === 'future-dated') assert.equal(await runtime.recoverUnacceptedNativeQuote(saved.request), false, label);
        else await assert.rejects(runtime.recoverUnacceptedNativeQuote(saved.request), /temporarily unavailable/);
        assert.equal(world.expireCalls.length, 1, label);
        assert.equal(runtime.runtime.journal, saved.journal, `${label}: journal intact`);
        assert.equal(JSON.stringify(saved.request), saved.bytes);
        assert.equal(runtime.commits.length, 0);
        assert.equal(world.timeRequests.length, 0);
    }
});

test('a signed receipt installs on a slow device while /v2/time fails; a changed quote is still refused', async t => {
    const world = worldFor(t, { skewMs: -3 * HOUR, timeEndpoint: 'network' });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const saved = savedJournal(world, world.serverSeconds() - 30);
    runtime.runtime = { ...runtime.runtime, journal: saved.journal };
    world.receipts = new Map([['saved-request', { response_payload: JSON.stringify({ billing_quote: { ...world.quote(), round_id: '999' } }) }]]);
    await assert.rejects(runtime.installRecoveredResponse('saved-request'), /changed the authorized ETH\/USD quote/);
    assert.equal(runtime.runtime.journal, saved.journal, 'journal intact on a real receipt error');
    world.receipts.set('saved-request', { response_payload: JSON.stringify({ billing_quote: world.quote() }) });
    assert.equal(await runtime.installRecoveredResponse('saved-request'), true);
    assert.equal(world.completed.length, 1);
    assert.equal(world.completed[0].journal, saved.journal, 'the exact saved journal completes the receipt');
    assert.equal(runtime.runtime.journal, null);
    assert.equal(world.timeRequests.length, 0);
});

test('a cached ordinary key is not returned after a 20-minute suspend when /v2/time fails, with no host callbacks', async t => {
    const world = worldFor(t, { skewMs: 3 * HOUR });
    const runtime = serverTimeRuntime(BrowserWalletRuntime, world, { funding });
    const lease = await runtime.issueLease('chat', undefined, null, 1);
    const journal = runtime.runtime.journal;
    world.suspend(20 * 60_000);
    world.timeEndpoint = 'network';
    await assert.rejects(runtime.acquireEphemeralKey('chat', undefined, { spendingLimitUsd: 1 }), { code: 'server_time_unavailable' });
    assert.equal(lease.inFlight, 0, 'the expired key was never checked out');
    assert.equal(world.leasePosts.length, 1, 'no replacement authorization');
    assert.equal(runtime.runtime.journal, journal, 'saved authorization preserved');
    assert.ok(world.serverSeconds() >= lease.expires_at + 600);
});
