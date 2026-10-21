import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

// Checks the gateway configuration without Docker. The static tests parse
// nginx.conf; the live test runs it against a stub API when an nginx binary is
// available (NGINX_BIN, or nginx on PATH). ZKAPI_REQUIRE_NGINX=1 makes a
// missing binary a failure instead of a skip.
const CONFIG_PATH = resolve('docker/aws/nginx.conf');
const config = await readFile(CONFIG_PATH, 'utf8');

function tokenize(source) {
    const tokens = [];
    let i = 0;
    while (i < source.length) {
        const c = source[i];
        if (/\s/.test(c)) {
            i += 1;
        } else if (c === '#') {
            while (i < source.length && source[i] !== '\n') i += 1;
        } else if (c === '{' || c === '}' || c === ';') {
            tokens.push({ type: c });
            i += 1;
        } else if (c === '"' || c === "'") {
            let value = '';
            i += 1;
            while (source[i] !== c) {
                if (source[i] === '\\') i += 1;
                if (i >= source.length) throw new Error('unterminated string');
                value += source[i];
                i += 1;
            }
            i += 1;
            tokens.push({ type: 'word', value });
        } else {
            let value = '';
            while (i < source.length && !/[\s{};]/.test(source[i])) {
                value += source[i];
                i += 1;
            }
            tokens.push({ type: 'word', value });
        }
    }
    return tokens;
}

// Directives as {name, args, block?}; quoted strings keep their braces.
function parse(tokens) {
    let i = 0;
    function block() {
        const directives = [];
        while (i < tokens.length && tokens[i].type !== '}') {
            const words = [];
            while (tokens[i].type === 'word') words.push(tokens[i++].value);
            const [name, ...args] = words;
            if (tokens[i].type === ';') {
                i += 1;
                directives.push({ name, args });
            } else if (tokens[i].type === '{') {
                i += 1;
                directives.push({ name, args, block: block() });
                assert.equal(tokens[i]?.type, '}', `unclosed block ${name}`);
                i += 1;
            } else {
                throw new Error(`unexpected token after ${name}`);
            }
        }
        return directives;
    }
    const directives = block();
    assert.equal(i, tokens.length, 'unbalanced braces');
    return directives;
}

const main = parse(tokenize(config));
const httpBlock = main.find(d => d.name === 'http').block;
const serverBlock = httpBlock.find(d => d.name === 'server').block;
const locations = serverBlock.filter(d => d.name === 'location');
const all = (block, name) => block.filter(d => d.name === name);
const one = (block, name) => {
    const found = all(block, name);
    assert.equal(found.length, 1, `expected one ${name}`);
    return found[0];
};

// nginx location selection for this config: an exact match wins, otherwise
// the longest prefix. The config has no regex locations.
function selectLocation(uri) {
    assert.ok(locations.every(l => l.args[0] === '=' || l.args.length === 1), 'unexpected location modifier');
    const exact = locations.find(l => l.args[0] === '=' && l.args[1] === uri);
    if (exact) return exact;
    return locations
        .filter(l => l.args.length === 1 && !l.args[0].startsWith('@') && uri.startsWith(l.args[0]))
        .sort((a, b) => b.args[0].length - a.args[0].length)[0];
}

function forwardedSourcePattern() {
    const map = httpBlock.find(d => d.name === 'map' && d.args[0] === '$http_x_forwarded_for');
    assert.ok(map, 'X-Forwarded-For map');
    assert.equal(map.args[1], '$zkapi_source');
    const entries = map.block.map(d => [d.name, ...d.args]);
    assert.deepEqual(entries.find(([key]) => key === 'default'), ['default', '$remote_addr']);
    const [pattern, value] = entries.find(([key]) => key.startsWith('~')).map(String);
    const capture = /\(\?<([a-z_]+)>/.exec(pattern)[1];
    assert.equal(value, `$${capture}`);
    return { regex: new RegExp(pattern.slice(1)), capture, pattern: pattern.slice(1) };
}

test('rate-limit zones are http-level and count only POST requests', () => {
    const zones = all(httpBlock, 'limit_req_zone');
    assert.deepEqual(zones.map(z => z.args), [
        ['$zkapi_post_source', 'zone=zkapi_clearance:10m', 'rate=10r/s'],
        ['$zkapi_post_source', 'zone=zkapi_lease:10m', 'rate=20r/s'],
        ['$zkapi_post_source', 'zone=zkapi_v2_post:10m', 'rate=20r/s'],
    ]);
    const methods = httpBlock.find(d => d.name === 'map' && d.args[0] === '$request_method');
    assert.equal(methods.args[1], '$zkapi_post_source');
    assert.deepEqual(methods.block.map(d => [d.name, ...d.args]), [['default', ''], ['POST', '$zkapi_source']]);
    assert.deepEqual(one(httpBlock, 'limit_req_status').args, ['429']);
});

test('the forwarded source is the last X-Forwarded-For address, else the TCP peer', () => {
    const { regex, capture } = forwardedSourcePattern();
    const source = header => regex.exec(header)?.groups[capture] ?? null;
    assert.equal(source('1.2.3.4, 5.6.7.8'), '5.6.7.8');
    assert.equal(source('1.2.3.4,5.6.7.8'), '5.6.7.8');
    assert.equal(source('spoofed, 10.0.0.1, 192.0.2.7  '), '192.0.2.7');
    assert.equal(source('9.9.9.9'), '9.9.9.9');
    assert.equal(source('2001:db8::1'), '2001:db8::1');
    assert.equal(source('1.2.3.4, 2001:db8:0:0:0:0:2:1'), '2001:db8:0:0:0:0:2:1');
    // Anything else falls back to $remote_addr.
    for (const header of ['', ' ', ',', '1.2.3.4,', 'unknown', '1.2.3.4, unknown', 'a'.repeat(46)]) {
        assert.equal(source(header), null, JSON.stringify(header));
    }
});

test('the forwarded-source pattern is anchored and linear on hostile headers', () => {
    const { regex, pattern } = forwardedSourcePattern();
    // An unanchored pattern restarts at every offset: quadratic in the header.
    assert.ok(pattern.startsWith('^') && pattern.endsWith('$'), pattern);
    assert.ok(!/\)[*+{]/.test(pattern), 'no repeated groups (nested quantifiers)');
    const longest = 8_000;
    for (const header of [
        'a'.repeat(longest) + ',',
        'a'.repeat(longest) + ', 1.2.3.4',
        ', '.repeat(longest / 2),
        'a '.repeat(longest / 2) + ',',
        '1'.repeat(longest),
    ]) {
        const started = performance.now();
        for (let i = 0; i < 20; i += 1) regex.exec(header);
        assert.ok(performance.now() - started < 200, `slow on ${header.slice(0, 12)}…`);
    }
    assert.equal(nginxPcreJit(), 'on');
});

function nginxPcreJit() {
    const index = main.findIndex(d => d.name === 'pcre_jit');
    assert.ok(index >= 0 && index < main.findIndex(d => d.name === 'http'), 'pcre_jit belongs in the main context');
    return main[index].args[0];
}

test('clearance, lease issuance and other /v2/ POST routes are limited', () => {
    const expected = {
        '/v2/withdraw/clearance': ['zone=zkapi_clearance', 'burst=100', 'nodelay'],
        '/v2/openrouter/leases': ['zone=zkapi_lease', 'burst=200', 'nodelay'],
        '/v2/openrouter/leases/request-id': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/openrouter/leases/request-id/expire': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/withdraw/clearance/': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/requests/request-id': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/nullifiers/0x1': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        // The stale-device evidence read is limited like recovery: a GET,
        // so the POST-only zone never counts it.
        '/v2/nullifiers/0x1/evidence': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/auth': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
        '/v2/billing/quote': ['zone=zkapi_v2_post', 'burst=200', 'nodelay'],
    };
    for (const [uri, limit] of Object.entries(expected)) {
        const location = selectLocation(uri);
        assert.deepEqual(one(location.block, 'limit_req').args, limit, uri);
        assert.deepEqual(one(location.block, 'proxy_pass').args, ['$server_upstream'], uri);
    }
});

test('tree, health, attestation, static and internal routes are not limited or not proxied', () => {
    for (const uri of ['/health', '/v1/attestation', '/v1/tree/root', '/v1/tree/notes/1/zero-path',
        '/config.json', '/proofs/request.pk', '/proofs/withdrawal.pk', '/proofs/manifest.json']) {
        assert.equal(all(selectLocation(uri).block, 'limit_req').length, 0, uri);
    }
    // Operator and internal endpoints stay behind the catch-all 404.
    for (const uri of ['/v1/dashboard/settlement', '/v1/dashboard/summary', '/v1/escapes/pending',
        '/metrics', '/livez', '/status', '/v1/tree', '/']) {
        const location = selectLocation(uri);
        assert.deepEqual(location.args, ['/'], uri);
        assert.deepEqual(one(location.block, 'return').args, ['404'], uri);
    }
});

test('throttled responses are ErrorResponse JSON with a matching Retry-After', () => {
    assert.deepEqual(one(serverBlock, 'error_page').args, ['429', '@zkapi_rate_limited']);
    const named = locations.find(l => l.args[0] === '@zkapi_rate_limited').block;
    const [code, body] = one(named, 'return').args;
    assert.equal(code, '429');
    assert.ok(!body.includes('$'), 'the body must not interpolate variables');
    const payload = JSON.parse(body);
    assert.deepEqual(Object.keys(payload), ['status', 'client_request_id', 'error_code', 'error_message',
        'retriable', 'retry_after_seconds']);
    assert.equal(payload.status, 'error');
    assert.equal(payload.error_code, 'gateway_rate_limited');
    assert.equal(payload.retriable, true);
    const headers = Object.fromEntries(all(named, 'add_header').map(d => {
        assert.equal(d.args[2], 'always', d.args[0]);
        return [d.args[0], d.args[1]];
    }));
    assert.equal(Number(headers['Retry-After']), payload.retry_after_seconds);
    assert.equal(headers['Cache-Control'], 'no-store');
    assert.equal(one(named, 'default_type').args[0], 'application/json');
});

test('requests are not logged and throttling logs only its status and zone', () => {
    assert.deepEqual(one(httpBlock, 'access_log').args, ['off']);
    assert.deepEqual(one(main, 'error_log').args, ['/dev/stderr', 'warn']);
    assert.deepEqual(one(httpBlock, 'limit_req_log_level').args, ['info']);
    const logged = locations.filter(l => all(l.block, 'access_log').length);
    assert.deepEqual(logged.map(l => l.args[0]), ['@zkapi_rate_limited']);
    const [, format] = one(logged[0].block, 'access_log').args;
    const definition = one(httpBlock, 'log_format').args;
    assert.equal(definition[0], format);
    const variables = definition.slice(1).join('').match(/\$[a-z_]+/g);
    assert.deepEqual(variables, ['$status', '$zkapi_limit_zone']);
    const zones = httpBlock.find(d => d.name === 'map' && d.args[0] === '$uri');
    assert.equal(zones.args[1], '$zkapi_limit_zone');
    assert.deepEqual(zones.block.map(d => [d.name, ...d.args]), [
        ['default', 'zkapi_v2_post'],
        ['/v2/withdraw/clearance', 'zkapi_clearance'],
        ['/v2/openrouter/leases', 'zkapi_lease'],
    ]);
});

function nginxBinary() {
    const candidate = process.env.NGINX_BIN || 'nginx';
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8' });
    return probe.error ? null : candidate;
}

async function freePort() {
    const server = net.createServer();
    await new Promise(done => server.listen(0, '127.0.0.1', done));
    const { port } = server.address();
    await new Promise(done => server.close(done));
    return port;
}

function request(port, { method = 'POST', path, headers = {}, body = '{}' }) {
    return new Promise((done, fail) => {
        const started = performance.now();
        const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, res => {
            let data = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: data,
                elapsed: performance.now() - started }));
        });
        req.on('error', fail);
        if (method === 'POST') req.end(body); else req.end();
    });
}

const nginx = nginxBinary();
const live = nginx || process.env.ZKAPI_REQUIRE_NGINX === '1';

test('the gateway limits per source, answers 429 JSON and passes API errors through', { skip: !live && 'nginx is not installed' }, async () => {
    assert.ok(nginx, 'ZKAPI_REQUIRE_NGINX=1 but no nginx binary was found (set NGINX_BIN)');
    const dir = await mkdtemp(join(tmpdir(), 'zkapi-gateway-'));
    const upstreamHits = [];
    const upstream = http.createServer((req, res) => {
        upstreamHits.push(`${req.method} ${req.url}`);
        req.resume();
        req.on('end', () => {
            if (req.url === '/v2/openrouter/leases/upstream-throttled') {
                res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '30' });
                res.end('{"status":"error","error_code":"oa_minute_request_limit","retriable":true}');
            } else {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end('{"status":"ok"}');
            }
        });
    });
    await new Promise(done => upstream.listen(0, '127.0.0.1', done));
    const port = await freePort();
    // Same configuration, with local ports and paths. JIT is off so the
    // hostile-header timings measure the pattern itself.
    const local = config
        .replaceAll('/tmp/', `${dir}/`)
        .replace('pcre_jit on;', 'pcre_jit off;')
        .replace('listen 8080;', `listen 127.0.0.1:${port};`)
        .replaceAll(/http:\/\/(server|indexer):300[01]/g, `http://127.0.0.1:${upstream.address().port}`);
    const configPath = join(dir, 'nginx.conf');
    await writeFile(configPath, local);
    let stdout = '';
    let stderr = '';
    const child = spawn(nginx, ['-p', `${dir}/`, '-e', 'stderr', '-c', configPath, '-g', 'daemon off;']);
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    try {
        for (let attempt = 0; ; attempt += 1) {
            try {
                await request(port, { method: 'GET', path: '/health' });
                break;
            } catch (error) {
                if (attempt > 100) throw new Error(`nginx did not start: ${stderr}`, { cause: error });
                await new Promise(done => setTimeout(done, 50));
            }
        }

        // Hostile X-Forwarded-For values near nginx's 8 KB header-line limit.
        for (const value of [
            'a'.repeat(7_990) + ',',
            'a'.repeat(7_980) + ', 198.51.100.1',
            ', '.repeat(3_995),
            'a '.repeat(3_990) + ',',
        ]) {
            const timings = [];
            for (let i = 0; i < 5; i += 1) {
                const response = await request(port, { path: '/v2/openrouter/leases/hostile', headers: { 'x-forwarded-for': value } });
                assert.equal(response.status, 200);
                timings.push(response.elapsed);
            }
            assert.ok(Math.min(...timings) < 100, `hostile header took ${Math.min(...timings)} ms`);
        }

        // One source exhausts the clearance burst; the next request is refused.
        const source = { 'x-forwarded-for': '203.0.113.9, 192.0.2.10' };
        let throttled = null;
        let accepted = 0;
        for (let i = 0; i < 150 && !throttled; i += 1) {
            const response = await request(port, { path: '/v2/withdraw/clearance', headers: source });
            if (response.status === 429) throttled = response; else accepted += 1;
        }
        assert.ok(throttled, 'no request was throttled');
        assert.ok(accepted >= 100, `only ${accepted} accepted before the burst was exhausted`);
        assert.equal(throttled.headers['content-type'], 'application/json');
        assert.equal(throttled.headers['retry-after'], '5');
        assert.equal(throttled.headers['cache-control'], 'no-store');
        const payload = JSON.parse(throttled.body);
        assert.equal(payload.error_code, 'gateway_rate_limited');
        assert.equal(payload.retriable, true);
        assert.equal(payload.retry_after_seconds, 5);
        // A refilled token may let one through; a refused request never reaches the API.
        const hitsBefore = upstreamHits.length;
        const statuses = [];
        for (let i = 0; i < 3; i += 1) {
            statuses.push((await request(port, { path: '/v2/withdraw/clearance', headers: source })).status);
        }
        assert.ok(statuses.includes(429), statuses.join(','));
        assert.equal(upstreamHits.length - hitsBefore, statuses.filter(status => status !== 429).length,
            'a throttled request reached the API');

        // Other sources, other zones, reads and preflights are unaffected.
        assert.equal((await request(port, { path: '/v2/withdraw/clearance', headers: { 'x-forwarded-for': '192.0.2.10, 192.0.2.11' } })).status, 200);
        assert.equal((await request(port, { path: '/v2/openrouter/leases', headers: source })).status, 200);
        for (const method of ['GET', 'OPTIONS']) {
            for (let i = 0; i < 5; i += 1) {
                assert.equal((await request(port, { method, path: '/v2/withdraw/clearance', headers: source })).status, 200);
            }
        }
        assert.equal((await request(port, { method: 'GET', path: '/v2/nullifiers/0x1', headers: source })).status, 200);

        // The API's own 429 passes through unchanged.
        const passed = await request(port, { path: '/v2/openrouter/leases/upstream-throttled' });
        assert.equal(passed.status, 429);
        assert.equal(passed.headers['retry-after'], '30');
        assert.equal(JSON.parse(passed.body).error_code, 'oa_minute_request_limit');

        // Internal routes are never proxied.
        for (const path of ['/v1/dashboard/settlement', '/v1/escapes/pending', '/metrics']) {
            const before = upstreamHits.length;
            assert.equal((await request(port, { method: 'GET', path })).status, 404, path);
            assert.equal(upstreamHits.length, before, path);
        }

        // Throttling is logged as status and zone, without addresses or URIs.
        await new Promise(done => setTimeout(done, 200));
        const lines = stdout.trim().split('\n').filter(Boolean);
        assert.ok(lines.length >= 2, stdout);
        for (const line of lines) {
            assert.deepEqual(JSON.parse(line), { event: 'gateway_rate_limited', status: 429, zone: 'zkapi_clearance' });
        }
        assert.ok(!/203\.0\.113\.9|192\.0\.2\.10|\/v2\//.test(stdout + stderr), 'a log line names a source or URI');
    } finally {
        child.kill('SIGTERM');
        await new Promise(done => child.once('exit', done));
        await new Promise(done => upstream.close(done));
        await rm(dir, { recursive: true, force: true });
    }
});
