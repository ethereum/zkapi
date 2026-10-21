import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { PLACES, assertVersion, check, readVersion, set } from '../../scripts/version.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// A copy of every versioned file, so `set` can be exercised without touching the checkout.
function copyOfRepo() {
    const root = mkdtempSync(path.join(tmpdir(), 'zkapi-version-'));
    for (const file of ['VERSION', ...PLACES.map((place) => place.file)]) {
        mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
        cpSync(path.join(repoRoot, file), path.join(root, file));
    }
    return root;
}

test('every versioned file agrees with VERSION', () => {
    assert.deepEqual(check(repoRoot), []);
});

test('the release stays on major version 0 until the project says otherwise', () => {
    // docs/versioning.md: 0.y.z promises no stable API. Moving to 1.0.0 is a
    // deliberate decision, so changing this test is part of making it.
    assert.match(readVersion(repoRoot), /^0\.\d+\.\d+/);
});

test('set rewrites every place and nothing else', () => {
    const root = copyOfRepo();
    try {
        assert.deepEqual(set(root, '0.9.7'), []);
        for (const place of PLACES) {
            const before = readFileSync(path.join(repoRoot, place.file), 'utf8');
            const after = readFileSync(path.join(root, place.file), 'utf8');
            const removed = place.read(before);
            assert.ok(removed.length > 0, `${place.file} holds a version`);
            // Putting the old version back must restore the file byte for byte.
            const restored = place.write(after, removed[0]);
            assert.equal(restored, before, `${place.file} changed more than its version`);
        }
        assert.equal(readFileSync(path.join(root, 'VERSION'), 'utf8'), '0.9.7\n');
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
});

test('check names the file that disagrees', () => {
    const root = copyOfRepo();
    try {
        const manifest = path.join(root, 'package.json');
        writeFileSync(manifest, readFileSync(manifest, 'utf8').replace(/"version": "[^"]+"/, '"version": "0.0.1"'));
        const problems = check(root);
        assert.equal(problems.length, 1);
        assert.match(problems[0], /^package\.json: 0\.0\.1, VERSION is /);
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
});

test('a lockfile that lost a workspace crate version is reported', () => {
    const root = copyOfRepo();
    try {
        const lock = path.join(root, 'Cargo.lock');
        const text = readFileSync(lock, 'utf8');
        writeFileSync(lock, text.replace(/(name = "zkapi-serverd"\nversion = ")[^"]+/, '$10.0.1'));
        assert.deepEqual(check(root).map((problem) => problem.replace(/, VERSION.*/, '')), ['Cargo.lock: 0.0.1']);
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
});

test('a tag must name the version', () => {
    const version = readVersion(repoRoot);
    assert.deepEqual(check(repoRoot, { tag: `v${version}` }), []);
    assert.deepEqual(check(repoRoot, { tag: `clientd-v${version}` }), []);
    assert.equal(check(repoRoot, { tag: 'v9.9.9' }).length, 1);
    assert.equal(check(repoRoot, { tag: `release-${version}` }).length, 1);
});

test('only semantic versions are accepted', () => {
    for (const good of ['0.2.0', '0.2.0-rc.1', '1.0.0', '10.20.30']) assert.equal(assertVersion(good), good);
    for (const bad of ['', '0.2', 'v0.2.0', '0.2.0+build', '01.2.3', '0.2.0-', '0.2.x', ' 0.2.0']) {
        assert.throws(() => assertVersion(bad), /not a semantic version/, bad);
    }
});
