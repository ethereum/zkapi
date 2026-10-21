#!/usr/bin/env node
// The zkAPI release version has one source of truth, the VERSION file at the
// repository root; docs/versioning.md is the policy.
//
//   node scripts/version.mjs check [--tag <git tag>]   every place agrees with VERSION
//   node scripts/version.mjs set <MAJOR.MINOR.PATCH>   write VERSION and every place
//
// `check --tag` also requires the tag to name VERSION (`v<VERSION>` or
// `clientd-v<VERSION>`). `set` rewrites the files in place and leaves the rest
// of each file byte for byte as it was.

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const TAG = /^(v|clientd-v)(.+)$/;

// Every place a release version is written. `read` returns the versions found
// in the file's text (a lockfile holds one per workspace crate); `write`
// returns the text with all of them replaced.
const tomlWorkspace = {
    read(text) {
        const match = /^\[workspace\.package\]\n(?:(?!\[)[^\n]*\n)*?version = "([^"\n]+)"/m.exec(text);
        return match ? [match[1]] : [];
    },
    write(text, version) {
        return text.replace(/^(\[workspace\.package\]\n(?:(?!\[)[^\n]*\n)*?version = ")[^"\n]+(")/m, `$1${version}$2`);
    },
};

// Workspace crates appear in a Cargo.lock without a `source` line.
const WORKSPACE_CRATE = /(\[\[package\]\]\nname = "zkapi-[^"\n]+"\nversion = ")([^"\n]+)("\n(?!source ))/g;
const cargoLock = {
    read(text) {
        return [...text.matchAll(WORKSPACE_CRATE)].map((match) => match[2]);
    },
    write(text, version) {
        return text.replace(WORKSPACE_CRATE, `$1${version}$3`);
    },
};

const packageJson = {
    read(text) {
        return [JSON.parse(text).version];
    },
    write(text, version) {
        return text.replace(/^(  "version": ")[^"\n]+(",?)$/m, `$1${version}$2`);
    },
};

// The lockfile repeats the package's version for its root entry.
const packageLock = {
    read(text) {
        const lock = JSON.parse(text);
        return [lock.version, lock.packages?.['']?.version];
    },
    write(text, version) {
        return text
            .replace(/^(  "version": ")[^"\n]+(",?)$/m, `$1${version}$2`)
            .replace(/^(  "packages": \{\n    "": \{\n(?:      [^\n]*\n)*?      "version": ")[^"\n]+(")/m, `$1${version}$2`);
    },
};

const openapi = {
    read(text) {
        const match = /^info:\n(?:  [^\n]*\n)*?  version: ([^\n]+)\n/m.exec(text);
        return match ? [match[1].trim()] : [];
    },
    write(text, version) {
        return text.replace(/^(info:\n(?:  [^\n]*\n)*?  version: )[^\n]+/m, `$1${version}`);
    },
};

export const PLACES = [
    { file: 'Cargo.toml', ...tomlWorkspace },
    { file: 'protocol/rust/Cargo.toml', ...tomlWorkspace },
    { file: 'Cargo.lock', ...cargoLock },
    { file: 'protocol/rust/Cargo.lock', ...cargoLock },
    { file: 'package.json', ...packageJson },
    { file: 'package-lock.json', ...packageLock },
    { file: 'docker/aws/signer/package.json', ...packageJson },
    { file: 'docker/aws/signer/package-lock.json', ...packageLock },
    { file: 'docs/openapi.yaml', ...openapi },
];

export function assertVersion(version) {
    if (typeof version !== 'string' || !SEMVER.test(version)) {
        throw new Error(`${JSON.stringify(version)} is not a semantic version (MAJOR.MINOR.PATCH, optionally -prerelease; no build metadata)`);
    }
    return version;
}

export function readVersion(root) {
    return assertVersion(readFileSync(path.join(root, 'VERSION'), 'utf8').trim());
}

// The disagreements between VERSION and the files; empty when everything agrees.
export function check(root, { tag } = {}) {
    const expected = readVersion(root);
    const problems = [];
    for (const place of PLACES) {
        const found = place.read(readFileSync(path.join(root, place.file), 'utf8'));
        if (found.length === 0 || found.some((value) => value === undefined)) {
            problems.push(`${place.file}: no version found`);
        }
        for (const value of new Set(found.filter((item) => item !== undefined))) {
            if (value !== expected) problems.push(`${place.file}: ${value}, VERSION is ${expected}`);
        }
    }
    if (tag !== undefined) {
        const match = TAG.exec(tag);
        if (!match) problems.push(`tag ${tag}: not v<version> or clientd-v<version>`);
        else if (match[2] !== expected) problems.push(`tag ${tag}: names ${match[2]}, VERSION is ${expected}`);
    }
    return problems;
}

export function set(root, version) {
    assertVersion(version);
    for (const place of PLACES) {
        const file = path.join(root, place.file);
        const before = readFileSync(file, 'utf8');
        const after = place.write(before, version);
        if (after !== before) writeFileSync(file, after);
    }
    writeFileSync(path.join(root, 'VERSION'), `${version}\n`);
    return check(root);
}

function main(argv) {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const [command, ...rest] = argv;
    if (command === 'check') {
        const at = rest.indexOf('--tag');
        const problems = check(root, at === -1 ? {} : { tag: rest[at + 1] });
        if (problems.length > 0) {
            const fix = problems.some((problem) => !problem.startsWith('tag '))
                ? '\nfix: node scripts/version.mjs set <version>' : '';
            console.error(`version check failed:\n  ${problems.join('\n  ')}${fix}`);
            return 1;
        }
        console.log(`version ${readVersion(root)}: every file agrees`);
        return 0;
    }
    if (command === 'set' && rest.length === 1) {
        const problems = set(root, rest[0]);
        if (problems.length > 0) {
            console.error(`version set left disagreements:\n  ${problems.join('\n  ')}`);
            return 1;
        }
        console.log(`version ${rest[0]} written to VERSION and ${PLACES.length} files`);
        return 0;
    }
    console.error('usage: node scripts/version.mjs check [--tag <tag>] | set <MAJOR.MINOR.PATCH>');
    return 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        process.exitCode = main(process.argv.slice(2));
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}
