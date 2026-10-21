# Versioning

zkAPI follows [Semantic Versioning 2.0.0](https://semver.org/) and stays on
**major version 0**. Under SemVer a `0.y.z` version promises nothing about a
stable API: any interface, wire format, file format, flag or configuration key
may change in any release. The project does not yet promise to keep an API
stable, and version 1.0.0 will say that it does.

## One version for everything

Everything built from one commit carries one version, `MAJOR.MINOR.PATCH`:

- both Rust workspaces (the root workspace and `protocol/rust`) and every
  binary built from them (`zkapi-serverd`, `zkapi-indexerd`, `zkapi-cli`,
  `zkapi-companion`, the browser WebAssembly) and the container images;
- the browser SDK (`@openanonymity/zkapi-browser-sdk`) and the signer
  sidecar (`docker/aws/signer`);
- `zkapi-clientd` and its companion, `zkapi-walletd`;
- the OpenAPI document, `docs/openapi.yaml` (`info.version`).

The root file `VERSION` is the single source of truth.

```sh
node scripts/version.mjs check                         # every file agrees with VERSION
node scripts/version.mjs check --tag clientd-v0.2.0    # and the tag names VERSION
node scripts/version.mjs set 0.2.1                     # rewrite VERSION and every file
```

CI runs `check`, and the `zkapi-clientd` release workflow runs `check --tag`
on a release tag, so a tag cannot name a version the files do not carry.

## What a bump means before 1.0

| Bump | Use it when | Example |
| --- | --- | --- |
| `0.y.0` (**MINOR**) | Anything that makes the new release unable to work with the previous one: a new circuit or trusted setup, a new vault, a changed wire or file format, a database or checkpoint that needs migrating, a removed or renamed flag or configuration key | `0.1.x` to `0.2.0`: the concession-exit circuit and vault |
| `0.y.z` (**PATCH**) | Fixes and additions that work with every release of the same `0.y` line | a server bug fix; a new optional response field |

Components of the same `0.y` line work together: serverd `0.2.3` with SDK
`0.2.0` and clientd `0.2.1`. Components of different lines refuse each other
with a typed error (for example `incompatible_proof_circuit` or
`deployment_binding`) instead of misbehaving. Before 1.0 a feature may be
removed without a deprecation period.

Release notes go in [CHANGELOG.md](../CHANGELOG.md). Anything that needs
action from an operator, a host or a user is listed under **Breaking**.

## Release lines

A release line is a `0.y` series. Each one is tied to one on-chain contract
revision, because a vault is immutable: a new vault is always a new MINOR.

| Line | Branch | Circuit | Vault | Status |
| --- | --- | --- | --- | --- |
| `0.1.x` | `release/v2-note-bound` | `zkapi-v2-note-bound-v1` | the originally deployed vault (revision 1) | Maintenance only: security fixes and the drain tooling of the [migration](migration-concession-vault.md). Ends when the legacy vault is drained and its stack retired |
| `0.2.x` | `main` | `zkapi-v2-concession-v1` | the concession-exit vault (revision 3) | Development; the first release is `0.2.0` |

## Numbers that are not release versions

Several things carry their own number. They describe a format or a capability,
not a release, and they change only with the thing they describe. Changing one
normally forces a MINOR bump.

| Number | What it identifies |
| --- | --- |
| `protocol_version` (2) | The note and proof layout inside signed states and public inputs |
| circuit ID, setup ID (`zkapi-v2-concession-v1`, `dev`, `mpc-1`) | The statement a proof proves and the keys that verify it; pinned in the vault's adapter |
| `vault_revision` (3), `exit_concession` (1) | The contract revision and its capability marker |
| `bridge_version` (5) | The wire contract between `zkapi-clientd` and its companion |
| `/v1`, `/v2` in API paths | The generation of an endpoint family |
| store, checkpoint and file formats (`zkapi-exit-kit-v1`, indexer cursor version, IndexedDB version) | On-disk formats; each build refuses a format it does not know |

A contract is identified by chain, address, runtime codehash and circuit ID,
never by a semantic version. It is not upgraded; a new revision is a new
deployment, and the release that supports it is a new `0.y` line.

## Tags and branches

| Tag | Meaning |
| --- | --- |
| `v0.2.0` | The release of everything at that version, on the line's branch |
| `clientd-v0.2.0` | Triggers the `zkapi-clientd` release workflow; must equal `VERSION` at the tagged commit |

A pre-release carries a suffix (`0.2.0-rc.1`). The `zkapi-clientd` workflow
publishes only plain `MAJOR.MINOR.PATCH` tags.

The legacy line's tags (`v0.1.7`, `clientd-v0.1.7`, the config-only SDK re-cut
as the next `v0.1.x`) are cut on `release/v2-note-bound`. That branch keeps its
Rust crate versions as they are, because the browser WebAssembly embeds them
(see below) and the re-cut ships the same WebAssembly bytes as before. Its tag
is its version; a binary built from that branch may report `0.1.0` for its
crates.

## Cutting a release

1. Update `CHANGELOG.md`: move the release's notes out of `Unreleased`.
2. `node scripts/version.mjs set <version>`.
3. Commit it. The rebuilt WebAssembly records the commit it was built from, so
   this commit must exist before step 4.
4. Rebuild and re-pin the browser bundle:
   `scripts/build-browser-client.sh --setup <dev|mpc-1>`. **A crate's version
   is part of the compiled bytes, so every version change changes the
   WebAssembly.** `npm run verify:wasm` fails until this is done.
5. Commit the bundle. Then, if a companion, protocol or `Cargo.lock` change is
   in the release, move `ZKAPI_SOURCE_COMMIT` in
   `zkapi-clientd/packaging/zkapi-source.env` to a pushed commit that holds it.
6. Run the full CI suite, tag `v<version>`, and for a client release tag
   `clientd-v<version>`.

## 1.0.0

Version 1.0.0 is a deliberate decision to promise a stable API. It needs at
least a reviewed circuit and a completed multi-party setup (see
[the migration runbook](migration-concession-vault.md), Phase A), a vault that
has run on mainnet without a change to its interface, and a written statement
of which interfaces are stable. Until then,
`sdk/test/version-sync.test.mjs` fails if `VERSION` leaves major version 0, so
that the move is made on purpose.
