# zkAPI sample host: two builds on one origin

During the move from circuit `zkapi-v2-note-bound-v1` to
`zkapi-v2-concession-v1`, a host serves both browser builds side by side
(design `docs/design/concession-exit.md` §10.5):

| Build | Package entry | Served at | Vault |
| --- | --- | --- | --- |
| legacy (note-bound) | `zkapi-sdk-legacy` | `/zkapi/` (its existing `publicPath`) | the legacy vault |
| current (concession) | `zkapi-sdk` | `/zkapi/v2c/` | the vault revision 3 |

There is no multi-circuit loader. Each package keeps its own WebAssembly,
proving keys and worker, and bundles its own `../wasm/zkapi_browser.js`. Both
builds share IndexedDB `zkapi-browser-wallet-v1` (version 3) and its Web Lock,
and each runtime's `reload()` refuses a runtime slot that holds another
deployment's note. Neither build rewrites the other deployment's records.

## The recipe

1. `package.json` lists the two package entries. Replace the placeholder tags
   with the published ones (`v0.1.<n>` for the config-only re-cut of
   `release/v2-note-bound`, `v0.2.<n>` for a concession release; see
   [versioning](../../docs/versioning.md)):

   ```json
   "zkapi-sdk": "git+https://github.com/ethereum/zkapi.git#v0.2.<n>",
   "zkapi-sdk-legacy": "git+https://github.com/ethereum/zkapi.git#v0.1.<n>"
   ```

2. `src/loader.mjs` reads `readBrowserWalletHoldings()` and `import()`s the
   legacy entry while a legacy runtime holds an open note, and the current
   entry otherwise (`chooseZkapiBuild`). It then points the chosen package at
   its own `browser-config.json` and worker (`loadZkapi`).
   - A legacy withdrawal that is still open (a set-aside close or a pending
     escape) while the runtime slot is empty appears in `legacyOpen`. Only the
     legacy build can finish it, so the page offers `{ prefer: 'legacy' }`.
   - That choice is refused with `legacy_build_blocked` while the current
     build's runtime holds a note.
   - One SDK runs per page: switching builds reloads the page.

3. `build.mjs` calls each package's `./build` export
   (`buildBrowserSdkAssets`) with its own `publicPath`. It then bundles
   `src/app.mjs` with code splitting, so each SDK is its own chunk.

   ```sh
   npm install
   npm run build        # node build.mjs --out dist
   ```

   The output is `dist/zkapi/` (legacy), `dist/zkapi/v2c/` (current),
   `dist/app/`, `dist/index.html` and `dist/zkapi-builds.json`. Serve `dist/`
   at the origin's root.

Until the concession vault is deployed, the current package's network profiles
are `not_deployed` placeholders. Its build therefore stops with
`deployment_not_deployed`, which is the intended refusal.

## Tests

`sdk/test/sample-host.test.mjs` installs both packages the way npm does:

- the legacy one from git revision `ac9be63`, where `release/v2-note-bound`
  is cut;
- the current one as a copy of this package with a deployed test profile.

It builds this host and checks:

- each deployment's pinned WebAssembly, keys and worker sit under its own
  path;
- the app holds two SDK chunks;
- the bundled loader chooses the legacy SDK only while a legacy note is in the
  runtime slot.

`sdk/test/browser-wallet-coexistence.test.mjs` runs the legacy store
(vendored from `ac9be63`) and this build's store over one shared database in
both directions.
