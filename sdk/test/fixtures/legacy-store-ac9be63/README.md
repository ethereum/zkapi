# Legacy wallet store fixture (ac9be63, release/v2-note-bound)

Byte-for-byte copies of `sdk/services/browserWalletStore.js` and the two
modules it imports, `sdk/services/zkapiRequestArchive.mjs` and
`sdk/services/zkapiWithdrawalRecovery.mjs`, at revision ac9be63: the commit
`release/v2-note-bound` is cut at, so the legacy (circuit
zkapi-v2-note-bound-v1) build that shares IndexedDB `zkapi-browser-wallet-v1`
with this build (design §10.5). `../../browser-wallet-coexistence.test.mjs`
runs them over a store this build wrote, and this build over a store they
wrote, and pins their SHA-256 so the check needs no git history.

Do not edit or reformat these files. To refresh them, run
`git show ac9be63:sdk/services/<file>` and update the pinned hashes.

`../v2c-store-snapshot.json` is the other direction's input: every object
store, as this build leaves it mid-exit (exit lock, deposit path,
`late_successor` / `invalid_successor` records, `exit_deferred` readings, an
open escape with concession fields) beside a set-aside legacy mutual close.
The release branch can load it into its own build's test store to check the
same property from its side. `ZKAPI_UPDATE_FIXTURES=1 node --test
sdk/test/browser-wallet-coexistence.test.mjs` rewrites it.
