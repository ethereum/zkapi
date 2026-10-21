# Legacy wallet store fixture (045b444)

Byte-for-byte copies of `sdk/services/browserWalletStore.js` and the module it
imports, `sdk/services/zkapiWithdrawalRecovery.mjs`, at revision 045b444: the
last browser build without the transmitted-request archive. The old-build
compatibility test in `../../browser-wallet-request-archive.test.mjs` imports
them directly and pins their SHA-256, so it runs without git history (shallow
CI clones, installed packages) and fails if a file is missing or edited.

Do not edit or reformat these files. To refresh them, run
`git show 045b444:sdk/services/<file>` and update the pinned hashes.
