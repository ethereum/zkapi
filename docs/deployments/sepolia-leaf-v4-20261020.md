# PR #31 Sepolia staging deployment

This deployment is based on ethereum/zkapi PR #31, commit
`4ac25c811318d96a873b8b232c7be2252e16c0bd`, with staging compatibility,
request-root retirement/freshness fencing, bounded RPC retries, and an
explicit Sepolia gas schedule for sponsored withdrawals.

- Network: Sepolia (11155111), development proving setup only.
- Deployment ID: `zkapi-native-eth-sepolia-leaf-v4-20261020`.
- Vault: `0x67EB750d9C0D63A99684AC3F3e65f0C610276993`.
- Vault creation block: 11958523.
- Service prefix: `https://zkapi-sepolia.openanonymity.ai/v0.4`.
- Browser: `https://staging.openanonymity.ai`, displayed as zkAPI v0.2
  (deployment registry entry and API prefix remain v4 and `/v0.4`).
- Minimum deposit: 0.001 test ETH; note lifetime: 30 days.
- First-version and earlier staging services remain available for existing balances.
- Mainnet and production configuration are unchanged.

The adjacent JSON records actual deployment receipts and runtime hashes.
Audit using `scripts/expected-codehashes.mjs` and **`demo/contracts/out`**.
The deployment compilation unit uses optimizer runs 200 because Deploy imports
the dual-schedule paymaster; the independently compiled Poseidon runtime uses
the pinned legacy profile. The protocol directory also contains core artifacts
compiled with 10,000 runs, which must not be substituted for deployment hashes.

All 400 Forge tests and 21 deployment/codehash tests passed. Exact deployment
artifacts also passed 13 real-proof EntryPoint simulations under Sepolia's
current pricing. The measurements and the conservative charge allowance for
partial repayment of an existing escape debt are recorded in
`protocol/contracts/snapshots/sepolia-gasless-gas.json`.

The staging bundler uses the existing pinned Alto image with API v2 and a
restricted paymaster/factory guard. EntryPoint validation and bundle simulation
remain enabled. The public RPC lacks debug tracing, so generic ERC-7562 trace
validation is not enabled on this staging relay; production bundler acceptance
is outside this deployment.

The server, indexer, challenger, signer and bundler use a separate Compose
project (`zkapi-pr31-sepolia`), data directory and signing keys. Backend source
commit is `9267853`; later backend edits are tests and documentation only.

The live smoke test deposited 0.001 test ETH into note 0, obtained an OA-org
temporary key using a browser-WASM request proof, retired that key, and verified
the signed settlement. No inference was sent and the settled balance remained
1,000,000 gwei. A fresh withdrawal signer held zero ETH both before and after
the ERC-4337 mutual close. The close returned 0.000998735066761392 ETH to the
funding owner, left the transit account empty, and marked the note Closed.

- [Deposit transaction](https://sepolia.etherscan.io/tx/0x21fa6b36cbf80d4fb59797659ad897eabc33e521c0011981f25191e9221bdce6):
  164,087 transaction gas, block 11958566.
- [Withdrawal transaction](https://sepolia.etherscan.io/tx/0xf409049d1aa7aae9f76c3619fb82bcf14b0bd820c74c943df40a711f0b8d3f29):
  1,122,514 transaction gas, block 11958579. EntryPoint separately accounted for
  1,252,843 gas, including the operation's pre-verification allowance and unused
  gas penalty. The paymaster charged 0.000001264933238608 ETH from the payout;
  the withdrawal signer paid no wallet gas.

The final deployment audit ran with `scripts/expected-codehashes.mjs`,
`--artifacts demo/contracts/out`, and `--confirmations 64`. At head 11958598,
all seven deployment and setup transactions remained canonical with at least
72 confirmations. There were zero bytecode, immutable, ownership, treasury,
paymaster policy, fee ceiling, stake, or funding mismatches. The re-finalized
manifest was unchanged, the SDK profile reproduced from it, and the served
`/v0.4/config.json` matched the public manifest and passed SDK trust validation.
This was a confirmation-depth check: the RPC's finalized head was 11958505 at
that observation, so the check did not yet establish consensus finality for the
deployment or the later smoke transactions.

## Staging UI release, 2026-10-21

The UI release uses commercial commit
`c5a110ecf99638c71e3acd5e46313bd63ed480b5` and oa-chat commit
`4db19ab0f8b3a5c60375c857ea93b8d7c8dcf986`. Both feature branches are
`codex/pr31-sepolia-staging`. They preserve the previously deployed Sepolia
password-memory changes (`f42c310` / `369334f6`) through normal merges.

The balance now displays **zkAPI v0.2**, its version help button opens an
accessible explanation, and wallet copy consistently says **Ethereum wallet**.
For supported balances, Send to address asks for the recipient and uses the
existing sponsored ERC-4337 flow, followed by fee review and explicit
confirmation. Legacy balances retain their compatible withdrawal route.
Prepared withdrawals retain their original signer and fee authorization, and
changing the destination discards an obsolete quote. Internal protocol version
identifiers, trusted deployment profiles and contract addresses are unchanged.

The complete release gate passed on these exact merged commits: 1,906
application tests, 2,739 payment tests (10 existing skips), 89 Chromium fault
scenarios, 708 commercial unit tests, and all four build/artifact suites.
Independent review passed 133 focused tests. Browser checks covered version
help with mouse and keyboard, narrow-screen layout, destination validation,
sponsored fee review, legacy withdrawal behavior and relay failure. These UI
withdrawal checks used synthetic balances; they did not submit a new funded
withdrawal. The live staging wallet entry and Sepolia access dialog also loaded.

Vercel deployment `dpl_BVRMXXjbfDde2Lw3r9E2y3zXG167` was promoted to the
dedicated `oa-staging-main` project. Canonical staging checks passed for the
frontend/oa-chat commit identities, all four balance profiles and asset hashes,
the public deployment manifest, protocol health, supported EntryPoint and
legacy protocol route. Production app manifests and configuration bytes matched
the pre-release snapshot.

An existing Tenderly public RPC outage had left the revision-4 indexer and
signer unhealthy before promotion. Only their RPC URLs were changed to the free
public `https://rpc.sepolia.ethpandaops.io` endpoint. Validation checked Sepolia
chain identity, matching block hashes, EIP-1898 vault reads, deployed bytecode,
1,000- and 10,000-block log queries, and known deposit/closure events. Protected
backups were saved on the staging host. Existing cursors, confirmation depths,
freshness checks, keys and fee policies were retained. Only the two affected
containers were recreated; all 42 other container identities and start times
were unchanged. The indexer caught up, the server reported `indexer_root:
agrees`, both containers became healthy, and challenger health reported no
alarms or outstanding obligations. The free public provider remains a shared
service without a dedicated capacity guarantee.

The protocol main update includes PR #30 and PR #31 by fast-forward. Its final
validation commit includes `[preserve-deployments]` so the tracked docs-site
Vercel ignore command skips the automatic production documentation deployment.
No production app or mainnet deployment is part of this release.
