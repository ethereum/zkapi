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
- Browser: `https://staging.openanonymity.ai`, version v4.
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
