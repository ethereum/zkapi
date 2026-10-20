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
