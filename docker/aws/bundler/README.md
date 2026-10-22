# Sepolia withdrawal bundler

This overlay is for the revision-4 Sepolia staging stack only. It does not
change the Mainnet or older Sepolia services. The public endpoint is
`https://zkapi-sepolia.openanonymity.ai/v0.3/bundler`; the web host forwards
its version-specific `_bundler` route there without application cookies.

The paymaster deployed on 2026-10-18 is
`0xDd5c8a38052E6024C970C6bd6b43D2C0e700123C`, with factory
`0x63632cdDA8caE2720B6f432996963e6c0Bab18Dd` and account implementation
`0xB2FBa4243Ed9F1219AE89845cdaBb71963C0FB38`. It serves only the existing
Sepolia vault `0x7ff4ba0662a8218d0954c1a11ae61df6c3548ea4`. Deployment
receipt `0xebbcd6229d8c0e9c4e89b629a65f6479a60f02e2067688bf90bd8e366b88b592`
and the finalized deployment audit verify compiled runtime hashes,
immutables, canonical EntryPoint v0.7/SenderCreator, policy, stakes and
funding before generating the browser/CLI pins. This deployment explicitly
selects the Glamsterdam gas schedule (`gas_schedule: 1`). The earlier
`0xe3a4893bB69b0316a0Eb2843213EabFb35120E3F` candidate is paused and its
EntryPoint deposit has been recovered; its two stakes remain locked. It is
not an accepted paymaster on the public relay.

The initial paymaster deposit is 0.004 test ETH. The factory and paymaster
each have 0.0001 test ETH staked for 86,400 seconds. The separate bundler
executor was funded with 0.002 test ETH and is reused by this deployment. There is no automatic replenishment.
The per-operation maximum sponsored cost is 0.001 test ETH, the flat fee is
zero, sponsored escapes are enabled with a minimum net payout of 0.0001
test ETH, and fee ceilings are 2 gwei maximum / 1 gwei priority. These are
bounded staging allocations, not suggested production operating balances.

## Validation boundary

The available public RPC does not support `debug_traceCall`. Alto therefore
runs with `safe-mode=false` in this **restricted staging deployment**. It
still runs EntryPoint/account/paymaster validation and bundle simulation;
`dangerous-skip-user-operation-validation` remains false. Generic ERC-7562
opcode/storage tracing is not performed. A traced bundler acceptance run
remains required before any production rollout.

`guard.mjs` allows only the pinned paymaster, optional pinned factory and
canonical v0.7 EntryPoint. The on-chain paymaster additionally authenticates
the transit account, proof, note, destination, payout and gas bounds. The
guard rejects batch RPC, state overrides, EIP-7702/legacy formats and admin
methods; limits bodies to 64 KiB and concurrent requests to four; and bounds
expensive request admission. The Glamsterdam schedule allows up to four
million gas per operation and five million per bundle while retaining the
496,000 account/paymaster verification caps and the on-chain wei cap. Alto's raw port is never exposed. Nginx adds
aggregate request limiting. Both containers disable logs to avoid retaining
addresses, proofs or operation histories.

**Use Alto API v2.** The guard explicitly forwards to `/v2/rpc`, and both
`ALTO_DEFAULT_API_VERSION=v2` and `ALTO_API_VERSION=v2` are set. Alto's legacy
v1 API skips minimum gas-price and pre-verification gas checks independently
of trace mode. Do not relax those checks to make a client operation pass.

Even with fixed contracts, invalid-proof load and state races can cost RPC
work or failed bundle gas. Included failed operations and defeated sponsored
escapes can cost the paymaster float. Monitor the paymaster status and
executor balance; investigate depletion before manually funding either.
The contract's per-key attempt limits and small operator-funded balances
bound exposure. They do not establish general public-bundler safety.

## Running the overlay

Use the existing stack's compose file, existing revision-4 overrides and
`compose.sepolia.yml` with its existing project name and `backend` network.
Create root-owned mode-0600 `bundler.env` and `bundler-guard.env` in
`ZKAPI_CONFIG_DIR`. Copy `guard.mjs` there as `bundler-guard.mjs` (readable by
UID 1000). Do not put keys in command arguments, source control or logs.

`bundler.env.example` records the non-secret configuration; add the dedicated
executor key as `ALTO_EXECUTOR_PRIVATE_KEYS`. Initial simulation-contract
deployment also needs its `ALTO_UTILITY_PRIVATE_KEY`. The utility wallet
must not be the vault owner. Keep wallet refilling disabled. The image is
pinned to the reviewed ARM64 digest used by the existing staging host.

The guard env contains `CHAIN_ID=11155111`, `PAYMASTER_ADDRESS`,
`FACTORY_ADDRESS`, `RPC_URL` and `BUNDLER_URL=http://bundler:3000`. Its startup
rejects another chain. Its loopback-only health endpoint is
`http://127.0.0.1:4338/health`. Publish only the guarded POST endpoint through
the existing revision-4 nginx gateway; keep access logging off.

Validate changes with `node --test docker/aws/bundler/guard.test.mjs`, then
check live chain/EntryPoint responses, rejection of debug/foreign-paymaster
requests and an actual zero-ETH sponsored withdrawal with a test-owned note.
Use `scripts/paymaster-status.mjs` with the finalized deployment manifest to
inspect the float, stakes and losses without inspecting user operations.
