# Native ETH deployment

The source supports native ETH vaults of circuit `zkapi-v2-concession-v1`
(vault revision 3). The committed keys are the single-party development setup
`dev`, which release builds refuse; production keys come from the multi-party
ceremony in [the ceremony setup](../protocol/setup/v2-concession/README.md),
which has not run yet. Publishing code does not establish an independent
audit or setup ceremony.

Configure the exact circuit artifacts, contract, code-hash and signing-key
pins, oracle feed, and denomination for the vault. Preserve persistent
operator state and keep wallet journals bound to their configuration. A
deployment of the legacy circuit `zkapi-v2-note-bound-v1` keeps running from
the release line `release/v2-note-bound`; moving its users to a revision-3
vault is described in
[the concession-vault migration runbook](migration-concession-vault.md).

## Build services

```sh
cargo build --release --workspace
```

`zkapi serverd` requires `--native-billing-rpc-url` and
`--native-price-feed-address` (or corresponding `ZKAPI_NATIVE_*` variables), plus
an OA org/service credential or direct OpenRouter management credential.
Supply chain ID, vault, gwei request cap, both signing seeds (required; see
below), the deployment manifest (`--deployment`), database path, indexer URL
and the exact proof directory. Run
`zkapi serverd --help` for flags. `--native-price-feed-decimals` (default 8) and
`--native-price-max-age-seconds` (default 4500) must equal the published
manifest. Native prices come from the pinned finalized oracle round; a generic
RPC/chain or USD token configuration is not interchangeable with these pins.

For a private Sepolia test, configure `ZKAPI_TESTNET_PASSWORD` only in the
Sepolia server's secret environment. The built-in gate requires that password
for every service API call while leaving health and protocol metadata public.
See [Sepolia shared password](testnet-auth.md) for client behavior, proxy header
forwarding, validation and rotation. Never put this value in the public SDK
manifest or configure it on Mainnet.

## Signing keys

The state and clearance signing seeds are required, with no default:
`ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` (or `--state-seed` and
`--clear-seed`, which are visible in the process list; prefer the environment).
An empty value counts as missing, and an explicitly empty flag does not fall
back to the environment. A seed is a hex field element. Generate each with:

```sh
printf '0x%s\n' "$(openssl rand -hex 31)"
```

`zkapi signing-keys` and `zkapi serverd` refuse:

- zero and any multiple of the Baby-JubJub subgroup order;
- any seed whose public key is a published development key, in either role and
  any spelling (`0x1`, `1`, `0X1`, `0x0001`, `1` plus a multiple of the subgroup
  order, and the swapped pair);
- a secret within 2^128 of zero or of the subgroup order, which includes every
  seed of 16 bytes or fewer;
- one key for both roles.

The development keys, derived from seeds `0x1` (state) and `0x2` (clearance),
are public and must never be pinned in a vault:

| Role | x | y |
| --- | --- | --- |
| state | `0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32` | `0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f` |
| clearance | `0x1812b84c2101217b0939a2f542535075eeaa81d07dab701a899a55db26e85be4` | `0x0be80d0f61a801533a94a03b12683474f86ca012941db1c568c53dc877b16fd6` |

Compare keys as numbers (for example with `cast to-dec`): `/v1/attestation` and
`zkapi signing-keys` omit leading zeros, while `cast call` prints 32 bytes.

With the seeds in the environment, `zkapi signing-keys` prints only the public
keys, `{"clearance_signing_key":{"x","y"},"state_signing_key":{"x","y"}}`, for
the vault constructor. The vault's keys are immutable: new keys need a new
vault.

Before `zkapi serverd` opens its database for writes, it checks that
`--native-billing-rpc-url` serves `--chain-id` (the CLI default is 1, so Sepolia
must pass 11155111), reads the vault's `stateSigningKeyX/Y()`,
`clearanceSigningKeyX/Y()` and `challengePeriod()` at `latest`, and refuses to
start unless both derived keys equal the vault's. There is no override. An
unreachable RPC is retried for about 15 seconds of backoff, each call waiting up
to 15 seconds, before the process exits. The verified result is recorded in the
database's `deployment_binding` row. Later restarts with the same database,
chain, vault and seeds start without the RPC and re-verify in the background,
stopping only when the vault definitively contradicts the record. A database
bound to another chain or vault is refused, so each deployment needs its own
database, indexer checkpoint and challenge checkpoint. `zkapi-challenged`
requires the row and refuses a database bound elsewhere. The RPC must allow
`eth_chainId` and the `eth_call` selectors listed in
[the Docker guide](../docker/aws/README.md#signing-seeds). After startup, compare
`GET /v1/attestation` with the vault's getters; the log line
`server signing keys match the vault's immutable keys` confirms the check.

If a deployment ever ran with the development keys, or with keys different from
its vault's, treat it as compromised and follow
[the compromise procedure](migration-concession-vault.md#if-development-or-mismatched-keys-were-ever-served).

## Contracts

`demo/contracts/script/Deploy.s.sol` links (or deploys) the `Bn254Poseidon`
library, deploys the circuit's Groth16 adapter and the native-only vault with
its 11 constructor arguments, and checks the adapter's circuit and
verifying-key hashes against the setup manifest and the vault's getters
against the inputs. Unless `GASLESS=0`, the same broadcast then deploys the
gasless-withdrawal paymaster against the canonical ERC-4337 EntryPoint
v0.7.0, stakes it and its transit-account factory, funds its deposit and
checks its getters ([below](#gasless-withdrawals)). Its header lists the
environment it reads, and `demo/contracts/foundry.toml` notes how to run it
with `forge script`. The script links the library itself; no
`FOUNDRY_REMAPPINGS` override is needed.

| Variable | Meaning |
| --- | --- |
| `PRIVATE_KEY` | Pays for the deployment |
| `OWNER` | Vault owner; required except on local chains (31337, 1337), where it defaults to the deployer. Use a multisig or timelock; the script warns on Mainnet when it has no code |
| `TREASURY` | Payout address of spent balances and expired deposits; required off local chains |
| `OUTPUT_PATH` | Absolute path of the final deployment manifest; the script writes `$OUTPUT_PATH.pending` |
| `STATE_SIGNING_KEY_X/Y`, `CLEARANCE_SIGNING_KEY_X/Y` | The public keys `zkapi signing-keys` prints; points of Baby-JubJub's prime-order subgroup, distinct, and off local chains not the published development keys |
| `CHALLENGE_PERIOD_SECONDS` | Escape window; default 24 hours. Immutable; it bounds the challenger's whole response time. Plan 172,800 on Mainnet and 43,200 on Sepolia |
| `NOTE_TTL_SECONDS` | Note lifetime; default 30 days |
| `MAX_PAUSE_DURATION_SECONDS` | Longest a pause blocks escapes and closes; at least twice the challenge period. Required except on local chains (default 7 days). Plan 3,888,000 (45 days) on Mainnet |
| `REQUEST_CHARGE_CAP` | Per-request gwei limit; the script default is 1,000,000, the published deployments use 50,000, so pass it explicitly |
| `SETUP_MANIFEST` | The setup's `manifest.json`; the adapter's hashes must match it. Required except on local chains (default `protocol/setup/v2-concession-dev`) |
| `ALLOW_DEV_SETUP` | `1` deploys a `dev` or `rehearsal` setup off local chains, Mainnet included ([Single-party setup](#single-party-setup)). Recorded as `allowDevSetup`; default 0 |
| `POSEIDON_ADDRESS` | An already deployed `Bn254Poseidon` to link; its runtime code hash must equal the compiled library's. Unset deploys a fresh library |
| `CHAIN_ID` | Optional expected chain ID; a mismatch aborts |
| `GASLESS` | `1` (default) deploys the gasless-withdrawal paymaster after the vault; `0` skips the block and writes `withdrawalPaymaster: null`. A `forge script` dry run without an RPC has no EntryPoint code, so it needs `GASLESS=0`. An Anvil started with a public chain ID (for example Sepolia's 11155111, as the acceptance harness does) is a public chain to the script: it needs the etched runtimes and explicit `PAYMASTER_STAKE_WEI`, `FACTORY_STAKE_WEI` and `PAYMASTER_DEPOSIT_WEI`, or `GASLESS=0` |
| `ENTRY_POINT` | The ERC-4337 EntryPoint v0.7.0; default the canonical `0x0000000071727De22E5E9d8BAf0edAc6f37da032`. Its runtime must hash to `0x8db5ff69…fc58`, and the SenderCreator at `0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C` to `0x283c9d14…a7689`; on Anvil etch both first (`cast rpc anvil_setCode` from `protocol/contracts/test/fixtures/*.runtime.hex`, as CI does) |
| `PAYMASTER_OWNER` | Owner of the paymaster (policy, fee ceilings, call caps, key release, stake and deposit withdrawals); default `OWNER`. When it is not the deployer, the script deploys the paymaster with the deployer as owner (only the owner may set the first stake), stakes and funds it, and nominates `PAYMASTER_OWNER`, which must call `acceptOwnership()` on the paymaster; the manifest records this as `paymasterOwnershipTransferPending` |
| `PAYMASTER_STAKE_WEI`, `FACTORY_STAKE_WEI` | EntryPoint stakes of the paymaster and the factory (positive, at most 2^112 - 1). Local chains default to 0.1 ether each; required off local chains. Plan 1 ether each on Mainnet and 0.1 ether on Sepolia |
| `PAYMASTER_UNSTAKE_DELAY_SECONDS` | Unstake delay of both stakes; default 86,400 |
| `PAYMASTER_DEPOSIT_WEI` | Initial EntryPoint deposit of the paymaster, the float that pays sponsored gas (positive). Local default 1 ether; required off local chains. Plan 1 ETH on Sepolia and 2 ETH on Mainnet |
| `PAYMASTER_MAX_SPONSORED_COST_WEI` | Most one sponsored operation may cost the float; default 0.05 ether, at most 0.25 ether |
| `PAYMASTER_FLAT_FEE_WEI` | Flat fee kept per sponsored operation; default 0, at most 0.001 ether |
| `PAYMASTER_MIN_ESCAPE_NET_WEI` | Least net payout a sponsored escape must leave; default 0.01 ether, at most 2^64 - 1 |
| `PAYMASTER_ESCAPES` | `1` sponsors escape initiations; default `0` (finalizations are always sponsored) |
| `PAYMASTER_MAX_FEE_CEILING_WEI`, `PAYMASTER_PRIORITY_FEE_CEILING_WEI` | Fee ceilings per gas the paymaster accepts; defaults 100 gwei and 3 gwei (Sepolia: 200 gwei), at most 500 gwei and 20 gwei, and the priority ceiling must not exceed the max ceiling |
| `PAYMASTER_FEE_KEEPER` | Optional key that may re-set the fee ceilings (`setFeeCeilings`) |

The setup policy is enforced by the script: off local chains (Mainnet
included) a single-party setup needs `ALLOW_DEV_SETUP=1`, and an `mpc-1` setup
must have the verifying keys of the committed
`protocol/setup/v2-concession/manifest.json`, which the ceremony commits with
its keys. Local chains accept any setup id.

```sh
cd demo/contracts
mkdir -p ../../.demo
OUTPUT_PATH="$PWD/../../.demo/deployment.json" \
  forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast   # plus the variables above
cd ../..
node scripts/expected-codehashes.mjs --deployment .demo/deployment.json.pending \
  --rpc "$RPC_URL" --finalize .demo/deployment.json --confirmations 64
```

The script runs locally before it sends anything, so `$OUTPUT_PATH.pending`
describes the simulated deployment: `deploymentStatus` `"pending"` (or
`"simulated"` without `--broadcast`), the linked addresses, the runtime code
hashes (the vault's three, and with the paymaster five more) and
`deployBlockLowerBound`, the chain head the simulation ran on, which is not
the vault's creation block. The deployment is final only after
`expected-codehashes.mjs --finalize`, run from the repository root after
`--broadcast`: it reads the creation receipts from forge's broadcast log
(`demo/contracts/broadcast/Deploy.s.sol/<chain>/run-latest.json`, or
`--broadcast-log FILE`), requires each creation to have succeeded at the
manifest's address, every runtime code hash on chain to be the expected one
(the vault's three, and the paymaster deployment's five more), the vault's
owner and treasury to be the manifest's and, with the paymaster, its deposit,
stakes, policy and owner too, and only then writes `$OUTPUT_PATH` with
`deploymentStatus: "deployed"`, `deployBlock` (the block that created the
vault) and `deployTransactions`. A mismatch exits 1 and any other failure 2,
and neither writes the output. Finalize after finality, for example
`--confirmations 64` on Sepolia and Mainnet (the default is 1), and keep the
broadcast log until then. Re-audit a deployment later with
`node scripts/expected-codehashes.mjs --deployment .demo/deployment.json --check --rpc "$RPC_URL"`,
which compares the code hashes only.

Every profile, the server stack's `deployment.json`, the SDK and clientd
profiles, takes its pins and `deploy_block` from the finalized manifest only,
never from `.pending` or `deployBlockLowerBound`; serverd, `zkapi db init`, the
companion, the SDK build and clientd refuse a `pending` or `simulated` status.
`node scripts/deployment-profile.mjs --finalized "$OUTPUT_PATH" ...` writes
each of them: the snake_case `trusted_deployment` form (`--format trusted`, the
default), the SDK config (`--format sdk`) and clientd's packaged profile under
its own field names (`--format clientd`). It checks the setup directory's
verifying keys against the manifest, refuses a legacy `deployment_id`, and
writes the signing-key coordinates, decimal strings in the manifest, as the
`0x` hex every consumer parses; `--bundler-url URL` names the operator's
bundler in the profiles' `gasless` object (`https`, without credentials, query
or fragment; [below](#operating-gasless-withdrawals)). The
[migration runbook](migration-concession-vault.md#b2-production-sepolia), step
5, gives the commands.

The owner controls an emergency pause and the treasury address. Use a multisig,
ideally behind a timelock, never a single deployer key:

- `pause()` stops `deposit`, `claimExpired`, `setTreasury`, `acceptTreasury`,
  `withdrawTreasuryArrears` and `renounceOwnership` until `unpause()`, and
  `mutualClose` and `initiateEscapeWithdrawal` for at most
  `maxPauseDuration()`: from `pausedAt() + maxPauseDuration()` they reopen
  while the vault is still paused. `challengeEscapeWithdrawal`,
  `raiseEscapeConcession`, `finalizeEscapeWithdrawal`, `claimEscapePayout`
  and `retireClosedLeaf` stay open, so escapes in flight still resolve and
  credited escape payouts can be delivered, and `cancelTreasuryChange`,
  `transferOwnership` and `acceptOwnership` stay open. A new pause needs
  `PAUSE_COOLDOWN()` (one day) since the latest unpause (`PauseCooldown()`).
  The NatSpec of `pause()` in `ZkApiVault.sol` lists these sets. `pause()` and
  `unpause()` emit `Paused(address)` and `Unpaused(address)` and revert when
  redundant.
- Ownership transfers are two-step. `transferOwnership(address)` only sets
  `pendingOwner()` (event `OwnershipTransferStarted(previousOwner, newOwner)`).
  The new owner, for example the multisig, must then call `acceptOwnership()`
  from that address (event `OwnershipTransferred`). Until it does, `owner()` is
  unchanged and the old key keeps every power: it can re-nominate, or cancel
  with `transferOwnership(address(0))`. When rotating away from a key that may
  be compromised, never send the nomination alone through the public mempool:
  whoever holds the old key can re-nominate before the acceptance and then
  accept from its own address. Submit the nomination and the new owner's
  `acceptOwnership()` together as one private bundle, so that they land
  consecutively in the same block; for a Safe, pre-sign its `execTransaction`
  calling `acceptOwnership()` so that the bundle can carry it. After any
  transfer, check that `owner()` is the new owner and `pendingOwner()` is zero,
  and alert on any `OwnershipTransferStarted` you did not send. The `OWNER`
  passed to `Deploy.s.sol` takes effect at deployment without an acceptance
  step, so verify it before deploying. See
  [the owner key rotation runbook](migration-concession-vault.md#owner-key-rotation).
- Paused time extends every note's claim time, and after any unpause
  `claimExpired` waits at least `unpauseClaimGrace()`, the larger of
  `challengePeriod()` and one day. `effectiveExpiry(noteId)` returns the
  earliest claim time assuming no further pause; `notes(noteId)` keeps the
  nominal expiry. Inference ends at the nominal expiry regardless.
- `setTreasury(address)` only schedules a change (`TreasuryChangeScheduled`).
  `acceptTreasury()` applies it (`TreasurySet`) after `treasuryChangeDelay()`,
  the larger of `challengePeriod()` and two days, counted in unpaused time;
  `pendingTreasuryReadyAt()` is on that same clock. `cancelTreasuryChange()`
  works at any time. A treasury that rejects a payout cannot block exits: its
  share accrues to `treasuryArrears()`. Likewise an escape destination that
  rejects its payout, or needs more than 100,000 gas to receive it, cannot
  block the escape: the amount is credited to `escapePayoutCredits(destination)`
  with an `EscapePayoutDeferred` event, and anyone can deliver it with
  `claimEscapePayout(destination)`, also while paused. Alert on
  `EscapePayoutDeferred` and follow the
  [escape payout credit runbook](migration-concession-vault.md#escape-payout-credits).
  A mutual close to a destination that rejects ETH reverts, and withdrawals to
  the zero address or the vault itself revert `InvalidDestination()`.

Withdrawal proofs may use any root the vault ever held (`knownRoots`); no
withdrawal needs Merkle siblings, and an unknown root reverts `UnknownRoot()`.
An escape consumes its nullifier and its successor's; a request proof at the
successor defeats it and marks the escaped nullifier in
`challengedNullifiers`, and a request proof at the escaped nullifier raises
its concession. The legacy vaults have none of these rules; see
[owner and operator powers](../docs-site/content/docs/protocol.mdx#owner-and-operator-powers)
and the migration runbook.

Use a fresh directory when intentionally generating a new Groth16 setup.
Keep challenger coverage and persistent server/indexer state available whenever
the vault holds funds.

### Single-party setup

A vault may run on a single-party setup (`dev`) on any chain, Mainnet
included, before the ceremony keys exist. Its trust differs from a ceremony
vault's: whoever generated the setup could have kept its toxic waste and can
then forge every proof, including withdrawals of any note and defeat evidence,
so depositors trust that party with the vault's funds. Every step opts in
explicitly, and default builds still accept only the pinned `mpc-1` keys:

- **Contracts:** `ALLOW_DEV_SETUP=1` with
  `SETUP_MANIFEST=protocol/setup/v2-concession-dev/manifest.json` (absolute,
  or relative to `demo/contracts`). The script logs a warning and the manifest
  records `allowDevSetup: true`.
- **Operator image:** build with `ALLOW_DEV_SETUP=1` (see
  [the operator runbook](../docker/aws/README.md#single-party-setup)): the
  daemons get `zkapi-proof`'s `dev-setup` feature, and the daemon and gateway
  images carry `protocol/setup/v2-concession-dev`. A binary built outside
  Docker needs `--features zkapi-proof/dev-setup`.
- **Browser SDK:** `scripts/build-browser-client.sh --setup dev` and
  `node scripts/sync-sdk-assets.mjs --setup dev --network mainnet`; the SDK
  build pairs the bundle with a profile that pins setup `dev`.
- **zkapi-clientd:** `ALLOW_DEV_SETUP=1 zkapi-clientd/scripts/build-native.sh …`
  builds the companion with `dev-setup` and bundles the development setup.

`release_policy_check` still fails if any of these builds gets `dev-setup`
without being asked, through a dependency or feature unification.

### Gasless withdrawals

With `GASLESS=1` (the default) the script deploys, in the same broadcast as
the vault, `ZkApiWithdrawalPaymaster` (whose constructor deploys
`ZkApiWithdrawalAccountFactory`, whose constructor deploys the
`ZkApiWithdrawalAccount` logic every transit account delegates to). It
requires the canonical EntryPoint v0.7.0 runtime at `ENTRY_POINT` and the
SenderCreator runtime at `0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C`, both
pinned by keccak256, before it deploys anything: a public chain has them; on
Anvil etch them with `cast rpc anvil_setCode <address> "$(cat
protocol/contracts/test/fixtures/<name>.runtime.hex)"` first (the `contracts`
job in `.github/workflows/ci.yml` shows both commands); a `forge script` dry
run without an RPC has neither and needs `GASLESS=0`. The script decides
"local" by chain ID alone (31337, 1337), so an Anvil started with a public
chain ID needs the etched runtimes and explicit `PAYMASTER_STAKE_WEI`,
`FACTORY_STAKE_WEI` and `PAYMASTER_DEPOSIT_WEI` as well. The paymaster is
constructed with `PAYMASTER_OWNER` (or, when that is not the deployer, with
the deployer, which stakes it, funds it and then nominates `PAYMASTER_OWNER`
by `transferOwnership`; the nominee must `acceptOwnership()` on the
paymaster, and until it does the deployer keeps the owner's powers), the
policy and the fee ceilings from the `PAYMASTER_*` variables; the script
then calls `addStake` on the paymaster and on the factory
(`PAYMASTER_STAKE_WEI`, `FACTORY_STAKE_WEI`, both at
`PAYMASTER_UNSTAKE_DELAY_SECONDS`), `deposit` (`PAYMASTER_DEPOSIT_WEI`) and,
if set, `setFeeKeeper`.

Post-checks, before the manifest is written: the paymaster's
`ENTRY_POINT_V070_CODEHASH` is the pin above; `entryPoint()`, `vault()` and
`adapter()` are the deployed ones; `factory().paymaster()` is the paymaster
and the factory's `entryPoint()` and `vault()` are the same; the factory's
`implementation()` is its nonce-1 creation; `WEI_PER_UNIT()` equals the
vault's `nativeAssetWeiPerUnit()`, `MAX_PAUSE_DURATION()` the vault's
`maxPauseDuration()`, and `STATE_X/Y`, `CLEAR_X/Y` the vault's signing keys;
`accountCreationCodeHash()` of both contracts is `keccak256(accountCreationCode())`;
`policy()`, `maxFeeCeiling()`, `priorityFeeCeiling()` and `feeKeeper()` are
the inputs; `owner()` and `pendingOwner()` are as recorded;
`entryPoint.balanceOf(paymaster)` is at least the deposit;
`getDepositInfo(paymaster)` and `getDepositInfo(factory)` are staked with at
least the stake at the delay; and `factory.getAddress(deployer, deployer)`
equals a CREATE2 computed locally from the creation code (the derivation
every client performs).

Manifest fields of the block (every wei amount a decimal string, every gas
figure a JSON number): `entryPoint`, `entryPointRuntimeCodehash`,
`senderCreator`, `senderCreatorRuntimeCodehash`, `withdrawalPaymaster`,
`withdrawalAccountFactory`, `withdrawalAccountImplementation`,
`paymasterRuntimeCodehash`, `factoryRuntimeCodehash`,
`accountImplementationRuntimeCodehash`, `accountCreationCode` (hex, 74
bytes), `accountCreationCodeKeccak256`, `paymasterOwner`,
`paymasterOwnershipTransferPending`, `paymasterDeployer`,
`paymasterFeeKeeper` (zero when unset), `paymasterStakeWei`,
`factoryStakeWei`, `paymasterUnstakeDelaySeconds`,
`paymasterInitialDepositWei`, `paymasterPolicy { maxSponsoredCostWei,
flatFeeWei, minEscapeNetWei, escapesEnabled }`, `paymasterFeeCeilings {
maxFeeWei, priorityFeeWei }` and `paymasterGasPolicy`, the paymaster's
`gasPolicy()` with its field names (`callFloor[4]`, `callCap[4]` (the hard
caps; the live `callCap(kind)` starts there, and the owner may move it
anywhere between the kind's floor and this hard cap), `postOpFloor`, `postOpCap`, `verificationFloor`,
`verificationFloorInit`, `verificationCap`, `pvgFloor`, `pvgCap`,
`pmVerificationFloor`, `pmVerificationCap`, `postOpBaseGas`,
`postOpEscapeGas`, `postOpFinalizeExtraGas`, `postOpEscapeForwardGas`,
`eoaPushGas`, `newAccountGas`, `payoutPushGas`, `creditGas`,
`accountCallOverheadGas`, `accountCallOverheadEscapeGas`, `marginGas`,
`finalizeReserveGas`, `maxAttempts`). With `GASLESS=0` the manifest carries
`withdrawalPaymaster: null` and none of the others.

`expected-codehashes.mjs` derives the paymaster's, the factory's and the
account logic's runtime code from the artifacts with their immutables filled
from the manifest (the EntryPoint, vault, adapter, factory, unit size, keys,
pause bound and creation-code hash; the factory's paymaster and logic; the
logic's own address), and pins the EntryPoint's and SenderCreator's runtimes
as constants, so `--check` and `--rpc` cover eight code hashes. `--finalize`
additionally requires the paymaster's creation receipt (the factory and the
logic are constructor creations, checked by their code), the deposit of at
least `paymasterInitialDepositWei`, both stakes, and `gasPolicy()`,
`policy()`, the ceilings, the fee keeper and the owner (or the nominated
owner) to be the manifest's.

Profiles: `trusted_deployment` (and so `sdk/assets/config/*.json`) and the
clientd profile gain a `gasless` object: `entry_point_address`,
`entry_point_runtime_codehash`, `sender_creator_address`,
`sender_creator_runtime_codehash`, `withdrawal_paymaster_address`,
`withdrawal_paymaster_runtime_codehash`,
`withdrawal_account_factory_address`,
`withdrawal_account_factory_runtime_codehash`,
`withdrawal_account_implementation_address`,
`withdrawal_account_implementation_runtime_codehash`,
`account_creation_code`, `account_creation_code_keccak256`, `bundler_url`
(from `--bundler-url`; `null` when none is published), `gas_policy` (the
manifest's gas policy in snake_case, `call_cap` for the caps, plus the
defaults clients sign: `call_default[4]`, `postop_default`,
`verification_default`, `verification_default_init`,
`pm_verification_default`, each inside its floor and cap), `policy`
(`max_sponsored_cost_wei`, `flat_fee_wei`, `min_escape_net_wei`,
`escapes_enabled`: the deployment-time values; clients read the live ones),
`fee_ceilings` (`max_fee_wei`, `priority_fee_wei`) and
`uneconomic_fraction_percent` (25). The clientd profile also gets
`deployment_evidence.{entry_point,sender_creator,paymaster,factory,account_implementation}_runtime_keccak256`.
A deployment made with `GASLESS=0` gives `gasless: null`, as the
`not_deployed` placeholders have. `node scripts/paymaster-status.mjs
--deployment "$OUTPUT_PATH" --rpc "$RPC_URL"` prints the float, stakes,
policy, loss metrics and open debts of a finalized deployment as JSON; see
[Operating gasless withdrawals](#operating-gasless-withdrawals) for the
float, the bundler, the fee ceilings, alerts and incident levers.

## Runtime

The [Docker guide](../docker/aws/README.md) configures API, indexer, gateway,
challenger and a restricted private signer. Start them in this order: the
indexer, `zkapi db init` (which creates the database with its append-only
request evidence and binds it to the deployment manifest), the challenger,
then the API server; the challenger must be healthy before the first deposit.
The challenger needs a funded exclusive account, EIP-1559 fee caps whose bids
fit the transaction fee cap of the node behind its signer
(`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, default 1 ETH, which allows about 1,666 gwei
for a 600,000-gas defeat and about 138.9 gwei for a leaf retirement), and the
API server's database: it defeats and raises with the request evidence the
server records. Keep the API running for every challenge window; see
[challenge operation](challenge-service.md).

Every lease settles by a write-once deadline: issuance + TTL + grace +
`--openrouter-settlement-deadline-seconds` (default 21600), at worst at the
proof's solvency bound. The server refuses to start unless TTL + grace +
deadline + twice the settlement poll + 600 seconds is at most half the vault's
`challengePeriod()`, and unless TTL + grace + deadline is at most the
manifest's `settlement_window_seconds`; the challenger also checks that its
raise lead fits the challenge period. See
[settlement terminality](native-eth-billing.md#settlement-terminality).

The indexer (`zkapi-indexerd` or `zkapi indexer`) needs an RPC with EIP-1898
`eth_call` by block hash, `eth_getBlockByHash`, and state for its confirmation
depth (`--confirmations`, default 12), plus an NTP-synchronized clock
(`--max-head-age-secs`, default 180; 0 disables it for chains that mine on
demand). Use a provider other than the `rpc_url` that client manifests pin:
`zkapi-clientd` corroborates deposits and withdrawals against this indexer's
tree, and that check is only as independent as the indexer's RPC. That pinned
`rpc_url` must itself serve `eth_getBlockByHash` for recent blocks, which
`zkapi-clientd` uses to date its deposit search on chain time, and `eth_call`
for the vault's `currentRoot()`, which it reads before setting a request
aside. Pass
`--chain-id`. It serves only a view verified against the vault and
answers 503 otherwise; `--resync`, or a `<cursor>.resync` file before a restart,
rebuilds it from `--from-block`. The reference gateway limits POST requests per
source; see [request limits](../docker/aws/README.md#request-limits).

For a local chain, `npm run test:e2e:v2` runs the complete stack and the
drill scenarios on Anvil ([acceptance](v2-acceptance.md)). It runs Anvil with
Sepolia's chain ID, the only chain besides mainnet the signer sidecar signs
for. It then:

1. generates random seeds and derives the keys with `zkapi signing-keys`;
2. etches the canonical EntryPoint v0.7.0 and SenderCreator runtimes with
   `anvil_setCode` (keccak-checked), then deploys with `Deploy.s.sol`
   (`ALLOW_DEV_SETUP=1`, as for the drill vault, and the explicit
   `PAYMASTER_STAKE_WEI`, `FACTORY_STAKE_WEI` and `PAYMASTER_DEPOSIT_WEI` an
   Anvil with a public chain ID needs, with `PAYMASTER_ESCAPES=1`);
3. finalizes the manifest with `expected-codehashes.mjs --finalize`, and builds
   the `trusted_deployment` profile from it, whose `gasless.bundler_url` is the
   harness's mini bundler;
4. starts the daemons in order: the indexer
   (`--from-block deployBlock --max-head-age-secs 0`), `zkapi db init`, the
   signer sidecar, `zkapi-challenged` (`--deployment`,
   `--settlement-window-seconds`), then serverd (`--deployment`).

Its native billing RPC is a loopback mock price feed that forwards every other
read to Anvil. Use [`scripts/v2-acceptance.mjs`](../scripts/v2-acceptance.mjs)
as the reference for a local deployment. CI's contracts job also broadcasts the
demo deployment to Anvil and finalizes its manifest.

The host application packages the SDK assets for the selected network. Review
its trusted config against the finalized deployment manifest, on-chain state,
the published expected code hashes and the selected proof hashes before
enabling funding. Until a revision-3 vault exists on a network, its packaged
profile is a `not_deployed` placeholder that the SDK build refuses.

### Operating gasless withdrawals

A deployment with the paymaster (`GASLESS=1`, [above](#gasless-withdrawals))
adds a float to keep funded, a bundler to run, fee ceilings to keep current
and a few incident levers. The vault does not depend on any of them: a dead,
paused or underfunded paymaster only removes the option to pay the fee from
the payout. Wallet-paid exits and `S.sweep()` need no paymaster policy.

**Bundler.** Run an ERC-4337 v0.7 bundler (the eth-infinitism reference
bundler, Rundler or Alto) against the operator's RPC. Whitelist the paymaster
and the factory (both are staked) so the bundler exempts them from
reputation. Set `beneficiary` to a fee account, and fund the bundler's EOA
with ETH. Publish its URL in every profile with `scripts/deployment-profile.mjs
--bundler-url` (`gasless.bundler_url`). The URL must be `https` (or `http` to
`localhost` or `127.0.0.1`) with no credentials, query or fragment, a URL
both clients accept: zkapi-clientd refuses a profile `bundler_url` with a
query, fragment or credentials and then reports gasless withdrawals as
unavailable, so the generator refuses such a URL. A hosted bundler that
takes its API key in the query (`?apikey=…`) cannot be published as is; put
a proxy in front of it that adds the key. Users may set their own bundler:
`client.setBundlerUrl` in the SDK, `--bundler-url` or `zkapi.bundler_url` in
zkapi-clientd.

Public bundlers are best effort. A close's calldata is public once it is in
a mempool. If someone replays it on the vault first, the paymaster fails the
bundler's second validation, and ERC-7562 GREP-040 lets that bundler ban the
paymaster at once. Only the operator's whitelisting bundler is reliable, so it
is the supported default.

The paymaster also holds a per-key in-flight lock (`SponsorshipInFlight` in
`ZkApiWithdrawalPaymaster.sol`). It refuses, in validation, a second
sponsorship of the same key in one bundle, because the EntryPoint validates a
whole bundle before it executes any of it. A compliant bundler never bundles
two operations of one sender, so the lock fires only against a non-compliant
or malicious bundler. When it fires, the whole bundle fails on-chain
validation: the bundler pays, nothing is counted, and GREP-040 lets that
bundler ban the paymaster. Clients replace a pending operation only at the
same nonce (a fee bump), and never build a new operation for a key while an
older one may still be in a mempool. Configure the operator's bundler so
that, while an operation is pending for a (sender, nonce key), it rejects
another operation with a different nonce sequence for that key, and still
accepts a same-nonce replacement whose fees clear its replacement rule (the
SDK's 12.5% bump of both fee fields).

**Float.** Bundlers reserve each pending operation's `maxCost` against the
paymaster's deposit (ERC-7562 EREP-010), so keep `entryPoint.balanceOf(P)` at
`N × maxSponsoredCost` plus a loss buffer for `N` concurrent operations.
With the default `maxSponsoredCost` of 0.05 ETH, start Sepolia at 1 ETH
(about 20 concurrent operations) and mainnet at 2 ETH (about 40). Alert
below `10 × maxSponsoredCost` (`deposit_covers_operations` under 10 in
`paymaster-status.mjs`). Start well above that threshold: the release
gates' and drills' forced failures cost the float, and a float started at
the threshold alerts on the first of them. Anyone can top it up with
`P.deposit{value}()`.

The float replenishes itself on success: each settled operation re-deposits
its measured charge, which covers the EntryPoint's cost within
`MARGIN_GAS`. It shrinks only by failed sponsorships (`SponsorshipFailed`,
`lostWei`), shortfalls (`Shortfall`, `shortfallWei`) and open escape debt
(`owed`).

`maxSponsoredCost` also bounds the fees the paymaster sponsors. A close or
escape that creates `S` signs about 1.7 million gas of limits, and its
`maxCost` is those limits times `maxFeePerGas`. Both clients choose it by
one rule: `min(2 × base fee + tip, maxFeeCeiling)`, with the tip capped at
`priorityFeeCeiling`, refused (`gas_above_paymaster_ceiling`, before any
proof) only when `base fee + tip` exceeds `maxFeeCeiling`.
At the default 0.05 ETH, operations
are refused above a `maxFeePerGas` of about 28 gwei (`max_cost_above_policy`,
before any proof). Raise the policy toward `1.8M × maxFeeCeiling` to sponsor
up to the ceiling, and fund the float to match, within the immutable hard
cap of 0.25 ETH per operation (`setPolicy` reverts `PolicyOutOfBounds`
above it, and `Deploy.s.sol` refuses a larger
`PAYMASTER_MAX_SPONSORED_COST_WEI`). That cap stops sponsorship above a
`maxFeePerGas` of about 139 gwei (0.25 ETH / 1.8M gas) whatever the
ceiling: a ceiling above that, such as Sepolia's 200 gwei, matters only for
operations with smaller limits.

**Stakes.** Never `unlockStake` the paymaster while it sponsors. The
factory's stake only lifts the public mempool's per-factory limits for
operations that create `S`; withdraw it only with the paymaster's. The
factory's code stays deployed (it is immutable): every `S` address depends
on it, and its `createAccount` keeps working for sweeps without any stake.

**Fee ceilings.** Validation cannot read the base fee, so the ceilings
(`setFeeCeilings`, by the owner or `feeKeeper`, at most 500 and 20 gwei) are
static policy. Both clients sponsor while `base fee + tip ≤ maxFeeCeiling`
and sign `maxFeePerGas = min(2 × base fee + tip, maxFeeCeiling)`, so a
ceiling of `c` covers base fees up to `c − tip`. Above `(c − tip) / 2` an
operation is signed at the ceiling, with less than the usual doubling of
headroom over the base fee; a base fee that keeps rising before inclusion is
met by the fee bump, which raises both fields within the ceilings, and once
no raise fits, by the stop 60 seconds before the proof's `valid_until` and a
new proof. To keep users sponsored up to about 3 × the trailing 24-hour p90
base fee, set `maxFeeCeiling` to about 3 × that p90 plus
`priorityFeeCeiling`, and raise `maxSponsoredCost` to match (it refuses
first; see above). The float is exposed through spikes up to that ceiling,
and a higher ceiling widens that exposure linearly. Set
`priorityFeeCeiling` to 2–3 gwei on mainnet, at most about 0.7 × a typical
base fee: that keeps a griefing bundler's gain from tips on reverted
operations below its cost. An optional `feeKeeper` key may re-set both daily
from the exit RPC's `eth_feeHistory`; a lost keeper only freezes them, within
the hard caps. Ceilings that are too low refuse sponsorship during fee spikes
(`gas_above_paymaster_ceiling`), and users keep the wallet path. Ceilings that
are too high raise that griefing exposure linearly.

**Escapes.** `escapesEnabled` is false in every published profile
(`PAYMASTER_ESCAPES=0`). Enabling it means the float pays each sponsored
initiation (about 1.25M gas) on top of the existing challenge (about 435k
gas) when the escape is defeated, against the attacker's deposit gas (about
0.3M, recovered later): about 5:1 against the operator. Enable it on the
Sepolia drill, and decide for mainnet from the `EscapeInitiationOwed` and
`owedPaid` data. Keep `minEscapeNetWei` at least 10 × a typical initiation
plus finalization cost. While it is disabled, escapes are sponsored only at
finalization: the user starts the escape through the wallet path with
destination `S`, or through a funded helper.

**Metrics.** `node scripts/paymaster-status.mjs --deployment "$OUTPUT_PATH"
--rpc "$RPC_URL"` prints one JSON report:

- the float (`deposit_wei`, `deposit_covers_operations`) and both stakes;
- the live policy, fee ceilings, call caps, keeper and owner;
- `lost_wei`, `shortfall_wei`, `total_credits_wei` and
  `unaccounted_balance_wei`;
- the open escape debt per transit account (`open_owed`, from the events and
  checked against `owed(S)`);
- `stranded_open`: transit accounts stranded or allowed without a later
  forward or sweep, with their balances, the event that listed each
  (`evidence`: `stranded` from postOp, or `forward_allowed` from the
  owner's `allowForward`) and whether it has code yet (`has_code`);
- the operations the paymaster paid for (`user_operations`);
- the EntryPoint's alarms for its senders (`entry_point_alarms`).

Alert on:

- any `entry_point_alarms` (`PostOpRevertReason`,
  `UserOperationPrefundTooLow`): the float paid and recorded nothing, which
  must never happen;
- a nonzero `unaccounted_balance_wei`;
- `deposit_covers_operations` under 10;
- growth of `lost_wei`, `shortfall_wei` or the open debt;
- `stranded_open` entries older than a day;
- the bundler's health (`eth_supportedEntryPoints` must list the
  EntryPoint) and, on the operator's bundler, the paymaster's reputation.

**Incident levers** (owner only, unless noted):

- `setPolicy` with `sponsorshipPaused: true` stops new sponsorship within a
  block. Operations not yet included then fail validation: an operation is
  never charged, and the bundler pays for any bundle it already sent.
- `release(keys)` resets a key's attempts. Use it only after an operation was
  included and reverted: an operation the bundler held, or one that failed
  on-chain validation, never consumes an attempt.
- `allowForward(S)` lets a sponsored FORWARD collect a balance that reached
  `S` without paymaster evidence (a close replayed before any sponsored
  operation). Anyone can otherwise `sweep()` it from a funded account.
- `writeOffDebt(S)` clears a defeated escape's debt once its note has closed
  elsewhere. It changes accounting only.
- `setFeeCeilings` (owner or `feeKeeper`) moves the ceilings anywhere up to
  the immutable hard caps (500 gwei and 20 gwei), and `setCallCap` moves
  each kind's call cap between its floor and its hard cap. Lowering them
  narrows what the paymaster accepts; raising them widens the float's
  exposure (a higher `priorityFeeCeiling` raises the griefing exposure of
  the fee-ceilings paragraph). A `feeKeeper` can raise the ceilings to the
  hard caps, so protect it like a key that sets risk policy, not as a
  low-value hot key. `withdrawTo` moves float.

No lever can move a payout, a credit (`credits[payee]`, which anyone delivers
with `claimCredit(payee)`) or a transit account.

**Retirement.** In this order:

1. `setPolicy` with `escapesEnabled: false` (the published default), so
   no new escape debt is recorded. Keep the profiles' `gasless` pins
   published for now: a sponsored operation for an existing record (the
   FORWARD of `collectTransitBalance` / `--collect`, a sponsored FINALIZE,
   a new, re-sent or re-signed operation of a sponsored close or escape)
   needs the current pins to name that record's paymaster and factory, so
   sponsored recovery ends with the pins. New closes stay sponsored meanwhile; each one settles
   inside its own operation and adds no debt.
2. Keep sponsoring until `paymaster-status.mjs` shows `open_owed` and
   `stranded_open` empty. Each pending sponsored escape finalizes after its
   challenge period, sponsored by its client, or by anyone with
   `finalizeEscapeWithdrawal` from a funded account followed by the
   permissionless `S.sweep()`, which pays the payee and settles the debt.
   Collect or sweep each stranded balance the same way, and `writeOffDebt`
   a defeated escape's debt (it never settles by itself). Draining here,
   while sponsorship is still possible, lets users recover without ETH.
3. Publish profiles whose `gasless` is `null`, so no new proof binds a
   transit account of this paymaster.
4. Pause sponsorship.
5. `unlockStake` the paymaster and the factory, wait the unstake delay,
   `withdrawStake`, and `withdrawTo` the float.

What step 3 changes for the clients: `gasless: null` stops new sponsored
operations and sponsored recovery. A new sponsored withdrawal is refused
with `gasless_unavailable` (the SDK's `reason: 'not_pinned'`;
zkapi-clientd's "this deployment publishes no gasless paymaster"). A
sponsored operation for an existing record (a forward, a sponsored
finalization, a new, re-sent or re-signed operation of a sponsored close or
escape) is refused with `gasless_record_not_pinned`, as it is for a profile
that pins another paymaster than the record's; the refusal names the
wallet-paid alternatives that apply, led by the wallet-paid close or escape
initiation (`withdraw(mode, …, { fees: 'wallet' })`, `withdraw --to Y
--fees wallet` or `withdraw --escape --to Y --fees wallet`) while the
record's exit is not on chain yet. The wallet-paid recovery of an existing
record keeps working, because it uses the addresses journaled with the
record (transit account, factory, paymaster, EntryPoint, owner, payee), not
the profile's: the SDK's `sweepTransit`, `claimGaslessCredit` and
`finalizeEscape(…, { fees: 'wallet' })`, and zkapi-clientd's `withdraw
--sweep`, `--claim-credit` and `--escape --fees wallet`. Before a sweep (and
zkapi-clientd's credit claim) the clients check, through the read RPC, that
the journaled factory's `getAddress(owner, payee)` is the journaled `S`; the wallet-paid
finalization is a plain `finalizeEscapeWithdrawal` on the vault and needs no
gasless contract. These need an account with ETH for gas, which is why
step 2 drains while sponsorship still works.

An operation a client sent before step 3 and that was not included yet is
not sent again under the new profile, but it is never left without a path
forward. The client looks for its inclusion through the journaled
EntryPoint and paymaster on the read RPC (zkapi-clientd also asks the
bundler it sent the operation to for a receipt, read-only; nothing is
re-sent): an operation included, before or after step 3, settles its record
as usual, and one included but reverted is released for the wallet-paid
action. One not included five minutes
(the re-send window) after it was last sent is released, its hashes kept for
a late inclusion, and the wallet-paid action takes over: zkapi-clientd's
resume (`withdraw --to`, or `withdraw --escape --to`, without `--fees`)
releases it with `gasless_record_not_pinned` and names the next command (a
close or escape again with `--fees wallet`, `--escape --fees wallet` for a
finalization, `--sweep` for a forward); the SDK releases a close or escape
initiation in its background sync, after which `withdraw(…, { fees:
'wallet' })` proceeds, and a finalization in `finalizeEscape(…, { fees:
'wallet' })` (refused with `user_op_pending` during the window). A forward
in flight never blocks the SDK's sweep. A released operation that lands
later fails harmlessly: the note's nullifier, or the escape's finalization,
is spent once.

Pausing sponsorship refuses every kind, FINALIZE and FORWARD included
(`SponsorshipPaused` is validation's first check). A balance that appears
later (an operation in flight at step 3 that landed or was released, or an
escape left pending) is recovered by its user's client with the
wallet-paid actions above, or by hand from any funded account. For a
pending escape, after its challenge period:

```sh
cast send "$VAULT" 'finalizeEscapeWithdrawal(uint32)' "$NOTE_ID" --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
cast send "$S" 'sweep()' --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
```

For a stranded balance, only the `sweep()`, and only once `S` has code.
An `S` that `paymaster-status.mjs` lists with `evidence: "stranded"` ran a
sponsored operation, so it has code. One listed with `evidence:
"forward_allowed"` may not: `allowForward(S)` is the lever for a close
replayed before any sponsored operation, whose operation carrying `S`'s
initCode then failed validation, so `S` holds the payout with no code until
a FORWARD lands. A `sweep()` sent to an `S` with no code succeeds and does
nothing: the balance stays and the entry stays listed. Check `has_code` in
the report (or `cast code "$S" --rpc-url "$RPC_URL"`, which prints `0x` for
none), and where it is false run
`cast send "$FACTORY" 'createAccount(address,address)' "$OWNER" "$PAYEE"`
first, with the owner and payee its client holds. `sweep()` pays the payee
and settles `S`'s debt on the way.

The contracts stay deployed (immutable code): `collect` (the path of
every `sweep()`), `claimCredit` and the factory's `createAccount` work
without a deposit or a stake. A new paymaster means new transit-account
addresses for new proofs.
