# Local concession-exit acceptance

This process tests circuit `zkapi-v2-concession-v1` (vault revision 3) end to
end on a disposable Anvil chain, runs every scenario of the Sepolia drill
(design §10.7 Phase B) and the mainnet smoke tests of Phase C, and measures
gas.

Real components:

- the contracts, deployed by `demo/contracts/script/Deploy.s.sol` and
  finalized on chain by `scripts/expected-codehashes.mjs --finalize`,
  including the gasless-withdrawal paymaster and its transit-account
  factory, deployed in the same broadcast against the canonical ERC-4337
  EntryPoint v0.7.0;
- Groth16 proofs with the dev setup (`protocol/setup/v2-concession-dev`);
- `zkapi serverd`, as the drill build with `--adversary`;
- `zkapi db init`, `zkapi-indexerd` and `zkapi-challenged`;
- the challenge signer sidecar (`docker/aws/signer`);
- three clients:
  - the browser SDK (`sdk/`: `zkapiClient` and `browserWalletRuntime`, with
    the shipped WebAssembly running in Node);
  - the clientd companion (`zkapi-walletd`);
  - the browser wallet core run natively behind a small driver
    (`crates/zkapi-serverd/examples/v2_acceptance_wallet.rs`).

Mocked, all on loopback: the inference provider and its key management API,
the OA org that issues station keys with its verifier, and the ETH/USD price
feed. The operator's ERC-4337 bundler is the harness's mini bundler
(`scripts/acceptance/mini-bundler.mjs`), which bundles with `handleOps` from
an Anvil account. No hosted service, provider credential, public RPC or
testnet funds are needed.

## Run

Install Node 24+, Rust and Foundry (`forge` and `anvil` on PATH), then run from
the repository root:

```sh
npm run test:e2e:v2
```

The wrapper (`scripts/run-v2-acceptance.sh`) does the following:

1. Runs the harness's own unit tests (`scripts/v2-acceptance.test.mjs`).
2. Installs the signer sidecar's locked dependencies.
3. Builds the drill binaries into `target/acceptance/`, so they never replace a
   release build. These are `zkapi` with `--features zkapi-cli/adversary`, and
   `zkapi-challenged`, `zkapi-indexerd`, `zkapi-walletd` and the wallet driver
   with `zkapi-proof/dev-setup` (release builds refuse the dev setup).
4. Builds both Forge projects.
5. Runs `scripts/v2-acceptance.mjs`.

It takes about fifteen minutes after the builds. CI runs the same wrapper in the
`lifecycle-acceptance` job. Dependency installation and the builds may
contact package registries; the scenarios use only loopback endpoints.

Each run saves a private, timestamped directory under `.zkapi/acceptance/`. It
holds:

- `result.json`: the outcome, the source commit, whether the tree is dirty, a
  hash of the tracked diff, and the hashes of the tested binaries, keys and
  WebAssembly;
- `scenarios.json`: each scenario's PASS or FAIL with its evidence;
- `gas.json`;
- `paymaster-status.json`, the operator's report
  (`scripts/paymaster-status.mjs`) at the end of the run;
- the deployment manifests, every service log and the server database.

Override the parent directory with
`npm run test:e2e:v2 -- --output-dir /path/to/results`. After a build, iterate
with:

```sh
node scripts/v2-acceptance.mjs --bin-dir target/acceptance/release [--stop-after STEP]
```

`--help` lists the steps. A successful exit and the run's JSON are the
acceptance evidence.

Each run generates fresh operator signing seeds. They reach only the
environment of `zkapi signing-keys` and `zkapi serverd`, and the run fails if
any saved file contains one.

## Chain and time

Anvil runs with Sepolia's chain ID, 11155111, because the signer sidecar signs
only for mainnet or Sepolia. `Deploy.s.sol` therefore treats it as a public
chain. It requires `OWNER`, `TREASURY`, `SETUP_MANIFEST`,
`MAX_PAUSE_DURATION_SECONDS` and `ALLOW_DEV_SETUP=1`, and it records
`allowDevSetup: true`, exactly as for the Sepolia drill vault.

Before the deployment the harness etches the canonical EntryPoint v0.7.0
(`0x0000000071727De22E5E9d8BAf0edAc6f37da032`) and its SenderCreator
(`0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C`) with `anvil_setCode` from the
pinned runtimes in `protocol/contracts/test/fixtures/`, and checks the
keccak256 of each `eth_getCode` against the pins, as a public chain would
serve them. Because the chain ID is a public one, the paymaster's stakes and
float are passed explicitly: `PAYMASTER_STAKE_WEI` and `FACTORY_STAKE_WEI`
0.1 ETH each, `PAYMASTER_DEPOSIT_WEI` 1 ETH, and `PAYMASTER_ESCAPES=1`, so the
drill sponsors escape initiations (every published profile keeps them off).
The other policy values are the script's defaults. Finalize checks the eight
code hashes, the deposit, both stakes and the gas policy, and every profile
carries the `gasless` object with `bundler_url` set to the mini bundler.
serverd and the challenger read that profile and ignore the object.

`--slots-in-an-epoch 1` makes the `finalized` tag two blocks deep, and a
block is mined every second.

The drill parameters are scaled down so that a challenge period can be skipped
with `evm_increaseTime`. Both daemons' startup checks hold for them
(`drillTiming`):

| Parameter | Value |
| --- | --- |
| `challengePeriod` | 3,600 s |
| `maxPauseDuration` | 7,200 s |
| `noteTtl` | 30 days |
| Lease TTL + grace + settlement deadline (`W`) | 60 + 1 + 901 = 962 s |
| `--raise-lead-seconds` | 1,200 s |
| Request bound (`request_charge_cap`) | 50,000 gwei |
| Deposit | 1,000,000 gwei |
| One inference | 400 gwei |

A time skip moves only block time. The daemons and clients keep the wall
clock, and clients bound exit proofs by it (valid for 3 hours). The chain
therefore starts two challenge periods behind the wall clock, so that block
time meets it when the bounded pause ends. That is just before the
missed-defeat drill: the challenger counts a miss only for evidence written
(wall clock) before the escape's deadline (block time).

From then on block time runs at most one period ahead, and two at the end. An
SDK that must judge a chain deadline (to finalize) gets its device clock moved
to block time. The SDK whose operator withholds gets its clock moved to the
settlement time `T` it reports. In the late-successor drill, the last before
the expiry sweep, the SDK's device clock is set so that its released escape
proof lives 600 s of block time; then block time and the device clock both
move past that proof's `valid_until + 900`. The run records every skip.

## Scenarios

The daemons start in the production order: indexer, `zkapi db init`, signer,
challenger, serverd. The challenger and its signer are healthy before the
first deposit.

Before the scenarios, serverd must refuse to start with:

- the published development seeds;
- seeds whose keys the vault does not pin;
- no seeds;
- a profile that pins another vault codehash.

| # | Scenario (design §10.7 Phase B) | Client | What is asserted |
| --- | --- | --- | --- |
| 1 | Honest flow | wallet core | Two requests settle at the measured charge and install (S1–S6). A kind-2 ownership proof reverts `WrongWithdrawalKind` as an escape or a close. The clearance reserves the nullifier. The close proves at the deposit-time root (A1). Payout `D − 800`, treasury 800, the wallet's balance equals the payout. |
| 2 | Stale exit after spending, defeat, `SupersededState`, re-escape from an older state, defeat | wallet core | The operator serves the evidence at `S2⁺` and it verifies. The escape from `S2` is defeated through the signer with the request at `N3`. `S1` reverts `SupersededState`. `S0` is recorded and defeated with the request at `N1`. `S2` again reverts `ChallengedNullifier`. Defeats move no funds, and the newest state closes. |
| 3 | Codehash-mismatch profile refuses deposits | SDK | `deposit` fails `deployment_mismatch` on `vault_runtime_codehash`, read through the wallet and the pinned RPC. Nothing is signed. |
| 4 | Indexer down, exit with the deposit-time path | SDK | Deposit (deployment checks pass), request, settle. Another deposit moves the root, the indexer stops, and the SDK escapes (`E2.escape`, `c = 0`, path source `deposit`) at the note's deposit root, not the current one. The indexer restarts from its checkpoint. |
| 5 | Honest close (the Phase C smoke test) | SDK | Deposit, request, settle, then `withdraw('mutual')`: the SDK's own exit lock, ownership proof, clearance and close proof. `MutualClose` pays `D − 400` to the destination and 400 to the treasury, the clearance nullifier reads `usedNullifiers` and `clearance_reserved`, the record is `closed`, and the SDK holds no note and no exit lock. |
| 6 | Under-concession, raise, finalize, deferred credit, claim | wallet core | The escape concedes 100 while a request is in flight. The server settles 400, signs nothing (`exit_deferred`), and the challenger raises to 400. Finalization to a destination that needs more than 100,000 gas credits the payout (`EscapePayoutDeferred`); `claimEscapePayout`, sent by a third party, pays it. |
| 7 | Forced early exit with `c = 0`, raise to the real charge, client state closed | companion | Serverd switches to the OA org key source; the companion's OA bridge lease is verified. The operator is unreachable: `early_exit: concede_nothing` prepares `c = 0` from the deposit path (`path_source` `deposit`). The key lapses, the server settles 400, the challenger raises to 400. After finalization (9) the companion records `complete` (payout `D − 400`, `conceded_final` 400) and `has_note` is false. |
| 8 | Stale-device pre-check; honest close | companion | A copy of the companion's wallet taken at the genesis state is the stale device; the newest device spends the genesis state and its successor. A second `zkapi-walletd` on the copy refuses the escape with `device_not_newest` and holds no exit lock and no escape record: nothing left it. The newest device then closes through its mutual route (kind 2, clearance, kind 1); the close pays `D − 800`, and `/oa/v1/withdraw/confirm` records it. |
| 9 | Pause with an escape pending, then finalize | all three | Escapes 4, 6 and 7 are pending when the owner pauses. A new escape reverts `Paused`. Finalization, the deferred credit and the claim all run while paused. The SDK record is `closed` with `concededFinal` 0, the companion holds no note, and the wallet core holds the state it escaped. |
| 10 | Pause past `maxPauseDuration`, then escape; re-pause cooldown; replay of an abandoned proof after `valid_until` | wallet core | Past `pausedAt + maxPauseDuration` a fresh escape lands while still paused. A proof prepared earlier and abandoned now reverts `ProofExpired` for anyone. After `unpause`, `pause` reverts `PauseCooldown`. |
| 11–13 | Born-spent anchor 1, reused anchor, random anchor | wallet core | The drill server signs the bad successor. The wallet refuses it (S4, archived `invalid_successor`, state unchanged). In a scratch copy installed without the checks, the wallet core refuses to prove from it, and the request circuit synthesized for it is unsatisfied (Q6a; anchor 1 names the genesis nullifier). A successor refused for S4 is handled like a withheld one (E3): the owner exits before `T` conceding 0, and the challenger raises to the settled 400. The wallet core has no exit rules of its own, so the harness applies them; 15 has the SDK decide. |
| 14 | Overcharge | wallet core | The successor charges `bound + 1`; the wallet refuses it (S3). The response passes S1, S2, S4 and S6, so the escape concedes `min(charge, bound)`, the bound, at once (E3, lost ε), and no raise exceeds it. |
| 15 | Random anchor, through the SDK | SDK | The SDK archives the successor `invalid_successor`; its balance is unchanged. A mutual withdrawal waits (`request_settlement_pending`). The SDK's early escape decides `E3.forced` conceding 0, to a destination that needs more than 100,000 gas to receive; the challenger raises to 400. At finalization (21) the payout is credited and the SDK's own `claimEscapePayout` delivers it. |
| 16 | Lying `expired_unaccepted` | SDK | The operator reserves the lease, keeps and spends the key, and answers `native_quote_expired`; `/expire` lies. The SDK archives `discarded_expired_unaccepted`. The mutual close's clearance reveals the reservation, so the SDK waits (`request_settlement_pending`). The forced escape concedes 0, the server settles 400 (`exit_deferred`), and the challenger raises to 400. |
| 17 | Withholding, then concession at `T` | SDK | The server settles and never signs. The state's bound is the SDK request's, 400,000 gwei (its $1 limit at the mock price). Before `T` a withdrawal waits. At `T` (device clock) it decides `E3.T` and concedes exactly that bound. The challenger finds the concession covers the settled 400 and sends nothing; there is no defeat. Payout `B − b`. |
| 18 | Indexer down, then rebuild from logs | SDK | The SDK loses its deposit-time path, a later deposit moves the root, and the indexer stops. The escape (`E2.escape`, path source `rebuild`) proves at the current root, rebuilt from the vault's logs through the wallet provider. |
| 19 | `hang` | SDK | After a served request, serverd restarts with `--adversary hang`, behind a gateway that relays without timeouts. The SDK's escape (`E3.forced`, `c = 0`) lands within its exit budget (each operator call 20 s, each recovery pass 120 s) and before `must_initiate_by`. The operator comes back, settles 400, and the challenger raises to it. |
| 20 | Missed defeat (challenger stopped), then `retireClosedLeaf` | wallet core | With the challenger stopped, an escape from the genesis state, whose successor's request is in the evidence, finalizes. The restarted challenger counts the miss for that note (`last_missed.note_id`, `kind` defeat), logs `MISSED escape deadline` for it, and retires the leaf through the signer (`ClosedLeafRetired`, new root, retirement budget 1). The note's leaf is gone from the current root. |
| 21 | Finalize every pending escape | all | Each payout is `B − c_final`, each treasury share `D − payout`. Escapes 17–20 were never defeated. Each SDK record is `closed` with `concededFinal = B − payout` and no payout alert; the SDK claims its credited payout (15). Each wallet core escape is the one it proved: the finalized nullifier is the wallet's, from the state it holds (from its `S0` snapshot for 20). |
| 22 | Late successor, then switch | SDK | The operator's successor reaches the SDK only after it released an escape proof (`E3.forced`, `c = 0`), which the owner rejects in the wallet: nothing is broadcast. The successor is archived `late_successor` and does not install, and a cancel keeps the lock while the proof can land. Once block time and the device clock pass `valid_until + 900`, E6 releases the lock and installs the successor (bound reset), and the owner closes from that newer state: `MutualClose` pays `D − 400`, and no escape of the note ever lands. |
| 23 | Expiry sweep; pause after the cooldown | — | `claimExpired` after `effectiveExpiry` pays the treasury `D`. `pause` succeeds after `PAUSE_COOLDOWN`. At the end the vault holds nothing and owes no treasury arrears. |

Rows 24 to 31 are gasless withdrawals (ERC-4337, `fees: 'payout'`). A
withdrawal proof names a transit account `S` derived from (owner, payee). A
user operation from `S` makes the vault call, the paymaster sponsors it, and
the payout less the measured charge reaches the payee, which holds no ETH.
The SDK's connected account owns its transit accounts. For zkapi-clientd the
harness generates an ephemeral owner key per withdrawal, and the companion
proves the escape. The harness then builds, signs and sends clientd-shaped
operations: the ephemeral owner key, the profile's default gas limits and an
EIP-191 signature over the operation hash. Its preVerificationGas (21,000 +
16 per byte + 10,000, clamped) and its tip (`eth_maxPriorityFeePerGas`, capped
at `priorityFeeCeiling`) are simplified, so the bytes differ from what
zkapi-clientd would sign (it takes the largest of three preVerificationGas
estimates and a low-percentile `eth_feeHistory` tip). A refusal caused by the
Go client's own preVerificationGas or tip choice would not show here; its unit
tests cover those rules.

| # | Scenario | Client | What is asserted |
| --- | --- | --- | --- |
| 24 | Gasless close to a payout address with no ETH | SDK | Deposit, request and settle, then `withdraw('mutual', { fees: 'payout', destination })`. `gaslessAvailability` and `gaslessWithdrawalQuote` each report a `transitAccount` equal to `factory.getAddress` on `S`, which has no code yet. The wallet sends no transaction; it signs exactly once (`personal_sign`), over the operation hash. The bundle creates `S` (`AccountDeployed`). `MutualClose` pays `S`, and `Settled` shows `received` = P, `owedPaid` 0 and `paidOut = P − charged`, which is the payee's balance change and at least the quoted minimum. `charged − actualGasCost` is at most `MARGIN_GAS` at the operation's gas price. The float after is at least the float before, and `S` holds nothing. The record is `closed`; there is no note and no exit lock. |
| 25 | Gasless escape as zkapi-clientd, raised, then finalized | harness as clientd + companion | The companion proves an early escape (`c = 0`) to `S` while the operator is down. The sponsored initiation creates `S` and records `owed[S]` = the initiation's charge (`EscapeInitiationOwed`, `Settled.received` 0, `escapeSponsored`). The float advances exactly `actualGasCost`. The challenger raises to the settled 400. Row 29 shows the finalization. |
| 26 | Bundler outages | SDK | (a) The bundler answers the pre-flight but not `eth_sendUserOperation`: `bundler_unavailable` after the proof, with `fallbacks: ['self_bundle', 'direct_call']`, and the plan stays bound to `S`. `selfBundle: true` sends `handleOps` from the funded wallet, with no initCode. The wallet's balance change is `actualGasCost − its transaction fee`: the beneficiary refund. (b) `drop()`: the mempool loses the operation and refuses its identical bytes as underpriced. The SDK signs it again with both fees raised by 12.5% and journals both hashes. (c) `forgetReceipts()`: the bundler answers every receipt with null, and the inclusion is found in the EntryPoint's logs. |
| 27 | Griefing bundle | SDK | The bundler holds the sponsored close and bundles it after a self-funded account's operation that replays its public calldata on the vault. The replay closes the note and pays `S`. The sponsored operation has `success = false` with `UserOperationRevertReason` = `VaultCallFailed(NoteNotActive)`, `SponsorshipFailed` and `Stranded(S)`. The float pays exactly `actualGasCost`, which is at most `maxCost`, at a tip within `priorityFeeCeiling`. One attempt is counted. `collectTransitBalance` (FORWARD) pays the payee the stranded payout less its charge, and the evidence is consumed. |
| 28 | Replay before inclusion | SDK | While the operation waits in the mempool, a third party sends the public close calldata to the vault directly. The bundle then fails on-chain validation: the same `handleOps` replayed with `eth_call` at its block answers `FailedOpWithRevert` `AA33` with the paymaster's `NoteNotActive`. Design §5.4 expected this replay to leave the operation executing with `success == false` and a FORWARD to recover it. The paymaster re-checks the note during validation, so a replay that lands before the bundle fails validation instead, nothing is sponsored or stranded, and the recovery is the wallet-paid sweep below rather than a FORWARD. Row 27 covers the `success == false` path. The bundler pays its transaction, and the float, the key's attempts (0 before and after) and `stranded` do not move. The SDK's `withdraw` refuses with `note_not_active` and records the payout waiting in `S`. `collectTransitBalance` is refused (`transit_not_stranded`), and `sweepTransit` (`createAccount`, then `S.sweep()`: exactly two wallet transactions, in that order) delivers all of it (`Collected`). |
| 29 | Pause | SDK, harness as clientd | While the vault is paused, `gaslessAvailability` and `withdraw(…, { fees: 'payout' })` refuse with `exits_paused` and the reopen time, before any proof or signature. Row 25's sponsored FINALIZE lands while paused: `Settled.owedPaid = owed[S]`, no `Shortfall` (`shortfallWei` stays 0 and the evidence records it), and the payee receives `B − c_final − owed − charge`. Design §5.4 asked for a sponsored finalize on the `Shortfall` path. The drill cannot reach it: a 400-gwei raise against a 50,000,000-gwei escape leaves `B − c_final` (about 0.05 ETH) far above `owed + charge` (about 0.0017 ETH), so the paymaster's `got < due` branch never runs. The `Shortfall` settlement is covered only by the Forge suite (`protocol/contracts/test/gasless/PostOp.t.sol`). The companion records the escape `complete`, with `conceded_final` 400. Past `maxPauseDuration` with the vault still paused (row 10), sponsored exits stay refused: `gaslessAvailability` still answers `exits_paused`, with a `reopenAt` already past, and the wallet path's escape lands. After `unpause`, a sponsored close of the SDK's second balance succeeds. Design §5.4 expected sponsored closes to resume once `maxPauseDuration` ends; the paymaster refuses them whenever the vault is paused (validation cannot read the clock), so the harness asserts that window as it is and the resumption after `unpause`. |
| 30 | Third-party finalization of a sponsored escape | SDK | The SDK's sponsored escape records its debt. While paused, a third party finalizes it into `S`. `finalizeEscape(recordId)` then goes straight to a FORWARD: every bundler send from `S` during the call is kind 4, `S` never sent a sponsored FINALIZE, and the wallet sends no transaction and pays nothing. The FORWARD's `Settled.owedPaid` is the debt and its payee receives `B − owed − charge`. `owed[S]` ends at 0. |
| 31 | Post-prepare fallback | SDK | The bundler stops accepting sends after the proof: `bundler_unavailable`. `withdraw(…, { fees: 'wallet' })` sends the prepared plan's vault call from the wallet, with destination `S` (the clearance is pinned to `S`). `sweepTransit` creates `S` and sweeps it: two wallet transactions, `Collected`, and the payee receives the whole payout. |

The gasless rows run, in this order and under these `--stop-after` names,
between row 8 and row 9: 24 `gasless-close`, 26 `gasless-bundler`, 27
`gasless-griefing`, 28 `gasless-replay`, 31 `gasless-fallback`, 25
`gasless-escape` and 30 `gasless-sdk-escape` (each initiation). Then come 29
and 30's finalizations (`gasless-pause`) after row 9, and the close after the
pause (`gasless-reopen`) after row 10.

At the end of the run, `paymaster-status.mjs` reports no open debt, no
stranded transit account, no EntryPoint alarm (`PostOpRevertReason`,
`UserOperationPrefundTooLow`) and nothing in the paymaster beyond its
credits.

Each client escaped at least once: the SDK (4, 15–19, 30), the companion (7,
25) and the wallet core (2, 6, 10–14, 20). The SDK (5, 22, 24, 26–28, 31), the
companion (8) and the wallet core (1, 2) each closed cooperatively.

`gas.json` holds every transaction's `gasUsed` by operation:

- deposit, escape, defeat and raise;
- mutual close, finalize (paid or deferred) and `claimEscapePayout`;
- `retireClosedLeaf`, `claimExpired`, pause and unpause;
- the reverted `SupersededState`, `ProofExpired` and ownership-proof calls;
- the gasless bundles: `gasless_close_first` (with `S`'s creation),
  `gasless_close_repeat`, `gasless_escape`, `gasless_finalize`,
  `gasless_forward`, `gasless_self_bundle` and `gasless_griefing_bundle`.
  Every one that emitted `Settled` (all but the griefing bundle, whose
  operation failed) carries its operation's `actual_gas_cost`, `gas_price`
  and `charged`, checked within `MARGIN_GAS`; `gasless_escape` adds
  `owed_wei` (equal to `charged`) and `gasless_self_bundle` adds
  `refund_wei`. The wallet-paid `gasless_create_account` and `gasless_sweep`
  carry `gasUsed` only.

A bundle's `gasUsed` includes the paymaster's validation, which re-verifies
the Groth16 proof, so a sponsored close costs more gas than a wallet-paid
`mutual_close`.

It also carries the committed Forge snapshot (`protocol/contracts/snapshots/concession-exit-gas.json`) for comparison.

## Coverage boundary

| Component | Execution |
| --- | --- |
| Vault, adapter, Poseidon library | Actual contracts from `Deploy.s.sol` on Anvil, finalized and codehash-checked |
| Proofs | Actual Groth16 proofs of the single-party dev setup (drill vault only; not the ceremony keys) |
| Server | Actual `zkapi serverd` drill build: honest, `withhold`, `born-spent`, `reuse-anchor`, `random-anchor`, `overcharge` and `lie-expired`, restarted between modes behind one loopback endpoint |
| Indexer | Actual `zkapi-indexerd`, stopped and restarted from its checkpoint |
| Challenger and signer | Actual `zkapi-challenged` and signer sidecar: defeats, raises and retire-on-miss, EIP-1559 fees within the caps |
| SDK | Actual `sdk/` code and WebAssembly in Node. A browser's IndexedDB, Web Worker, window and wallet extension are substituted (in-memory store, in-thread worker, an EIP-1193 wallet over an Anvil account) |
| Companion | Actual `zkapi-walletd` routes as `zkapi-clientd` calls them; the harness plays clientd and signs its transactions |
| Gasless contracts | The canonical EntryPoint v0.7.0 and SenderCreator runtimes, etched and codehash-checked. The paymaster, its factory and the account logic come from the same `Deploy.s.sol` broadcast, finalized and codehash-checked |
| Bundler | In-process mini bundler (`scripts/acceptance/mini-bundler.mjs`). It checks each operation's shape and hash (local and the EntryPoint's `getUserOpHash`), dry-runs `handleOps` with `eth_call` and returns its `FailedOp` as the JSON-RPC error, then bundles with `handleOps` from an Anvil account. Drill knobs: hold, drop, defer, two-operation bundles, forgotten receipts |
| zkapi-clientd's gasless path | The harness plays it: an ephemeral owner key, the profile's pinned gas fields, an EIP-191 signature and the bundler's JSON-RPC. The companion proves |
| Provider, OA org, price feed | Loopback mocks |

The run does not establish:

- the ceremony setup;
- the Go clientd's signing path, gasless implementation and UI (its own test suite covers them);
- a real browser's storage, locks and tabs;
- reorganizations (the indexer's `poller::reorg_tests`);
- a pending bid replaced in a node's pool;
- a real ERC-4337 bundler: the ERC-7562 validation rules, reputation and
  bans (GREP-040), and a public mempool. The mini bundler simulates nothing
  beyond the dry run. The opcode and storage audit of the paymaster's
  validation is the Forge suite's
  (`protocol/contracts/test/gasless/Validation.t.sol` `test_opcodeAudit_*`,
  and `RealAdapter.t.sol` with the real adapter). A real bundler's tracer run
  against this harness is a release gate
  ([migration runbook](migration-concession-vault.md));
- public-network finality and real operator and RPC latency;
- live Sepolia.

The wallet core has no exit rules (E0–E7): where it escapes, the harness
applies them, and the SDK or companion scenario of the same drill shows the
client deciding. The companion's endpoints are on loopback; the run shows that
every one of its connections passed its authenticated proxy (the operator,
indexer and RPC entrances answer only relayed requests), not that a remote
endpoint is reached only that way.

Those need their own runs, and the result keeps the mocked-provider label.
