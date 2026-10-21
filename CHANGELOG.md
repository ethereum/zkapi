# Changelog

All notable changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) on major version 0, so any release
may change an interface; see [docs/versioning.md](docs/versioning.md) for what
each bump means. **Breaking** lists what an operator, a host or a user has to
act on.

## [Unreleased]

Folded into 0.2.0's notes at release.

### Added

- **Gasless withdrawals (ERC-4337, EntryPoint v0.7.0).** `fees: 'payout'` in
  the SDK (`client.withdraw`, `finalizeEscape`) and `--fees payout` in
  zkapi-clientd pay the network fee from the payout through an
  operator-funded paymaster; the payout address needs no ETH. New contracts
  `ZkApiWithdrawalPaymaster`, `ZkApiWithdrawalAccountFactory` and
  `ZkApiWithdrawalAccount`, deployed with the vault by `Deploy.s.sol`; new
  deploy variables `GASLESS` and `PAYMASTER_*`; a new profile object
  `gasless` (with the operator's `bundler_url`); `scripts/paymaster-status.mjs`
  for the operator. The wallet-pays path is unchanged and remains the
  default. The local acceptance runs the gasless scenarios through a mini
  bundler ([v2 acceptance](docs/v2-acceptance.md), rows 24 to 31).
- **Single-party vaults on any chain.** `Deploy.s.sol` no longer refuses a
  `dev` or `rehearsal` setup on Mainnet: off local chains, Mainnet included,
  it needs `ALLOW_DEV_SETUP=1` as before. The operator images
  (`docker/Dockerfile`, `Dockerfile.gateway`, through `compose.yml`) and
  zkapi-clientd's `build-native.sh` take `ALLOW_DEV_SETUP=1` to build with
  `zkapi-proof/dev-setup` and ship the development setup, and the SDK build no
  longer refuses a mainnet profile on `dev` (`development_setup_on_mainnet` is
  gone). Default builds still accept only the pinned `mpc-1` keys, and
  `release_policy_check` still fails if a production build gets `dev-setup`
  without asking. A single-party vault trusts its setup's generator, who can
  forge every proof ([Single-party setup](docs/deployment.md#single-party-setup)).

### Changed

- **Network fees cut across the board (vault revision 3, circuit setup
  regenerated).** Measured with CI's pinned Forge against the previous
  revision: `deposit` ~6,000,000 gas → ~1,000,000; `mutualClose` 427,837 →
  387,321; `initiateEscapeWithdrawal` 574,544 → 495,463;
  `challengeEscapeWithdrawal` 374,881 → 359,450; `raiseEscapeConcession`
  335,128 → 319,815; `finalizeEscapeWithdrawal` 91,898 → 82,580;
  `claimExpired` 77,509 → 72,703; a Groth16 verification about 282,000
  instead of 316,000. The sponsored (gasless) shapes carry the lower
  verification twice, and the paymaster's floors follow the measurements
  (`callFloor` 540,000 / 540,000 / 250,000 / 80,000, `pmVerificationFloor`
  400,000; the profile defaults and `finalizeReserveGas` 990,000 follow). What
  changed:
  - The note tree's node hash is one Poseidon permutation of
    `(domain "zkapi.v2.node", left, right)` with the domain in the capacity
    lane (`zkapi_core::v2::compress_fields`, `Bn254Poseidon.compress`),
    instead of the sponge's two. Every root changes, the circuits lose about
    7,700 constraints each (request 23,990, withdrawal 28,772 rows; both fit
    a 2^15 QAP domain, so a 2^15 powers of tau now suffices) and proving is
    correspondingly faster; the development setup, every fixture and vector,
    the clientd Poseidon vectors and the sealed exit-kit fixture are
    regenerated.
  - `Bn254Poseidon.sol` is generated in the optimized form of the Poseidon
    reference implementation (equivalent round constants, sparse partial
    rounds), 2.6 times cheaper per permutation; `zkapi-proof`'s
    `refresh_setup_sources` example rewrites a setup's Solidity sources and
    its Poseidon manifest from its keys.
  - The vault keeps the tree's frontier (`MerkleUpdateLib.insert`) and
    appends a deposit's leaf itself: 32 compressions, no Merkle proof, and
    deposits no longer race each other (`StaleRoot` is a `retireClosedLeaf`
    revert only). `retireClosedLeaf` refreshes the one frontier entry a
    retirement can reach.
  - `Groth16ProofAdapter` skips the scalar multiplication for public inputs
    of 0, 1 and 2 (the protocol version, an exit's kind, a close's zero
    `nextNullifier` and `conceded`).
  - A pending escape is 5 storage slots instead of 7 (`Types.Escape`); the
    `pendingWithdrawals` and `pendingConcessions` getters keep their shapes.
  - The vault and the paymaster use a transient reentrancy guard
    (`ReentrancyGuardTransient`, EIP-1153), same error selector.

### Breaking
- **`deposit(bytes32 commitment, uint128 amount)`** (selector `0x56d2e1ea`)
  replaces `deposit(bytes32,uint128,uint256[32])`: the siblings argument is
  gone. The SDK (`encodeDeposit`) and zkapi-clientd send the new calldata and
  keep the deposit-time path locally for the note's exit proof; clientd ties
  a prepared deposit slot to its signed transaction by nonce
  (`signed_nonce`) rather than by the calldata's sibling words.
- **The note tree's roots change** (see Changed): proofs, paths and roots
  from any earlier deployment or fixture do not carry over, and the browser
  bundle (`sdk/wasm`) must be rebuilt with `scripts/build-browser-client.sh
  --setup dev` for the new node hash before it computes correct roots.
- **`rootRetiredAt(uint256)` is removed** from the vault (informational, never
  read on chain; `NoteDeposited` and `ClosedLeafRetired` carry every root
  change).

- None: the change is additive. Profiles without `gasless` (or with
  `gasless: null`) keep working with the wallet-pays path.

## [0.2.0] - not yet released

The concession-exit line: circuit `zkapi-v2-concession-v1`, vault revision 3,
capability `exit_concession: 1`. The release needs a new vault, adapter and
trusted setup, and none is deployed yet; the gates are in
[the migration runbook](docs/migration-concession-vault.md).

### Breaking

- **New vault, circuit and keys.** An owner's exit no longer needs the
  operator: an escape names the state it leaves and its successor, concedes an
  amount `c` of at most the state's request budget, and pays `B - c`. Only a
  request proof at the successor defeats it. Notes cannot move between
  vaults; each owner withdraws from the legacy vault and deposits into the new
  one. Design: [concession-exit](docs/design/concession-exit.md).
- **Wire formats.** `WithdrawalPublicInputsV2C` has 16 fields
  (`next_nullifier`, `conceded`, `valid_until`, withdrawal `kind`), challenge
  calldata is `0xda0ce43d` (defeat) and `0xdd0064ba` (raise), and a request
  carries the anchor chain. Request JSON keeps its schema and its keys change.
- **Services refuse the legacy vault.** serverd, indexerd and the challenger
  read the deployment manifest and refuse another circuit, setup or vault
  (`deployment_binding`). Use a new database, indexer checkpoint, challenge
  checkpoint, signer key, sender, hostname and image tag for the new stack.
- **Clearance needs an ownership proof**; serverd refuses
  `ZKAPI_ALLOW_LEGACY_CLEARANCE` on this deployment.
- **Browser SDK.** Served at `/zkapi/v2c/` next to the legacy build; refuses a
  profile of another circuit (`incompatible_proof_circuit`) or setup
  (`setup_mismatch`). Profiles are `not_deployed` placeholders until a vault
  exists.
- **zkapi-clientd** reports `bridge_version` 5. It warns about an open legacy
  wallet and names the legacy release, `0.1.7`; it never opens that wallet.
- **Version numbers.** Every shipped component now carries one version,
  `0.2.0` (the crates were `0.1.0`, the SDK and signer sidecar `0.2.0`,
  OpenAPI `2.2.0-concession`). The browser WebAssembly embeds crate versions,
  so its bytes and manifest hashes changed.

### Added

- Escape payout credits (`escapePayoutCredits`, `claimEscapePayout`),
  `raiseEscapeConcession`, an append-only tree with `retireClosedLeaf`, exits
  against any root the vault ever held (Amendment A1), a bounded pause
  (`maxPauseDuration`, a one-day cooldown), and codehash and verifying-key
  pins checked by every service and client.
- An exit kit (`zkapi-exit-kit-v1`) for the browser SDK, `--exit-rpc-url` for
  clientd, the escape routes of the companion, and `CircomReduction` proving
  with a multi-party phase-2 ceremony readiness check (`dev`, `mpc-1`).
- `VERSION`, `scripts/version.mjs` and [docs/versioning.md](docs/versioning.md).

### Fixed

The nine findings of the security review. The first two are contract defects:
the new vault fixes them, the legacy vault keeps them until it drains, and the
`0.1.x` services only mitigate them.

- A challenge to an escape burned the withdrawal nullifier.
- A pause blocked exits.
- Challenge and finalization transactions had no gas-price cap.
- The indexer could diverge from the chain.
- The signer and server accepted default signing seeds.
- Clearance did not need proof of ownership.
- Clients relied on an unpinned third-party RPC.
- A lease could be left that nothing settled.
- The wallet discarded its write-ahead journal.

## [0.1.7] - not yet released

The legacy line (`release/v2-note-bound`, circuit `zkapi-v2-note-bound-v1`),
cut from the `0.1.x` code of the deployed vaults. Maintenance only.

### Fixed

- The nine findings above, in serverd, indexerd, the challenger, the signer
  sidecar, the browser SDK and `zkapi-clientd` (commit `ac9be63`).

### Changed

- `zkapi-clientd` `0.1.7` closes deposits (`deposits_closed`), adds
  `withdraw --escape` from a fresh, settled state with its finalization and
  payout check, and ships the runbook `zkapi-clientd/docs/LEGACY_ESCAPE.md`.
- The SDK re-cut that closes deposits is the next `0.1.x` patch, a
  configuration-only change that keeps the WebAssembly bytes.

## [0.1.6] and earlier

`zkapi-clientd` `0.1.0` to `0.1.6` (tags `clientd-v0.1.0` to `clientd-v0.1.6`).
