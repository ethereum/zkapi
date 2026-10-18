# Changelog

All notable changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) on major version 0, so any release
may change an interface; see [docs/versioning.md](docs/versioning.md) for what
each bump means. **Breaking** lists what an operator, a host or a user has to
act on.

## [Unreleased]

### Sepolia staging integration

Carry the existing staging client's wallet withdrawal fee quote and confirmed
withdrawal identity checks into revision 4. Preparation and submission recheck
the displayed note and operation under the wallet lock, including after a
mutual close converts to an escape. No contract or proof artifact changes.

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
- **Activation signer and Compose services.** The signer sidecar takes
  `ZKAPI_SIGNER_PROFILE`: `challenge` (the default, the challenger's three
  calls as before) or `activation`, which signs only aligned `activateNotes`
  batches of 1, 4 or 16 notes to its vault, reads only `ZKAPI_ACTIVATION_`
  variables (`ZKAPI_ACTIVATION_MAX_GAS` 1,000,000 by default, no retirement
  settings) and refuses every other call, the challenger's and
  `activateNotesOnChain` included. A signer refuses to start while its
  environment holds a variable of the other profile's prefix
  (`ZKAPI_ACTIVATION_` for a challenge signer, `ZKAPI_CHALLENGE_` for an
  activation signer). `GET /health`, `zkapi_signerStatus` and the startup
  line report `profile` (an activation signer omits the retirement fields;
  its `zkapi_signerStatus` and startup line add the vault's `activator`, and
  its status warns `sender_not_activator` while that is not its sender, or
  `activator_unreadable` while the read fails).
  `docker/aws/compose.yml` adds, under the Compose profile `activation`, the
  services `activator` (the launcher's new `zkapi-run activator` role, which
  runs `zkapi-activated` with `deployment.env` and `activation.env`) and
  `activation-signer` (with `activation-signer.env`, from the new
  `docker/aws/activation-signer.env.example`)
  ([activation profile](docker/aws/signer/README.md#activation-profile)).
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

- **Note-bound exits and a request tree updated by proved batches (design C:
  vault revision 4, circuit `zkapi-v2-concession-v2`, every setup
  regenerated).** Measured with CI's pinned Forge against revision 3:
  `deposit` ~1,000,000 gas → 77,206 (on Anvil, in steady state: it only
  records the note); `mutualClose` 387,321 → 395,657;
  `initiateEscapeWithdrawal` 495,463 → 481,776; `retireClosedLeaf`
  1,648,719 (newly pinned; the challenger's gas limit, its estimate plus 20%,
  is about 2.0M, not the 7.2M the operator docs gave);
  `activateNotes` 275,635 (1 note), 337,933 (4 notes), 594,662 (16 notes),
  that is about 37,166 per note at 16 (end to end on Anvil, intrinsic gas
  and calldata included, about 286,100, 348,400 and 605,200);
  `activateNotesOnChain` 1,656,574 (1 note); the paymaster's floors
  `callFloor` 550,000 for a close (escape, finalization and forward
  unchanged) and `pmVerificationFloor` 410,000 (the profile defaults and
  `finalizeReserveGas`, now 1,000,000, follow). What changed:
  - A deposit only records its note (`notes(noteId)`: commitment, amount,
    expiry, status; `NoteDeposited(noteId, commitment, amount, expiryTs)`)
    and does no tree work. This replaces the frontier insertion below.
  - Every withdrawal (escape, mutual close, ownership proof) is bound to the
    note as stored: the statement's input 3 is the registration commitment
    `C` and a new input 16 the packed amount and expiry `M = amount +
    expiry * 2^128` (17 inputs). The vault compares both with `notes(noteId)`
    before it verifies the proof (`NoteBindingMismatch()`), and the circuit
    proves `H_reg(secret, 0) = C` instead of tree membership (withdrawal
    21,029 constraints). A note can exit as soon as it is recorded, and no
    exit needs a root, a Merkle path, an indexer or a log rebuild.
  - The vault keeps only the request tree's root. Recorded notes are appended
    in deposit order, as aligned batches of 1, 4 or 16, by
    `activateNotes(firstNoteId, count, expectedRoot, newRoot, proof)` with an
    insertion proof whose inputs the vault builds from its own state (three
    new verifying keys in the same adapter: 16,439, 18,941 and 31,847
    constraints), or by the permissionless no-prover
    `activateNotesOnChain(firstNoteId, count, siblings)`. New:
    `NotesActivated(firstNoteId, count, newRoot, proved)`, `activationCursor()`,
    `isActivated(noteId)`, `NOTE_BOUND_EXIT_VERSION()` (1), the errors
    `StaleActivation()`, `InvalidActivation()` and `NoteNotActivated()`.
    Activations are paused with deposits.
  - Only the vault's activator proves batches: `activateNotes` reverts
    `NotActivator()` (`0xb2df0af0`) for any other sender while the vault is
    unpaused, before any other check (the range, the root, the proof). The
    activator is the constructor's new 12th and last argument (nonzero),
    read with `activator()` (`0x4ecea992`) and replaced by the owner with
    `setActivator(address)` (`0x7c0cc0be`, open while paused); both emit
    `ActivatorChanged(previousActivator, newActivator)` (topic
    `0xbd0aa56c02389240616a23c1d092ae6238c0e2847610bc4d302628e56cfee2e4`, from
    `address(0)` at deployment). `activateNotesOnChain` stays open to anyone,
    but only from `activationFallbackOpensAt()` (`0x3a02aa08`):
    `ACTIVATION_FALLBACK_DELAY()` (`0x4c81d3cd`, 1 hour) after the latest
    proved activation, the deployment or the latest unpause. Before then it
    reverts `ActivationFallbackClosed()` (`0x67df368d`), checked first;
    on-chain activations do not move the opening. Why: batches must be
    aligned and the insertion proving keys are public, so anyone could land
    a proved singleton (about 276,000 gas) just ahead of the worker's batch
    of 16 and force more than 1.2M gas of smaller, realigning batches on the
    operator, and an early `activateNotesOnChain` (about 1.66M) would do
    the same. Funds are never at risk: exits do not depend on activation.
    If the worker stops, anyone can activate an hour after its last proved
    batch. Gas, against the same vault without these rules: a proved
    activation reads the activator and writes `activationFallbackOpensAt`
    in the same slot, 5,232 gas more; an on-chain activation 2,133 more
    for its check; an escape's initiation, defeat, raise and finalization,
    an expiry claim and a retirement 88 more, and a mutual close and a
    deposit 66 more, for the larger dispatch. The runtime code is 20,940
    bytes (20,260 without them).
  - The operator runs an activation worker, the new `zkapi-activated` binary
    of zkapi-serverd, that proves the batches: the largest size the recorded
    notes fill at an aligned cursor, after a bounded wait for a fuller one
    (`--max-activation-wait-seconds`, 30 by default), sent from a dedicated
    sender with a signer of its own, the vault's activator; while it is
    not, the worker sends nothing (`not_activator`)
    ([activation worker](docs/activation-worker.md)).
    Requests are unchanged (12 inputs, the exact current root) and need an
    activated note: the SDK, the companion and zkapi-clientd report
    `note_not_activated` and show the note as activating until then.
  - serverd checks a clearance's ownership proof against the vault's
    `notes(noteId)` (status `Active`, `C`, `M`) instead of a root window; the
    challenger retires a missed-defeat note's leaf once the note is activated
    (blocked meanwhile as `awaiting_activation`, which escalates with time).
  - serverd's, the challenger's and the activation worker's startup probes
    require `NOTE_BOUND_EXIT_VERSION() == 1` instead of
    `ROOT_HISTORY_WINDOW() == 86400`; the indexer and zkapi-clientd require
    it too, with `CONCESSION_ESCAPE_VERSION() == 1`.
  - The indexer mirrors recorded notes and activations and verifies its view
    against `currentRoot()`, `nextNoteId()` and `activationCursor()`; its
    snapshot adds `activation_cursor`, `note_leaves` and `notes`, and a path
    adds `activated` and `activation_cursor`.
  - `Deploy.s.sol` checks all five verifying-key hashes of the adapter and
    the fresh vault's `NOTE_BOUND_EXIT_VERSION`, root and cursor, and an
    `mpc-1` setup must match all five ceremony keys; CI also requires
    `Bn254Poseidon.sol` to be the setup's generated copy.
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

- **Vault revision 4, circuit `zkapi-v2-concession-v2`.** New vault, adapter,
  `Bn254Poseidon` library (`compressPairPath`, `compressSubtree`; a
  revision-3 `POSEIDON_ADDRESS` cannot be linked) and keys; the
  never-deployed revision 3 does not carry over. Deployment manifests drop
  `rootHistoryWindow` and add `noteBoundExitVersion` and
  `insertion{1,4,16}VkKeccak256`; profiles say `vault_revision` 4 and pin
  `insertion{1,4,16}_vk_keccak256`. The operator image requires
  `CIRCUIT_ID=zkapi-v2-concession-v2`, and `docker/aws/compose.yml` tags
  its images `concession-v2` by default (`ZKAPI_IMAGE_TAG`, was
  `concession-v1`). Every service refuses a vault whose
  `NOTE_BOUND_EXIT_VERSION()` is not 1.
- **Exit wire and calldata.** `WithdrawalPublicInputsV2C` has 17 statement
  fields in 18 JSON keys: `registration_commitment` replaces `active_root`,
  and `deposit_amount` and `expiry` are added. `mutualClose` is
  `0x5acd3b15`, `initiateEscapeWithdrawal` `0x8e110492` and the adapter's
  `assertValidWithdrawal` `0x330fa82a`; an exit's calldata is 868 bytes (a
  sponsored `withdraw(bytes)` 964). `pendingWithdrawals` returns 5 words (no
  `activeRoot`). `NoteDeposited` loses `newRoot` (topic `0x3d5756e3…`).
  `knownRoots`, `isKnownRoot` and `ROOT_HISTORY_WINDOW` are removed, and
  neither the vault nor the paymaster raises `UnknownRoot` any more
  (`NoteBindingMismatch`, `0x41c6633b`, instead).
- **Deposits make requests only once activated.** Run the activation worker,
  `zkapi-activated`, with its own sender, signer and insertion proving keys
  (or, an hour after the last proved activation, activate with
  `activateNotesOnChain`), or no deposit ever becomes request-capable; exits
  are unaffected. With Docker, start the Compose profile `activation`
  (`activator` and `activation-signer`) with `/etc/zkapi/activation.env` and
  `/etc/zkapi/activation-signer.env`.
- **The vault's activator.** `ZkApiVault`'s constructor takes a 12th and
  last argument, the activator, and `Deploy.s.sol` a new variable
  `ACTIVATOR`, required off local chains (the deployer by default on them):
  the activation worker's sender, the address of the activation signer's
  key. The deployment manifest records it (`activator`) and
  `expected-codehashes.mjs --finalize` checks it on chain. Only the
  activator may call `activateNotes`, so run the worker with `--sender` set
  to it; the owner moves the role with `setActivator`, after which the
  manifest must name the new activator before the worker starts
  ([the activator](docs/activation-worker.md#the-activator)). Anyone else
  activates only through `activateNotesOnChain`, from
  `activationFallbackOpensAt()`.
- **No deposit paths.** Clients no longer save a deposit-time path, the
  companion's `/oa/v1/deposit/path` is removed, its deposit plan drops
  `zero_path` and `active_root`, and its confirmation ignores
  `deposit_root` and `deposit_siblings`. Exit kits stay
  `zkapi-exit-kit-v1`; `merkle_path` and `deposit_path` are optional and
  ignored.
- **serverd** drops `--clearance-root-window-seconds`
  (`ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS`): `zkapi serverd` refuses the flag
  and ignores the variable. A clearance's `stale_root` is replaced by
  `400 note_binding_mismatch` and `409 note_not_active` (refusals) and
  `409 note_not_recorded` (retriable), none of which carries `latest_root`.
- **Indexer HTTP API.** `/v1/tree/notes/{id}/zero-path` and
  `/v1/tree/roots/{root}` are removed, `/v1/tree/root` adds
  `activation_cursor`, `/v1/tree/snapshot` adds `activation_cursor`,
  `note_leaves` and `notes` (its `leaves` are the tree's: 0 until a note is
  activated), a path adds `activated` and `activation_cursor`, `/health`
  reports `activation_cursor` instead of `known_root_count`, and the
  checkpoint version changes to 4, so an indexer replays from the deployment
  block. `/v1/tree/snapshot?parts=tree` (the header and `leaves`) and
  `?parts=records` (the header, `note_leaves` and `notes`) each serve only
  part of the larger payload; without `parts` it is served whole, and any
  other value is `400 invalid_request`. The browser SDK asks for `tree` and zkapi-clientd for
  `records`, and both accept a whole snapshot from an older indexer.
- **Companion bridge 6.** The companion reports `bridge_version` 6, which
  zkapi-clientd requires (`withdrawal_bridge_version` stays 1): exit plans
  carry the 17-input statement and 868-byte calldata, deposits carry no path,
  `/wallet/status` reports `activated` and `activation_cursor` (from a
  cached reading, so status never waits on a slow RPC or indexer), a request
  for a note not activated yet is refused with `note_not_activated`, and one
  for a note the vault activated before the operator's indexer caught up
  with `503 indexer_root_lag` (retriable).
- **SDK deposit recovery.** A pending deposit whose predicted note slot
  another note took is found by its commitment wherever it was recorded, and
  is never given up while its transaction may still land; recovery no longer
  returns `slot_consumed` or `slot_conflict_unconfirmed`. An exact retry of
  a deposit whose send is unknown reuses that send's sender and nonce, so at
  most one of the two can be mined (`deposit_retry_nonce_unknown` when the
  nonce was never saved). A clearance answered `note_not_recorded` is retried
  with a bounded backoff instead of turning the exit into an escape.
- **Activation waits.** The SDK waits up to 90 s for a note's activation,
  extended while the vault's cursor advances (at most 5 minutes), and reports
  a paused vault (`vault_paused`, `exits_reopen_at`) instead of waiting for an
  activation that cannot happen. zkapi-clientd saves a deposit the operator's
  indexer does not record once the owner's exit RPC (`--exit-rpc-url`) shows
  its final receipt and the same note, so the note can always be escaped;
  requests still wait for the activation. The exit RPC also confirms a
  withdrawal's completion, an exit RPC that cannot answer is named in the
  status (`exit_rpc_unusable`), and a plain-HTTP exit RPC on this machine is
  dialed directly (loopback addresses only) instead of through the relay.
- **`deposit(bytes32 commitment, uint128 amount)`** (selector `0x56d2e1ea`)
  replaces `deposit(bytes32,uint128,uint256[32])`: the siblings argument is
  gone. The SDK (`encodeDeposit`) and zkapi-clientd send the new calldata;
  clientd ties a prepared deposit slot to its signed transaction by nonce
  (`signed_nonce`) rather than by the calldata's sibling words.
- **The note tree's roots change** (see Changed): proofs, paths and roots
  from any earlier deployment or fixture do not carry over, and the browser
  bundle (`sdk/wasm`) must be rebuilt with `scripts/build-browser-client.sh
  --setup dev` for the new node hash before it computes correct roots.
- **`rootRetiredAt(uint256)` is removed** from the vault (informational, never
  read on chain; `NotesActivated` and `ClosedLeafRetired` carry every root
  change).
- Gasless withdrawals are additive: profiles without `gasless` (or with
  `gasless: null`) keep working with the wallet-pays path.

## [0.2.0] - not yet released

The concession-exit line: circuit `zkapi-v2-concession-v2`, vault revision 4,
capabilities `exit_concession: 1` and `NOTE_BOUND_EXIT_VERSION()` 1. The
release needs a new vault, adapter and trusted setup, and none is deployed
yet; the gates are in [the migration runbook](docs/migration-concession-vault.md).

### Breaking

- **New vault, circuit and keys.** An owner's exit no longer needs the
  operator: an escape names the state it leaves and its successor, concedes an
  amount `c` of at most the state's request budget, and pays `B - c`. Only a
  request proof at the successor defeats it. Notes cannot move between
  vaults; each owner withdraws from the legacy vault and deposits into the new
  one. Design: [concession-exit](docs/design/concession-exit.md).
- **Wire formats.** `WithdrawalPublicInputsV2C` has 17 fields
  (`registration_commitment`, `next_nullifier`, `conceded`, `valid_until`,
  withdrawal `kind`, and the note's packed `deposit_amount` and `expiry`),
  challenge calldata is `0xda0ce43d` (defeat) and `0xdd0064ba` (raise), and a
  request carries the anchor chain. Request JSON keeps its schema and its keys change.
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
- **zkapi-clientd** reports `bridge_version` 6. It warns about an open legacy
  wallet and names the legacy release, `0.1.7`; it never opens that wallet.
- **Version numbers.** Every shipped component now carries one version,
  `0.2.0` (the crates were `0.1.0`, the SDK and signer sidecar `0.2.0`,
  OpenAPI `2.2.0-concession`). The browser WebAssembly embeds crate versions,
  so its bytes and manifest hashes changed.

### Added

- Escape payout credits (`escapePayoutCredits`, `claimEscapePayout`),
  `raiseEscapeConcession`, exits bound to the recorded note (no root or
  path), an append-only request tree updated by proved activations (the
  operator's `zkapi-activated`) with `retireClosedLeaf`, a bounded pause
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
