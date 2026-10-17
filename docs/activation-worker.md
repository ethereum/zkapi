# Operating the activation worker

`zkapi-activated` appends the notes a revision-4 vault (circuit
`zkapi-v2-concession-v2`) recorded to its request tree, in proved batches, so
that they can make anonymous API requests.

A deposit only records its note (`notes(noteId)`: the registration commitment,
amount and expiry). The note can exit at once: withdrawals are bound to the
stored note, not to the tree. But a request proves membership in the request
tree under the vault's `currentRoot()`, and a recorded note is in that tree
only once it is *activated*: notes below `activationCursor()` are, notes from
the cursor to `nextNoteId()` wait. Clients report a waiting note as
`note_not_activated` and retry; its queue position is `noteId -
activationCursor()`.

The vault activates in deposit order, in aligned batches of 1, 4 or 16 notes:

- `activateNotes(firstNoteId, count, expectedRoot, newRoot, proof)` checks an
  insertion proof against inputs it builds from its own state
  (`[expectedRoot, newRoot, firstNoteId, C_0, M_0, …]`, with each note's
  commitment and packed amount and expiry read from storage). Only the
  vault's `activator()` may call it (else `NotActivator()`): this is what the
  worker sends, from that address.
- `activateNotesOnChain(firstNoteId, count, siblings)` hashes the batch and
  its path on chain instead. Anyone may call it once no proved activation has
  landed for an hour; see
  [the permissionless fallback](#the-permissionless-fallback).

Both require `firstNoteId == activationCursor()`, `firstNoteId % count == 0`,
recorded notes, and an unpaused vault; `activateNotes` also requires
`expectedRoot == currentRoot()`. Activation inserts each note's original leaf
whatever its status, so a note that closed before its activation still gets
its leaf (the challenger retires it afterwards when it has to).

Proofs are the activator's alone because every batch must be aligned and the
insertion proving keys are public. If anyone could prove, a third party could
land a proved singleton (about 276,000 gas) just ahead of the worker's batch
of 16 and force the other 15 notes through batches of 1 and 4, costing the
operator more than 1.2M gas beyond that one batch; an early
`activateNotesOnChain` would do the same, hence its delay (below). Exits never
depend on activation, so this is about the operator's gas, never about funds.

## Running it

```sh
cargo build --release -p zkapi-serverd --bin zkapi-activated
RUST_LOG=info target/release/zkapi-activated \
  --rpc-url "$ACTIVATION_SIGNER_RPC_URL" \
  --indexer-url http://127.0.0.1:3001 \
  --sender "$DEDICATED_ACTIVATION_ACCOUNT" \
  --deployment /etc/zkapi/deployment.json \
  --checkpoint /var/lib/zkapi/activation.json \
  --proof-setup-dir /srv/zkapi/protocol/setup/v2-concession \
  --confirmations 2 \
  --max-fee-per-gas-wei 100000000000 \
  --max-priority-fee-per-gas-wei 10000000000 \
  --status-listen 127.0.0.1:3003
```

Start it after the indexer and the challenger, before the API server takes
deposits. It needs no server database and holds no signing key of the
protocol: it proves with the setup's insertion proving keys and sends from an
account of its own, which must be the vault's activator
([below](#the-activator)).

The RPC must implement `eth_sendTransaction` with an operator-controlled
signer for the dedicated, funded sender. Give the worker **its own signer
instance and sender**, never the challenger's: each daemon assumes nobody else
sends from its account, and a stuck activation must never hold up a defeat.
Restrict that signer to `activateNotes` calls to the vault (the challenger's
signer profile allows only its own three calls and refuses activations). The
worker locks `<checkpoint>.lock` so two instances cannot share a checkpoint.

The bundled signer sidecar does this with `ZKAPI_SIGNER_PROFILE=activation`
([Activation profile](../docker/aws/signer/README.md#activation-profile)): it
signs only aligned `activateNotes` batches to its configured vault, refuses
every other call (the challenger's and `activateNotesOnChain` included), and
reads only `ZKAPI_ACTIVATION_` variables. In
[the Docker deployment](../docker/aws/README.md#activation-worker-and-its-signer)
the Compose profile `activation` runs the worker as the `activator` service
(`zkapi-run activator`, with `deployment.env` and `activation.env`) and its
signer as the `activation-signer` service (with `activation-signer.env`, from
`docker/aws/activation-signer.env.example`), which the worker reaches at
`http://activation-signer:8547`.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--rpc-url` | `ZKAPI_ACTIVATION_RPC_URL` | required | Signer RPC for `--sender`. |
| `--indexer-url` | `ZKAPI_ACTIVATION_INDEXER_URL` | required | The indexer whose `/v1/tree/notes/{id}/path` serves the siblings of the cursor's slot. |
| `--sender` | `ZKAPI_ACTIVATION_SENDER` | required | Dedicated gas-paying account: the vault's `activator()`. |
| `--deployment` | `ZKAPI_DEPLOYMENT_MANIFEST` | required | The deployment manifest (`trusted_deployment` profile). |
| `--chain-id`, `--contract-address` | | the manifest's | Optional; must equal the manifest. |
| `--checkpoint` | `ZKAPI_ACTIVATION_CHECKPOINT` | required | The worker's durable state (its pending transaction and counters). |
| `--proof-setup-dir` | `ZKAPI_PROOF_SETUP_DIR` | required | Holds `insertion1.pk`, `insertion4.pk`, `insertion16.pk`, and the request and withdrawal verifying keys the startup probes compare with the adapter. |
| `--confirmations` | | 2 | The worker's nonce is held until its transaction is this deep. |
| `--poll-interval-ms` | | 2000 | Poll period. |
| `--max-activation-wait-seconds` | `ZKAPI_MAX_ACTIVATION_WAIT_SECONDS` | 30 | Longest wait for a larger aligned batch to fill, from when the oldest pending note was first seen. |
| `--dry-run` | | off | Build, prove and simulate activations; never send. |
| `--max-fee-per-gas-wei` | `ZKAPI_ACTIVATION_MAX_FEE_PER_GAS_WEI` | required | Highest `maxFeePerGas` proposed; at most the signer's cap. |
| `--max-priority-fee-per-gas-wei` | `ZKAPI_ACTIVATION_MAX_PRIORITY_FEE_PER_GAS_WEI` | required | Highest tip; at least twice `--priority-fee-per-gas-wei`. |
| `--priority-fee-per-gas-wei` | `ZKAPI_ACTIVATION_PRIORITY_FEE_PER_GAS_WEI` | 2 gwei | Tip of a first attempt. |
| `--tx-fee-cap-wei` | `ZKAPI_ACTIVATION_TX_FEE_CAP_WEI` | 1 ETH | Highest gas limit x `maxFeePerGas` of one transaction; the node's RPC fee cap. A lower cap the signer reports (`zkapi_signerStatus`) or implies by a refusal applies too. |
| `--fee-bump-after-blocks`, `--fee-bump-percent` | | 3, 25 | Same-nonce replacement pace and fee-cap step. |
| `--status-listen` | `ZKAPI_ACTIVATION_STATUS_LISTEN` | 127.0.0.1:3003 | Internal status listener; never publish it. |
| `--pending-warning-seconds`, `--pending-critical-seconds` | | 600, 3600 | Wait of the oldest pending note at which the status warns, then is critical. |
| `--blocked-warning-seconds`, `--critical-blocked-seconds` | | 120, 1800 | Blocked time at which the status warns, then is critical. |
| `--stale-poll-seconds`, `--startup-grace-seconds` | | 300, 300 | Poll staleness alarm; warning-only time before the first successful poll. |
| `--min-sender-balance-wei` | | 0.75M gas x max fee, at most `--tx-fee-cap-wei` | Balance below which the status warns (one 16-note activation, with headroom). |

## The activator

The vault accepts `activateNotes` from one address, `activator()`
(`0x4ecea992`), and reverts `NotActivator()` (`0xb2df0af0`) for any other
sender while the vault is unpaused, before any other check (the range, the
root, the proof); a paused vault reverts `Paused()` first. The worker's
`--sender` must be that address: deploy the vault with `ACTIVATOR` set to it,
the address of the activation signer's key
([the contract notes](deployment.md#contracts)), and check
`cast call "$VAULT" 'activator()(address)'` before starting the worker. The
constructor emits `ActivatorChanged(address(0), activator)`.

The owner moves the role with `setActivator(address)` (`0x7c0cc0be`), which
takes a nonzero address, works while the vault is paused too, emits
`ActivatorChanged(previousActivator, newActivator)` (topic
`0xbd0aa56c02389240616a23c1d092ae6238c0e2847610bc4d302628e56cfee2e4`), and
leaves the fallback's opening alone. To move the worker to a new key or
sender:

1. Fund the new sender, whose key the activation signer will hold.
2. Wait until the worker's status shows no `pending_call`, then stop it, so
   that no transaction from the old sender is in flight.
3. From the owner, call `setActivator(newSender)`, and check `activator()`.
4. Restart the activation signer with the new key, and record the new
   activator in the deployment manifest (`activator`): the worker refuses to
   start while the manifest names another one. Record it too in the
   finalized manifest that `scripts/deployment-profile.mjs --finalized`
   reads, or a profile regenerated from it names the old activator again.
   Then start the worker with the new `--sender` and a new `--checkpoint`:
   a checkpoint belongs to one sender (with Docker, move
   `/var/lib/zkapi/activation.json` aside).

Deposits wait from step 2 to step 4, and if that lasts an hour past the last
proved batch, anyone can activate with the fallback meanwhile. If the worker's
key may be compromised, skip the wait and call `setActivator` at once: the
old key's transactions then revert `NotActivator()`. An activator can do no
more than activate the recorded notes in order (it can neither skip, reorder
nor alter one), so a stolen activator key risks only its account's balance
and the pace of activations.

## What it does

Every poll reads, at one block, `nextNoteId()`, `activationCursor()`,
`currentRoot()`, `paused()`, `activator()` and
`activationFallbackOpensAt()`.

**Batch size.** The largest of 16, 4 and 1 that is aligned at the cursor
(`cursor % K == 0`) and filled by recorded notes. When that is also the
largest batch aligned at the cursor, it is activated at once. Otherwise (a
larger aligned batch is still filling) the worker waits, but at most
`--max-activation-wait-seconds` after it first saw the oldest pending note,
then activates what is recorded. So at low volume every deposit gets a
singleton proof within the bound; the worker never waits for 16 deposits and
never falls back to the on-chain path. Examples, with the default 30 s:

| Cursor | Recorded after it | Batch |
| --- | --- | --- |
| 0 | 1 | 1, after 30 s (a batch of 16 could fill) |
| 0 | 16 or more | 16 at once |
| 4 | 4 or more | 4 at once (4 is the largest batch aligned at 4) |
| 5 | any | 1 at once |
| 16 | 5 | 4, after 30 s; then the 5th alone at cursor 20, once 30 s have passed since it was first seen |

A backlog therefore catches up by aligned steps (for example 4, 4, 4, then
16s). The wait clock comes from the checkpoint, so a restart does not reset
it.

**Batch.** The statement's notes are read from the vault (`notes(id)` at the
poll's block). The siblings of the cursor's slot come from the indexer
(`GET /v1/tree/notes/{cursor}/path`) and are verified locally: the empty
subtree of the batch's height, hashed up those siblings, must give the
vault's `currentRoot()`. A lagging or diverged indexer therefore blocks the
batch (`indexer_path_behind`) before any proving; it cannot make the worker
prove a wrong statement. The proof uses the proving key of size K and runs on
a blocking thread; its time is reported per batch (`last_batch.proving_ms`).

**Keys.** At startup the worker loads the three insertion proving keys under
this build's setup policy (a release build accepts only the pinned ceremony
keys; development keys load only with the `dev-setup` feature, as for the API
server), runs the API server's startup probes against the manifest (vault
revision 4, `NOTE_BOUND_EXIT_VERSION() == 1`, the adapter's circuit and
request and withdrawal verifying keys equal to the setup's, and the three
runtime codehashes), and requires each proving key's verifying key to equal
the adapter's `INSERTION1_VK_HASH()`, `INSERTION4_VK_HASH()` and
`INSERTION16_VK_HASH()`, and to be of the manifest's setup. When the manifest
records an `activator`, the vault's `activator()` must be it. A mismatch
exits; an unreadable RPC is retried. A `--sender` that is not the vault's
activator does not stop the worker: it is reported (below), since the owner
may still name it.

**Sending.** Before every send the worker simulates the call (`eth_call`),
estimates its gas (plus 20%), and writes the nonce, call, proof and fees to the
checkpoint. Fees are EIP-1559 bids within the caps and the transaction fee
ceiling, raised by same-nonce replacement after `--fee-bump-after-blocks` or
when the base fee passes the bid, keeping two replacements in reserve, as the
challenger does. The worker spends that reserve (10/11 of the caps, then the
caps) once the oldest pending note has waited past
`--pending-critical-seconds`. One nonce is in flight at a time, and it is held
until the transaction is `--confirmations` deep; the next batch is built after
that.

A persisted call is sent again only while it is still the batch at the
vault's state of the poll: the same cursor and root, its notes below
`nextNoteId()`, and the same notes (`notes(id)` at the poll's block, compared
with a digest of the proved ones, re-read whenever the head block changes).
Otherwise it is obsolete, and replaced on its nonce by a fresh batch.

Measured on Anvil against the revision-4 vault and the generated adapter
(`tests/activation_anvil.rs`), an `activateNotes` receipt (intrinsic gas and
calldata included) shows about 286,100 gas for 1 note, 348,400 for 4 and
605,200 for 16 (a few dozen gas more or less with the calldata's bytes), so
about 37,800 per note at 16. CI's pinned Forge measurement, with cold
contracts, is 275,635, 337,933 and 594,662
(`protocol/contracts/snapshots/activation-gas.json`). Both include the write
of `activationFallbackOpensAt()`, which costs about 2,800 gas less when the
activation lands in the same second as the previous write (a proved
activation, the deployment or an unpause), as some of the Anvil test's
batches do (about 283,300, 345,600 and 602,400).

## Races and failure modes

The vault accepts an activation only at its cursor and root, and every
decision of the worker is made from the chain, so each race is resolved by
rebuilding from fresh state.

- **Deposits while proving.** They change neither the cursor nor the root:
  the batch is a prefix of the recorded notes and stays valid.
- **A competing activation** (an `activateNotesOnChain` once the fallback is
  open, or another worker sending as the activator) **or a leaf retirement**
  (the challenger's `retireClosedLeaf`, which moves the root) landing first:
  - while proving: the worker re-reads the cursor and root after proving and
    discards the batch (`rebuilding`, counted in `stale_rebuilds_total`);
  - in simulation: `StaleActivation()` (`0x9c9413a1`) or `InvalidActivation()`
    (`0xe72f8984`), likewise rebuilt on the next poll; a persisted call that
    reverts so (or `InvalidProof()`) is marked obsolete in the checkpoint and
    never sent again;
  - while pending: the obsolete transaction is replaced on its nonce by the
    fresh batch, outbidding it, so it never mines; if nothing is left to
    activate, or no valid replacement fits the caps, it is left to mine and
    revert `StaleActivation()`, which happens before any verification and
    costs little (counted in `reverted_total`).
- **Retirements and activations invalidate each other's pending
  transactions**, since both move `currentRoot()`; each daemon rebuilds. The
  challenger waits for a note's activation before retiring it
  (`awaiting_activation`): activation appends the leaf of a note that closed
  before it.
- **A dropped transaction** (unknown to the RPC, its nonce unconsumed): the
  nonce is re-sent with the persisted call, without proving again, or with a
  fresh batch if the persisted one is obsolete.
- **An ambiguous send** (a timeout, or a signer that may have broadcast):
  the write-ahead record is kept and the nonce outbid at the replacement pace
  (`send_ambiguous`). Without a hash and with nothing on the nonce after
  `--fee-bump-after-blocks`, it is re-sent at the persisted fees (only one
  attempt on a nonce can mine), so a send that never left does not hold the
  nonce.
- **A restart** resumes the persisted nonce and call. The checkpoint belongs to
  one sender, chain and vault; another one is refused.
- **A reorganization**: the nonce is held until confirmation depth, then the
  receipt says how the batch ended (`activated`, `reverted`, or `unknown` for a
  nonce consumed by an attempt without a known receipt). An activation undone
  before that is waited on if the node returns it to its pool, else re-sent on
  its nonce without proving again. One that dropped or replaced a deposit of
  the batch leaves cursor and root unchanged but makes the persisted proof
  unsendable (`InvalidActivation()` or `InvalidProof()`): it is replaced on
  its nonce by a fresh batch. A batch undone after confirmation depth is
  activated again from the chain's state (the counters are not rewound).
- **Not the activator**: while the vault's `activator()` is not `--sender`
  (a vault deployed with another `ACTIVATOR`, or after a `setActivator`), the
  vault refuses every batch (`NotActivator()`, `0xb2df0af0`). The worker
  sends nothing and reports `not_activator`; a transaction already pending
  stays on its nonce and reverts if it mines. It resumes once the owner
  names its sender. Meanwhile deposits wait for the fallback.
- **A paused vault**: activation reverts while paused; the worker reports
  `paused` and waits.
- **`InvalidProof()`** (`proof_rejected`, critical at once): the adapter
  refused a freshly proved batch whose notes the vault still holds as proved,
  which the startup pins should make impossible. Check the setup directory
  against the manifest and the adapter. A batch whose notes a reorganization
  moved while it was proved is rebuilt instead.
- **Fee caps, balance, signer refusals**: reported with the challenger's
  reasons (`tx_fee_cap_reached`, `insufficient_balance`, `signer_refused`, …).

## Status

`GET /status` on `--status-listen` serves the snapshot, schema
`zkapi-activated-status/v1`; `GET /health` answers 503 when it is critical and
`GET /livez` 503 when the poll loop stalled. It reports:

- `state`: `starting`, `idle`, `waiting` (a larger batch is filling; see
  `next_batch.activate_by`), `proving`, `submitted`, `confirming`,
  `rebuilding`, `paused`, `dry_run` or `blocked` (with `blocked_reason` and
  `blocked_since`; `not_activator` while the vault's `activator()` is not
  `--sender`, which escalates with time like the other reasons until the
  owner names the sender);
- `queue`: `activation_cursor`, `next_note_id`, `pending_notes` and the age of
  the oldest pending note;
- `next_batch`, `pending_call` (nonce, batch, hash, attempts, fees) and
  `last_batch` (batch, outcome, proving time, gas used, hash, block);
- `totals`: batches by size, notes activated, reverted transactions, stale
  rebuilds, proofs and proving time, gas used;
- `sender` (balance and fee caps), `chain` (with the vault's `activator` and
  `activation_fallback_opens_at`, read every poll), `poll`, and `alarms`.

The status warns when the oldest pending note waits past
`--pending-warning-seconds` and is critical past `--pending-critical-seconds`:
deposits then cannot make requests. If the worker cannot recover in time,
activate with the fallback below, which opens an hour after the last proved
activation (`chain.activation_fallback_opens_at`).

## The permissionless fallback

Activation never depends on the operator's prover:
`activateNotesOnChain(firstNoteId, count, siblings)` (`0x027e21e9`) is open to
anyone while the vault is unpaused, from `activationFallbackOpensAt()`
(`0x3a02aa08`) on: `ACTIVATION_FALLBACK_DELAY()` (`0x4c81d3cd`, 1 hour) after
the latest proved activation, the deployment or the latest unpause, whichever
is last. Before then it reverts `ActivationFallbackClosed()` (`0x67df368d`),
checked before anything else. On-chain activations do not move the opening,
so once the activator has been idle for an hour the fallback stays open until
its next proved batch. While the worker proves, then, nobody can activate a
note ahead of it and break its batches' alignment, and if it stops, anyone can
activate an hour later.

The call takes the same aligned batch at the cursor and the 32 siblings of
slot `firstNoteId` in the current tree (entries below the batch's height are
ignored), which the indexer serves or any client rebuilds from the vault's
events; it hashes the leaves and both paths on chain and emits
`NotesActivated` with `proved = false`. It costs far more gas (about 1.66M for
one note, 1.89M for 4 and 3.08M for 16).

The vault accepts only the batch at the cursor, so a given note is reached one
aligned batch at a time, from `activationCursor()` up to the batch holding it.
This loop does that: each round re-reads the cursor and `nextNoteId()`, then
waits while the latest block's timestamp is before
`activationFallbackOpensAt()` (the vault compares `block.timestamp`; a proved
activation landing meanwhile moves the opening, and a note the worker reaches
meanwhile ends the loop), then reads the root, takes the cursor slot's path
from the indexer only once the indexer's view has the vault's cursor and root,
and sends the largest batch of 16, 4 or 1 that is aligned at the cursor and
recorded. Set `TARGET` to the note to reach; by default it activates every
recorded note. It stops at the first failed send (a paused vault, or another
activation landing first): run it again, since it reads everything afresh.

```sh
TARGET=${TARGET:-$(( $(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC" | jq -r '.[0]') - 1 ))}
while :; do
  CURSOR=$(cast call --json "$VAULT" 'activationCursor()(uint32)' --rpc-url "$RPC" | jq -r '.[0]')
  NEXT=$(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC" | jq -r '.[0]')
  [ "$CURSOR" -le "$TARGET" ] && [ "$CURSOR" -lt "$NEXT" ] || break
  OPENS=$(cast call --json "$VAULT" 'activationFallbackOpensAt()(uint64)' --rpc-url "$RPC" | jq -r '.[0]')
  NOW=$(cast block latest --field timestamp --rpc-url "$RPC")
  if [ "$NOW" -lt "$OPENS" ]; then
    echo "the fallback opens in $((OPENS - NOW)) s"; sleep $((OPENS - NOW < 60 ? OPENS - NOW : 60)); continue
  fi
  ROOT=$(cast call --json "$VAULT" 'currentRoot()(uint256)' --rpc-url "$RPC" | jq -r '.[0]')
  SLOT=$(curl -fsS --max-time 30 "$INDEXER/v1/tree/notes/$CURSOR/path")
  if [ "$(echo "$SLOT" | jq -r .activation_cursor)" != "$CURSOR" ] ||
     [ "$(cast to-dec "$(echo "$SLOT" | jq -r .root)")" != "$ROOT" ]; then
    echo "the indexer is behind the vault; retrying"; sleep 5; continue
  fi
  COUNT=1
  for K in 16 4; do
    if [ $((CURSOR % K)) -eq 0 ] && [ $((CURSOR + K)) -le "$NEXT" ]; then COUNT=$K; break; fi
  done
  SIBLINGS=$(echo "$SLOT" | jq -r '"[" + (.siblings | join(",")) + "]"')
  cast send "$VAULT" 'activateNotesOnChain(uint32,uint256,uint256[32])' \
    "$CURSOR" "$COUNT" "$SIBLINGS" --rpc-url "$RPC" --private-key "$KEY" || break
done
```

Numbers come from `cast call --json`: plain `cast call` annotates numbers of
10,000 or more (`12345 [1.234e4]`); `cast block --field timestamp` prints a
plain decimal. The indexer serves each sibling as a quoted hex string, and
cast parses a `uint256[32]` argument only unquoted (`[0x0,0x3b56…,…]`), hence
the `join`. A running worker treats such an activation like any other
competing one.

## Revision-4 changes elsewhere in the server stack

- The API server binds a clearance's kind-2 ownership proof to the note the
  vault recorded instead of a root: `notes(noteId)` must hold the proof's
  commitment, amount and expiry and be Active (activation does not matter).
  It answers `note_binding_mismatch` (400), `note_not_active` (409), or the
  retriable `note_not_recorded` (409) while its RPC has not seen the deposit;
  `stale_root` no longer applies to clearances. **Breaking:** the
  `--clearance-root-window-seconds` flag is removed: `zkapi serverd` refuses
  it, and ignores `ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS`. Request admission
  keeps the exact current root.
- The server's, the challenger's and the worker's startup probes require
  `NOTE_BOUND_EXIT_VERSION() == 1` instead of `ROOT_HISTORY_WINDOW()`.
- The challenger decodes the 5-word `pendingWithdrawals`, and its retirement
  of a missed defeat waits for the note's activation.

## Tests

`cargo test --release -p zkapi-serverd --lib activation` covers batch selection
and the wait bound, and runs the worker against a mock vault, signer RPC and
indexer (which verifies every insertion proof) through singletons at low
volume, full batches of 4 and 16, a deposit and a competing activation while
proving, a competing activation and a retirement landing first, a restart with
a pending call, a dropped transaction, reorganizations (of a mined activation
before and after confirmation depth, of a batch's deposit dropped or replaced
under a pending or mined call, and across a restart), a persisted call failing
simulation, an ambiguous send that never left, the replacement reserve spent at
the critical threshold, a lagging indexer, a sender that is not (or stops
being) the activator, `--dry-run` and the startup key pins.
`cargo test --release -p zkapi-serverd --test activation_anvil` deploys the
real vault and adapter on Anvil, with the worker's sender as the activator,
and runs the worker end to end, including a competing `activateNotesOnChain`
once the fallback opens, an owner's `setActivator` away from the worker and
back, and two reorganizations by `evm_snapshot`/`evm_revert` (it skips
without `forge` and `anvil`, and fails instead with `ZKAPI_REQUIRE_ANVIL=1`).
