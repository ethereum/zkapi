# Migrating to the concession-exit vault

This is the operator runbook for moving a zkAPI deployment from the legacy
vault (circuit `zkapi-v2-note-bound-v1`) to the concession-exit vault (circuit
`zkapi-v2-concession-v1`, vault revision 3, capability `exit_concession: 1`).
The design and its security argument are in
[the concession-exit design](design/concession-exit.md); its §10 is the plan
this runbook carries out, with Amendment A1 (exits accept any root the vault
ever held).

On a legacy vault, an operator that finalizes a request but withholds its
signed successor state can defeat every escape the owner can build, and then
take the deposit at expiry. On the concession vault an escape names the state
it leaves and that state's successor, concedes an amount `c` of at most the
state's request budget, and pays `B − c`. Only a request proof at the
successor defeats it, and a request proof at the escaped state can only raise
`c`, within that budget. The owner's exit therefore needs no operator
cooperation. The vault is immutable, so this needs a new vault, adapter and
trusted setup.

Vaults deployed before this change are called **legacy vaults** here. They
include the published Mainnet vault
`0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe` and Sepolia vault
`0x49fA19f9bdECe7A48Ebc7749fD69aD40F577590F`. The revision-2 "hardened" vault
that an earlier version of this guide described was built but never deployed.
It is superseded: the concession vault replaces it, so users migrate once.
[The earlier guide](migration-hardened-vault.md) now points here.

Notes cannot move between vaults. Each owner withdraws from the legacy vault
and deposits into the new one. The migration runs in these phases:

| Phase | What happens | Gate before it starts |
| --- | --- | --- |
| [0](#phase-0-harden-the-legacy-stack-in-place) | Upgrade the legacy stack's services in place, from `release/v2-note-bound` | None; do it now |
| [A](#phase-a-freeze-review-and-trusted-setup) | Freeze the circuits, external review, multi-party setup (G-SETUP), regenerate and publish every pin | All suites green on the revision-3 source |
| [B](#phase-b-sepolia) | Sepolia drill vault, then production Sepolia, then a 14-day soak | Phase A complete |
| [C](#phase-c-mainnet) | Mainnet deployment, smoke tests, canary, legacy deposits closed (day 0), `X` announced | Phase B soak and drills green; the mainnet gates below |
| [D](#phase-d-clientd-releases) | The legacy clientd point release 0.1.7, then the new clientd release | 0.1.7 before the new release; the new release after a Sepolia drill |
| [E](#phase-e-drain-and-retire-the-legacy-vault) | Drain the legacy vault over [the 30-day transition](#the-30-day-transition-for-existing-users) and retire its stack | Day 0 (Phase C) |

Phases B to D overlap: the legacy stack keeps running, unchanged except for
configuration, until the end of Phase E.

**Mainnet gates.** Phase C starts only when all of these hold (design §11):

- G-SETUP is complete: a multi-party phase 2 with at least two contributors
  the operator did not select, a public random beacon, over a listed public
  powers of tau, with both fidelity gates passed;
- an external review covered the circuit diff, the `CircomReduction`
  prover, the R1CS export and zkey import, the vault, the adapter template,
  the codehash derivation, the challenger policy and the clients' exit logic;
- the WebAssembly is rebuilt reproducibly and the expected codehashes are
  published;
- every drill passed on Sepolia, followed by 14 days of soak with weekly
  drills;
- the daemons start in order, with the challenger healthy before the first
  deposit;
- the canary is configured (the SDK caps and the server's lease ceiling);
- the legacy deposit routes are ready to close, the legacy re-cut is ready to publish, and day 0 and the cutoff `X` are announced at least 14 days ahead
  ([the 30-day transition](#the-30-day-transition-for-existing-users)).

## Compatibility

| Component | Legacy vault (`zkapi-v2-note-bound-v1`) | Concession vault (revision 3, `zkapi-v2-concession-v1`) |
| --- | --- | --- |
| Legacy browser SDK re-cut (`v0.1.x`, existing `publicPath`, `/zkapi/`) | Requests and exits; deposits closed | Refused (`incompatible_proof_circuit`) |
| Browser SDK from `main` (`0.2.x`, `/zkapi/v2c/`) | Refused (circuit mismatch) | Supported |
| zkapi-clientd 0.1.7 (`release/v2-note-bound`) | Supported; deposits closed; mutual close and a fresh-state escape | Refused (pins) |
| zkapi-clientd from `main` (`0.2.x`, `bridge_version` 5) | Warns and names the 0.1.7 release; never opens that wallet | Supported |
| zkapi-clientd 0.1.6 and earlier | Supported, with the earlier releases' risks; no escape | Refused |
| Legacy stack (`0.1.x`: serverd, indexer, challenger from `release/v2-note-bound`) | Supported | Refused (`deployment_binding`, circuit) |
| New stack (`0.2.x`, from `main`) | Refused | Supported |
| Request JSON (`ApiRequestV2`) | Same schema; legacy keys | Same schema; new keys |
| Withdrawal and clearance wire | `WithdrawalPublicInputsV2` (14 fields) | `WithdrawalPublicInputsV2C` (16 fields), `deny_unknown_fields` |
| Challenge calldata | `0x8a43467c`, evidence at `N`, with siblings | Defeat `0xda0ce43d`, evidence at `N⁺`, no siblings; raise `0xdd0064ba` |
| Proving keys and WebAssembly | `protocol/setup/v2` | `protocol/setup/v2-concession` (`mpc-1`), new key URLs |

Release versions follow [the versioning policy](versioning.md): `0.1.x` is
the legacy line and `0.2.x` the concession line, and components of different
lines refuse each other.

The two stacks never share a database, indexer checkpoint, challenge
checkpoint, signer key, sender, hostname or gateway image tag. Each vault has
its own stack until the legacy one retires.

## The 30-day transition for existing users

The legacy vaults give every note a 30-day life, so the migration is bounded by
it: **close legacy deposits on the day the new vault goes live (day 0), and
every note that exists on that day has expired or exited before day 31.** The
legacy stack keeps serving those notes, unchanged, until then. This section is
the schedule. The phases below hold the commands.

### What the deployed vaults do

Both legacy vaults (Mainnet and Sepolia) have `noteTtl` 2,592,000 s (30 days)
and `challengePeriod` 86,400 s (24 hours).

- **Expiry.** A note expires `noteTtl` after its deposit, rounded up to the
  next UTC midnight. A note deposited on day 0 therefore expires before day 31.
- **The sweep.** From its expiry anyone can call `claimExpired`, which pays the
  note's whole deposit to the treasury. There is no grace and no challenge
  wait, and the owner never pauses the vault (Phase 0, step 8), so the date is
  exact. A note that has left `Active` first, closed or with an escape
  pending, cannot be swept. **An owner must close the note, or start an
  escape, before its expiry.** A started escape finalizes 24 hours later.
- **Exits need the live root.** `mutualClose` and `initiateEscapeWithdrawal`
  revert with `StaleRoot` if a deposit, close or sweep lands between the proof
  and the transaction. Clients re-prove and retry, and a retry succeeds unless
  another transaction moved the root first.

### Terms

- **Day 0** is the moment the legacy deposit routes close at the gateway
  (Phase E, step 1). It is the same hour as the new vault's go-live.
- **`N_C`** is `nextNoteId()` read right after that. A note with an ID below
  `N_C` is a **transition note**. A note with an ID of at least `N_C` is a
  **late note**: a direct deposit that bypassed every official client.
- **`E_last`** is the expiry of note `N_C - 1`. Expiry never decreases with
  the note ID, so this is the last transition note's expiry, before day 31.
- **`X`**, the moment legacy admission closes, is `E_last`.

```sh
# Day 0, right after the deposit routes close:
N_C=$(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC_URL" | jq -r '.[0]')
E_LAST=$(cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$((N_C - 1))" --rpc-url "$RPC_URL" | jq -r '.[2]')
echo "N_C=$N_C X=E_last=$E_LAST ($(date -u -d "@$E_LAST"))"
```

Publish `N_C` and `X`.

### Schedule

| When | Operator | Owners and hosts |
| --- | --- | --- |
| Before day 0 (from Phase B) | Finish Phase 0 and ship `zkapi-clientd` 0.1.7 ([Phase D](#phase-d-clientd-releases)). Prepare the two gateway changes of Phase E (deposit routes, then leases) and test them on a staging copy. Publish day 0, the rules below and the sweep policy at least 14 days ahead. Run the rehearsal below | Hosts deploy the two-build loader ([Side-by-side browser builds](#side-by-side-browser-builds)) and their banners |
| Day 0 | Phase C, steps 1 to 4, then close the deposit routes and publish the legacy re-cut with `"deposits": "closed"` (Phase E, step 1). Record `N_C` and `X` | New deposits go to the new build. A legacy owner is routed to the legacy build |
| Days 1 to `X` | Legacy chat, close and escape stay open for every note. Monitor daily (Phase E, step 3). Decide about legacy clearance on days 14 and 21 (Phase E, step 5). Clients retry `StaleRoot` reverts by themselves | Owners close when they choose, then deposit into the new vault. Hosts show each owner a "close by" date (below) and remind at 7, 3 and 1 days before it |
| `X` | Close legacy admission at the gateway (Phase E, step 2). Every transition note has now expired or exited, so no owner who acted loses service | Chat on the legacy build ends |
| `X` + 1 day | Finalize every escape that is past its deadline (Phase E, step 3). Sweep expired transition notes by the announced policy | |
| After that | Retire the stack when the retirement condition holds (Phase E, step 6) | |

Retirement is therefore about day 32 for the transition notes. Day 31 is the
latest `X` and the 24-hour challenge period follows it.

### Rules for the window

- **Each owner has their own deadline**, the note's expiry, and the wallet
  holds it (`expiry_ts`). Hosts show a **close by** date three days before it
  (72 hours: a request in flight needs its settlement, a transaction can
  revert on a moving root, and an owner may not be at their device). Reminders
  are broadcast; the operator cannot tell who holds a note.
- **Spread the move.** Every close and escape changes the vault's root, and
  the next one in line must re-prove against it. Do not announce "everyone
  move today". Announce each owner's own date and let the expiries stagger the
  load. If owners report `StaleRoot` reverts (they show as failed
  transactions on the vault), tell them to retry later and not to wait for
  the last day.
- **Service continues.** Admission stays open to every note until `X`, because
  the legacy server cannot tell a transition note from a late note (a request
  hides its note ID). Do not close it earlier than `X` without a notice of at
  least 7 days.
- **Old clients keep working while they can.** `zkapi-clientd` 0.1.6 and
  earlier have no escape and exit only through a mutual close, which needs
  legacy clearance. Keep legacy clearance on until the Phase E, step 5 gate
  passes, never switch it off in the last 7 days before `X`, and tell those
  owners to upgrade to 0.1.7, which keeps their wallet directory.
- **The sweep policy is announced before day 0.** At `X` the treasury sweeps
  the expired transition notes that nobody closed. State that, state whether
  the operator refunds an owner who proves ownership afterwards (for example
  with an escape-form ownership proof, as the clearance route checks), and
  state until when. Sweeping at `X` is what lets the challenger retire at
  about day 32. Waiting instead keeps those owners' escape open and keeps the
  challenger running for as long as the wait.
- **A griefer can slow exits.** Anyone can move the root by depositing, at the
  price of gas and a locked deposit. Nothing on the legacy vault stops that.
  If exits stall near a deadline, delay the sweep for the affected notes,
  announce it, and keep the challenger up.

### What an owner does

| Owner | Steps |
| --- | --- |
| Browser SDK user | Open the host. The loader picks the legacy build for a legacy note. Withdraw (mutual close; if a request has not settled, wait for it or use the escape). Then deposit in the new build |
| `zkapi-clientd` 0.1.7 | Withdraw (mutual close), or `withdraw --escape` from a settled state; `zkapi-clientd/docs/LEGACY_ESCAPE.md` has the steps. Then install the new release and fund it |
| `zkapi-clientd` 0.1.6 or earlier | Install 0.1.7 first; it opens the same wallet directory. Then as above |
| Anyone else (a direct depositor, a lost device) | The exit kit, or `LEGACY_ESCAPE.md`; the escape is started before the expiry |

### Late notes

A late note can hold service history, because admission is open until `X`, so
the retirement condition has two parts. Read `nextNoteId()` daily: while it
equals `N_C`, there are no late notes.

- **None.** Retire when every transition note is `Closed` or swept and the last
  escape deadline has passed: about day 32.
- **Some.** Record their IDs and expiries. A late note deposited before `X` may
  have history, so the challenger runs until each one is closed, or swept, and
  its last escape deadline has passed: before day 63. A late note deposited after `X` holds only its genesis state and
  needs no challenger (Phase E, step 6). The operator may instead retire at
  about day 32 and accept the exposure: a late owner who consumed service and
  then escaped from an older state is paid more than they should be, by at
  most the service they consumed.

### Server readiness

Nothing on the legacy line needs new code. For day 0 the legacy services are
ready when:

| Piece | Ready means |
| --- | --- |
| Legacy serverd, indexerd, challenger and signer | Built from `ac9be63` or later (Phase 0), healthy, and running side by side with the new stack under their own database, checkpoints, signer key, sender, hostname and image tag |
| Legacy challenger | Funded for the whole window and its retries (about 35 days), because it must run until about day 32 |
| Legacy clearance | On (`ZKAPI_ALLOW_LEGACY_CLEARANCE=true`) until the gate of Phase E, step 5 |
| Legacy gateway | The deposit-route block is built and tested for day 0, and the lease-route block for `X` (Phase E, steps 1 and 2); each is one new gateway image tag |
| New stack | Refuses the legacy vault (`deployment_binding`) and never serves a legacy note |

### Rehearsal

Deposit a note on the legacy Sepolia vault at the start of Phase A, 31 days or
more before Phase C. Run on Sepolia, with that note and the gateway blocks:
the deposit-route block, a mutual close, an escape with its finalization, the
lease-route block, the sweep at expiry and the refund policy. The Sepolia
vault has the same 30-day note life, so this is the one rehearsal of the expiry
and the sweep.

## Before you start

The examples assume the Docker deployment in [docker/aws](../docker/aws/README.md).
For the legacy deployment, set:

```sh
export VAULT=0xREPLACE_WITH_LEGACY_VAULT RPC_URL=https://REPLACE_WITH_READ_RPC DEPLOY_BLOCK=REPLACE
dc() { sudo docker compose -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi API_URL=http://127.0.0.1:8080
```

Use for `RPC_URL` a read RPC independent of the indexer's. `DATA_DIR` is the
deployment's data directory (`ZKAPI_DATA_DIR`) and `API_URL` its gateway on
the VM (`ZKAPI_HTTP_PORT`). Once the new deployment shares the VM (Phase B),
`dc`, `DATA_DIR` and `API_URL` change for the legacy deployment; see
[Two stacks on one VM](#two-stacks-on-one-vm). Take numbers for shell
arithmetic from `cast call --json`: plain `cast call` annotates numbers of
10,000 or more (`10000 [1e4]`).

1. **Vault state.**

   ```sh
   for getter in 'owner()(address)' 'paused()(bool)' 'treasury()(address)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'nextNoteId()(uint32)'; do
     printf '%s ' "$getter"; cast call "$VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   TREASURY=$(cast call "$VAULT" 'treasury()(address)' --rpc-url "$RPC_URL")
   cast call "$TREASURY" --value 1gwei --from "$VAULT" --rpc-url "$RPC_URL"
   ```

   The last call simulates a payment from the vault to its treasury and prints
   `0x` while the treasury accepts ETH. `execution reverted` means that every
   legacy exit with an operator share, and every expiry claim, reverts; see
   Phase 0, step 8.

2. **Pending escapes and their evidence.**

   ```sh
   N=$(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC_URL" | jq -r '.[0]')
   for i in $(seq 0 $((N - 1))); do
     status=$(cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$i" --rpc-url "$RPC_URL" | jq -r '.[3]')
     [ "$status" = 2 ] || continue
     pending=$(cast call --json "$VAULT" 'pendingWithdrawals(uint32)(bool,uint256,uint256,uint128,address,uint64)' "$i" --rpc-url "$RPC_URL")
     nullifier=$(cast to-hex "$(echo "$pending" | jq -r '.[2]')")
     echo "note $i deadline $(echo "$pending" | jq -r '.[5]') nullifier $nullifier" \
       "destination $(echo "$pending" | jq -r '.[4]') final_balance $(echo "$pending" | jq -r '.[3]')"
     sudo sqlite3 -readonly "$DATA_DIR/server.db" \
       "SELECT n.status, n.reservation_kind, l.status, l.key_source, l.key_hash IS NOT NULL FROM nullifiers n LEFT JOIN openrouter_leases l ON l.request_nullifier = n.nullifier WHERE n.nullifier = '$nullifier';"
   done
   ```

   Schedule Phase 0 so that its challenger runs well before the nearest
   deadline. The Phase 0 challenger contests a legacy escape whose nullifier
   has a `Finalized` record, and waits on a `Reserved` one until the server
   finalizes it; on a legacy vault that challenge consumes the nullifier, and
   the owner exits from the signed successor state.

3. **Signing seeds.** Run `dc run --rm --no-deps --entrypoint zkapi server
   signing-keys` with the images of Phase 0, step 1. If it refuses the
   production seeds, the Phase 0 server cannot serve that vault: keep the
   earlier stack for it (server, challenger, indexer, gateway and signer from
   the previous checkout and image tag), apply only Phase 0, step 8, and drain
   it promptly. If the seeds derive a development key, follow
   [the compromise procedure](#if-development-or-mismatched-keys-were-ever-served).

4. **Served keys.** Compare `/v1/attestation` with the vault's getters as
   numbers:

   ```sh
   for getter in stateSigningKeyX stateSigningKeyY clearanceSigningKeyX clearanceSigningKeyY; do
     cast to-dec "$(cast call "$VAULT" "$getter()" --rpc-url "$RPC_URL")"
   done
   curl -fsS "$API_URL/v1/attestation" \
     | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
     | while read -r value; do cast to-dec "$value"; done
   ```

5. **Keys served in the past.** Every archived request must carry the vault's
   state key. On a copy of the database:

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT json_extract(request_inputs_json, '$.state_signing_key_x') AS k, count(*) FROM nullifiers WHERE request_inputs_json IS NOT NULL GROUP BY k;
      SELECT json_extract(api_request_json, '$.public_inputs.state_signing_key_x') AS k, count(*) FROM openrouter_leases GROUP BY k;"
   ```

   Any other value, in particular the development state key
   `0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32`, means
   [the deployment is compromised](#if-development-or-mismatched-keys-were-ever-served).

6. **Settlement and clearance snapshot.**

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT key_source, status, count(*) FROM openrouter_leases WHERE status <> 'finalized' GROUP BY 1, 2;
      SELECT status, reservation_kind, count(*) FROM nullifiers GROUP BY 1, 2;"
   ```

   Unsettled leases of another key source make the Phase 0 server refuse to
   start until they drain; see
   [Changing the key source](native-eth-billing.md#changing-the-key-source).
   Never delete a `ClearanceReserved` row: a clearance signature was returned
   for it.

7. **RPC capabilities.** The indexer's RPC must answer an EIP-1898 call and
   `eth_getBlockByHash`; the native billing RPC must serve the chain and the
   `finalized` tag:

   ```sh
   HASH=$(cast block latest --field hash --rpc-url "$INDEXER_RPC_URL")
   cast rpc eth_call "{\"to\":\"$VAULT\",\"data\":\"0xfdab463d\"}" "{\"blockHash\":\"$HASH\",\"requireCanonical\":true}" --rpc-url "$INDEXER_RPC_URL"
   cast rpc eth_getBlockByHash "$HASH" false --rpc-url "$INDEXER_RPC_URL" | jq -r .number
   cast chain-id --rpc-url "$NATIVE_BILLING_RPC_URL"
   cast block finalized --field number --rpc-url "$NATIVE_BILLING_RPC_URL"
   ```

   The indexer's RPC must come from a provider other than the `rpc_url` that
   clients pin: `zkapi-clientd` corroborates deposits and withdrawals against
   the indexer's tree. Also find the `--rpc.txfeecap` of the node behind the
   challenge signer (1 ETH by default in geth and reth).

## Phase 0: harden the legacy stack in place

The legacy stack runs from the release line `release/v2-note-bound`, cut at
`ac9be63`. That line carries the hardening of the legacy services (required
signing seeds checked against the vault, authenticated clearance, terminal
settlement, the verifying indexer, the EIP-1559 challenger and signer), its
security fixes, and the config-only re-cuts of Phase E. `main` carries only
the new circuit, so never build the legacy stack from `main`. The maintainers
must publish the release line (push the branch and tag the release) before
operators build from it.

If the legacy deployment already runs images built from `ac9be63` or later on
that line, Phase 0 is done except for step 8; check the owner policy and
continue with Phase A. Otherwise upgrade the legacy deployment's own
services: same vault, data directory and sender. Plan a window with no
challenge deadline close (Before you start, item 2); the API is down for a few
minutes in step 6. The full list of the behaviour changes this upgrade brings
to the legacy services and clients is in that branch's own copy of the
earlier guide (`docs/migration-hardened-vault.md` on `release/v2-note-bound`,
sections "What changed and why", "Breaking changes" and "Compatibility");
ignore its Phases 1 to 4, which this runbook replaces.

1. **Build.** Check out `release/v2-note-bound`, set a new `ZKAPI_IMAGE_TAG`
   in the operator's Compose environment file (so the previous images stay
   available for rollback), and build: `dc build server gateway signer`.
2. **Configuration.**
   - `deployment.env`: add `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS=21600`,
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (the node's `--rpc.txfeecap` in wei),
     `INDEXER_CONFIRMATIONS=12`, `INDEXER_MAX_HEAD_AGE_SECS=180` and
     `ZKAPI_ALLOW_LEGACY_CLEARANCE=true`. Legacy clearance must stay on while
     clients from before this line may withdraw: `zkapi-clientd` 0.1.6 and
     earlier have no other exit. Its proof-less budget (60 per minute per
     server process) is one pool that anyone can exhaust; alert on
     `legacy_clearance_rejected_total`.
   - `server.env`: both seeds, which passed Before you start, item 3.
   - `signer.env`: delete `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`, set
     `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` (required on Mainnet), and the same
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` as `deployment.env`. A legacy challenge
     needs about 7.53M gas, so at a 1 ETH ceiling keep the fee cap at most
     about 131.6 gwei.
   - `challenge.env`: `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
     `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`, no higher than the
     signer's caps, the tip cap at least twice the daemon's priority fee.
   - Fund the sender with at least (pending escapes + reverted attempts + 1) x
     the lower of 7.6M gas x fee cap and the transaction fee cap.
   - Restrict the EC2 security group's inbound port to the
     `com.amazonaws.global.cloudfront.origin-facing` prefix list.
3. **Gateway:** `dc up -d --no-deps --wait gateway`.
4. **Indexer:** `dc up -d --no-deps --wait indexer`. It archives its
   version-1 checkpoint as `indexer.cursor.v1-<unix_ms>.bak` (keep it for
   forensics only; never restore it) and replays from `DEPLOY_BLOCK`. Compare
   its root and next note ID with the vault as in
   [Indexer resync](../docker/aws/README.md#indexer-resync), step 1.
5. **Signer:** `dc up -d --no-deps --wait signer`, then check
   `zkapi_signerStatus`: `tx_fee_cap_wei` must be the node's cap, and the
   warnings empty apart from `balance_below_required` and
   `tx_fee_cap_below_fee_cap`, which its default 12M `ZKAPI_CHALLENGE_MAX_GAS`
   can raise (lower it toward 8M to clear them).
6. **API server, then challenger.** Stop both, back up the data directory,
   start the server first, check the log line
   `server signing keys match the vault's immutable keys` and the attestation
   keys (Before you start, item 4), then start the challenger and read its
   `/status`:

   ```sh
   dc stop challenger server
   sudo tar -C /var/lib -czf "/root/zkapi-legacy-before-phase0-$(date +%s).tgz" zkapi
   dc up -d --no-deps --wait server
   dc up -d --no-deps --wait challenger
   dc exec -T challenger curl -sS http://127.0.0.1:3002/status | jq '{status, alarms, config_warnings}'
   ```

   Set up the alerting of that line's Docker guide (its Monitoring section)
   before closing the window, and schedule online database backups.
7. **Settlement.** Every pre-upgrade lease receives a settlement deadline and
   finalizes by it, at worst at its solvency bound with an operator review.
   Within about TTL + grace + the deadline, every row of Before you start,
   item 6, must be `finalized`. Handle each review
   ([Settlement reviews](#settlement-reviews)).
8. **Owner policy for the legacy vault.** Its owner can still pause every new
   exit without a time limit while `claimExpired` and an instant `setTreasury`
   keep working, and a treasury that rejects ETH blocks every exit with an
   operator share. Publish and follow this policy for the rest of its life:
   never pause it (unpause it now if `paused()` is true); make no treasury
   change unless the treasury stops accepting ETH; move ownership to a
   multisig with `transferOwnership(address)`, which takes effect at once on
   a legacy vault (verify the multisig address on that chain first); never
   renounce ownership. Repeat the treasury check of Before you start, item 1,
   daily during the drain.

## Phase A: freeze, review and trusted setup

1. **Freeze** the circuits at a tagged revision (`circuit-freeze-v2c`) and
   record the constraint counts (request 23,990, withdrawal 28,772 at the
   current revision).
2. **External review** of the scope listed under the mainnet gates above.
   Fix forward on `main`; any circuit change returns to step 1.
3. **G-SETUP**, as written step by step in
   [the ceremony setup README](../protocol/setup/v2-concession/README.md):
   - export the R1CS (`export_r1cs`) and pass the fidelity gate
     (`r1cs_export_roundtrip`, `r1cs_negative_assignments`);
   - use a public powers of tau of at least 2^15 that is on
     `ceremony::PUBLIC_PTAU`, checked against its published Blake2b-512, and
     pin its SHA-256 before the ceremony starts;
   - at least three phase-2 contributions, at least two of them by parties
     the operator did not select, then a public random beacon fixed in
     advance. Short of contributors, mainnet slips: no single-party setup
     reaches mainnet or production Sepolia, and `Deploy.s.sol` refuses one
     there;
   - publish the transcript, `r1cs-manifest.json` and every hash; each
     external reviewer downloads the powers of tau from its public source,
     exports the R1CS themselves and runs `snarkjs zkey verify` on both
     circuits;
   - import with `import_zkey --setup-id mpc-1` into
     `protocol/setup/v2-concession`, which runs every gate before writing
     anything;
   - run the proving gate against the imported keys (`ZKAPI_SETUP_DIR=../setup/v2-concession`
     with the `proofs` and `reduction_cross_check` tests and both fixture
     generators) before publishing the keys.
4. **Pins, in the same change that commits the keys.** Set
   `CEREMONY_VK_KECCAK256` in `zkapi-proof/src/compact.rs` and run
   `cargo run --release -p zkapi-proof --bin release_policy_check` from
   `protocol/rust`; regenerate the adapter (`forge fmt` into
   `protocol/contracts/src/adapters`), the fixtures and the gas snapshot; and
   rebuild the WebAssembly with `bash scripts/build-browser-client.sh --setup mpc-1`,
   which also copies the keys into `sdk/assets/proofs/` and rewrites
   `sdk/assets/manifest.json`. Commit
   `protocol/setup/v2-concession/manifest.json`: `Deploy.s.sol` checks an
   `mpc-1` deployment against it. Then `npm run verify:wasm` must reproduce
   the WebAssembly byte for byte.
5. **Expected codehashes.** Publish the expected runtime code hashes of the
   vault, adapter and library for each deployment's constructor arguments,
   computed from source by `node scripts/expected-codehashes.mjs` (it takes
   the arguments as flags, or reads a deployment manifest with
   `--deployment`). Anyone can rebuild the Forge artifacts with the pinned
   compiler settings and audit a profile against them.

## Phase B: Sepolia

### B1. Drill vault

The drill vault tests the adversarial cases with short timings. It uses the
`dev` setup, so it is a drill only: its toxic waste is public.

1. Deploy with the drill parameters (table below), `SETUP_MANIFEST` pointing
   at `protocol/setup/v2-concession-dev/manifest.json` and `ALLOW_DEV_SETUP=1`
   (recorded as `allowDevSetup: true`; a profile built from it is a drill
   profile only). Deploy the gasless-withdrawal paymaster with it as in
   [B2, step 2](#b2-production-sepolia), with `PAYMASTER_ESCAPES=1`: the
   drill sponsors escape initiations, which no published profile does.
   Finalize the manifest as in [B2, step 3](#b2-production-sepolia).
2. Build drill binaries that load the `dev` keys, the server with the
   adversary modes, into their own target directory, as
   `scripts/run-v2-acceptance.sh` does, so that they never replace a release
   build in `target/release`:

   ```sh
   cargo build --locked --release --target-dir target/drill \
     --features zkapi-cli/adversary,zkapi-proof/dev-setup \
     -p zkapi-cli --bin zkapi -p zkapi-serverd --bin zkapi-challenged \
     -p zkapi-indexerd --bin zkapi-indexerd -p zkapi-companion --bin zkapi-walletd
   ```

   Build the drill browser client in a worktree of its own: the build writes
   the tracked `sdk/wasm`, `sdk/assets/proofs` and `sdk/assets/manifest.json`,
   which in the release checkout hold the `mpc-1` bundle of Phase A, step 4.
   Pin the drill vault in that worktree's Sepolia profile, then build:

   ```sh
   git worktree add --detach ../zkapi-drill HEAD && cd ../zkapi-drill
   npm ci                                             # this worktree's own node_modules
   node scripts/deployment-profile.mjs --finalized "$DRILL_MANIFEST" \
     --deployment-id zkapi-native-eth-sepolia-concession-drill-1 \
     --protocol-server-url https://DRILL_API_HOST --indexer-url https://DRILL_API_HOST \
     --verifier-url https://OA_VERIFIER_HOST --format sdk \
     --base sdk/assets/config/sepolia.json --out sdk/assets/config/sepolia.json
   bash scripts/build-browser-client.sh --setup dev   # the dev WebAssembly and keys
   npm run build:browser                              # dist/sdk-sepolia
   ```

   Never commit these builds or ship them: release binaries and the Docker
   image load only the ceremony keys and reject `--adversary`. The server's
   mode is chosen at start, `zkapi --adversary <mode> serverd ...`:
   `withhold` (settles every request but never signs its successor),
   `born-spent` (signs successors at anchor 1), `reuse-anchor`,
   `random-anchor`, `overcharge` (one unit above the bound), `lie-expired`
   (answers every expiry check `expired_unaccepted`) and `hang` (holds every
   connection, drips a byte every 5 seconds for up to 600 seconds, then
   answers 429 or 503 with `Retry-After: 86400`). Clients give up on each call
   after 20 seconds, so under `hang` an escape must still land before
   `must_initiate_by`.

   **Running the drill stack.** The Docker image refuses the `dev` keys, so
   run the drill binaries directly, each with
   `--proof-setup-dir protocol/setup/v2-concession-dev` (`ZKAPI_PROOF_SETUP_DIR`
   for `zkapi-walletd`) and the drill profile from
   `scripts/deployment-profile.mjs` (`--deployment`), in the production order:
   `zkapi-indexerd` from a fresh checkpoint at the drill vault's
   `deployBlock`; `zkapi --proof-setup-dir ... db init --deployment ... --db ...`
   on a fresh database; the signer sidecar
   (`node docker/aws/signer/server.mjs` with the variables of
   `docker/aws/signer.env.example`, its own key and
   `ZKAPI_CHALLENGE_VAULT` set to the drill vault); `zkapi-challenged` with
   `--deployment`, `--settlement-window-seconds 2105` and
   `--raise-lead-seconds 1800`; then `zkapi [--adversary <mode>] serverd`
   with `--deployment` and the drill lease timings. Restart serverd to change
   its mode. `scripts/v2-acceptance.mjs` starts exactly this stack on Anvil:
   read its `serverArgs`, `challengerArgs`, `indexerArgs` and signer
   environment for every flag.
3. Run the drills of design §10.7 B on it, each asserting the client's final
   state as well as balances: the honest flow; a withholding server
   (`--adversary withhold`) and the concession at `T`; `hang`, with the
   escape landing before `must_initiate_by`; `born-spent`, `reuse-anchor`,
   `random-anchor` and `overcharge`; `lie-expired`; gasless withdrawals
   (`fees: 'payout'`) through the operator's bundler: a close to a payout
   address with no ETH, a sponsored escape, its raise and its sponsored
   finalization, and a forced `success == false` (the two-operation bundle
   of [gasless release gate 3](#gasless-release-gates), sent from a funded
   account) collected by a sponsored forward; a forced early exit with
   `c = 0`, a raise to the charge, and the client state `closed`; an
   under-concession, its raise, a finalization to a destination that refuses
   ETH and the credit's claim; a stale escape defeated, `SupersededState`,
   and a re-escape from an older state defeated again; the stale-device
   pre-check; a replay after `valid_until`; a late successor and the switch;
   an ownership proof sent on chain (`WrongWithdrawalKind`); the indexer down
   and the rebuild from logs; a pause with an escape pending, a pause past
   `maxPauseDuration`, and the re-pause cooldown; a codehash-mismatch profile
   refusing deposits; and a missed defeat (challenger stopped) followed by
   `retireClosedLeaf`. There is no scripted Sepolia drill harness yet: run
   them with the drill binaries and record each result. The local acceptance
   ([`npm run test:e2e:v2`](v2-acceptance.md)) rehearses every one of them
   on Anvil, with the SDK, the companion or the wallet core as the client
   ([its scenario table](v2-acceptance.md#scenarios) names which). A drill
   that retires leaves more than twice a day needs
   `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY` raised in `signer.env`.

| Parameter | Mainnet | Sepolia production | Sepolia drill |
| --- | --- | --- | --- |
| `CHALLENGE_PERIOD_SECONDS` | 172,800 | 43,200 | 7,200 |
| `NOTE_TTL_SECONDS` | 2,592,000 (30 d) | 2,592,000 | 86,400 (1 d) |
| `MAX_PAUSE_DURATION_SECONDS` | 3,888,000 (45 d) | 604,800 (7 d) | 14,400 |
| `REQUEST_CHARGE_CAP` | 50,000 | 50,000 | 50,000 |
| Lease TTL / grace / settlement deadline / poll | 300 / 5 / 21,600 / 2 | 300 / 5 / 14,400 / 2 | 300 / 5 / 1,800 / 2 |
| `settlement_window_seconds` (`W`) | 21,905 | 14,705 | 2,105 |
| `ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS` | 21,600 | 21,600 | 1,800 |
| Settlement check (`≤ challengePeriod / 2`) | 22,509 ≤ 86,400 | 15,309 ≤ 21,600 | 2,709 ≤ 3,600 |
| Raise check (`≤ challengePeriod`) | 44,713 ≤ 172,800 | 37,513 ≤ 43,200 | 5,113 ≤ 7,200 |
| Setup | `mpc-1` | `mpc-1` | `dev` (`ALLOW_DEV_SETUP=1`) |

The settlement check is lease TTL + grace + deadline + 2 x poll + 600; the
raise check is `W` + raise lead + 4 x poll + 1,200. serverd refuses to
start when the settlement check fails and `zkapi-challenged` when either
fails; the vault's constructor requires `maxPauseDuration` of at least twice
the challenge period.

#### Gasless release gates

Gasless withdrawals have release gates. Pass them on the drill vault before
B2, step 5 generates any profile with `--bundler-url` (a published
`gasless.bundler_url`), and again before mainnet (Phase C, step 1). Until
they pass, generate the profiles without `--bundler-url` (`bundler_url` is
then `null`, and no client sponsors anything by default), and regenerate and
republish them once the gates pass.

1. **Validation gas.** The Forge suite's `RealAdapter.t.sol`
   (`test_realValidationGasFitsUnderTheCap`, run by CI's `forge test`)
   measures the paymaster's validation with the real Groth16 adapter, for
   the close and the escape shapes, cold and warm. It requires each cold
   measurement under `PM_VERIFICATION_CAP − 20,000`, each warm one below its
   cold one, and a cold/warm gap under 70,000 gas (about 15%: the cold
   storage and account accesses of the checks). The gap changes no outcome,
   because a bundler's simulations and the inclusion all run cold. The
   committed measurements are in `protocol/contracts/snapshots/gasless-gas.json`.
2. **A real bundler's tracer.** Run a v0.7 bundler with full ERC-7562
   validation (the reference bundler's `debug_bundler_*` mode or Rundler in
   debug mode) against the Anvil harness with the etched EntryPoint, send it
   the acceptance's sponsored close, escape, finalization and forward, and
   record zero rule violations with the bundler's version. The acceptance's
   mini bundler does not trace, and the Forge opcode audit
   (`test_opcodeAudit_*`) is not a bundler's.
3. **A public bundler on Sepolia.** On the drill vault, with a public v0.7
   bundler, `eth_sendUserOperation` is accepted and included and `Settled`
   is observed. Then force a `success == false` that the operator controls:
   build a sponsored close as the acceptance harness does (scenario 27),
   and send `handleOps([replay, sponsored])` from a funded account, where
   the replay is a self-funded operation that lands the close's public
   calldata on the vault first. The sponsored operation executes with
   `success == false` and `Stranded(S)`; recover it with a sponsored
   FORWARD sent through the public bundler, and observe its `Settled`. Do
   not force the failure by landing a replay ahead of an operation the
   public bundler holds: the bundler's second validation then fails
   (`NoteNotActive`, `AA33`), nothing executes, and GREP-040 lets that
   bundler ban the paymaster for the rest of the drill and for this gate's
   re-runs during the B4 soak.
4. **The canonical EntryPoint.** Before each broadcast, the `cast keccak`
   check of both runtimes in [B2, step 2](#b2-production-sepolia) matches.

### B2. Production Sepolia

The new deployment is a separate stack: new public manifest, hostname,
signer key, exclusive sender and data directory. Prefer a separate VM; to
share one, see [Two stacks on one VM](#two-stacks-on-one-vm).

1. **Keys.** Generate fresh state and clearance seeds into the new
   `server.env` and print the public keys
   ([Signing seeds](../docker/aws/README.md#signing-seeds)). Never reuse the
   legacy deployment's seeds.
2. **Deploy.** From `demo/contracts`, run `Deploy.s.sol` with `OWNER` (a
   multisig, ideally behind a timelock), `TREASURY`, the four key
   coordinates, the Sepolia production parameters,
   `SETUP_MANIFEST=../../protocol/setup/v2-concession/manifest.json`,
   optionally `POSEIDON_ADDRESS` (an existing library with the compiled
   codehash) and `CHAIN_ID=11155111`; see [the contract notes](deployment.md#contracts).
   The script checks the keys, links the library, deploys the adapter and
   the vault with 11 constructor arguments, checks the adapter's
   `CIRCUIT_ID_HASH()` and verifying-key hashes against the setup manifest,
   and writes only the provisional manifest `$OUTPUT_PATH.pending`.

   In the same broadcast it deploys the gasless-withdrawal paymaster
   (`GASLESS=1`, the default; see
   [the contract notes](deployment.md#gasless-withdrawals)). Set
   `PAYMASTER_OWNER` (the multisig; when it is not the deployer it must call
   `acceptOwnership()` on the paymaster), `PAYMASTER_STAKE_WEI` and
   `FACTORY_STAKE_WEI` (0.1 ETH on Sepolia, 1 ETH on mainnet),
   `PAYMASTER_DEPOSIT_WEI` (1 ETH on Sepolia, 2 ETH on mainnet),
   `PAYMASTER_MAX_FEE_CEILING_WEI` (200 gwei on Sepolia) and leave
   `PAYMASTER_ESCAPES` at 0. Etch nothing on a public chain: the canonical
   EntryPoint v0.7.0 and its SenderCreator are deployed there. Check their
   code before the broadcast, as the script and the paymaster's constructor
   will:

   ```sh
   cast keccak "$(cast code 0x0000000071727De22E5E9d8BAf0edAc6f37da032 --rpc-url "$RPC_URL")"
   # 0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58
   cast keccak "$(cast code 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C --rpc-url "$RPC_URL")"
   # 0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689
   ```
3. **Finalize the manifest** once the vault's creation is final:

   ```sh
   node scripts/expected-codehashes.mjs --deployment "$OUTPUT_PATH.pending" \
     --rpc "$RPC_URL" --finalize "$OUTPUT_PATH" --confirmations 64
   ```

   It reads the creation receipts from forge's broadcast log
   (`demo/contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json`, or
   `--broadcast-log`), checks every creation, the three runtime codehashes,
   the owner and the treasury on chain (with the paymaster: the eight
   codehashes, its deposit, both stakes, its policy, ceilings, gas policy and
   owner), and only then writes `$OUTPUT_PATH`
   with `deploymentStatus: "deployed"`, `deployBlock` (the vault's creation
   block) and `deployTransactions`. Keep the broadcast log until then: there
   is no fallback without it. Re-audit later with
   `node scripts/expected-codehashes.mjs --deployment "$OUTPUT_PATH" --check --rpc "$RPC_URL"`.
4. **Post-deploy checks** (`NEW_VAULT` is the manifest's `vault`):

   ```sh
   for getter in 'owner()(address)' 'pendingOwner()(address)' 'treasury()(address)' 'paused()(bool)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'maxPauseDuration()(uint64)' \
       'requestChargeCap()(uint128)' 'PROTOCOL_VERSION()(uint16)' 'CONCESSION_ESCAPE_VERSION()(uint16)' \
       'ROOT_HISTORY_WINDOW()(uint64)' 'PAUSE_COOLDOWN()(uint64)' 'ESCAPE_PAYOUT_GAS()(uint256)' \
       'proofAdapter()(address)'; do
     printf '%s ' "$getter"; cast call "$NEW_VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   ADAPTER=$(cast call "$NEW_VAULT" 'proofAdapter()(address)' --rpc-url "$RPC_URL")
   for getter in 'CIRCUIT_ID_HASH()(bytes32)' 'REQUEST_VK_HASH()(bytes32)' 'WITHDRAWAL_VK_HASH()(bytes32)'; do
     printf '%s ' "$getter"; cast call "$ADAPTER" "$getter" --rpc-url "$RPC_URL"
   done
   ```

   Expect `owner()` the multisig and `pendingOwner()` zero,
   `PROTOCOL_VERSION` 2, `CONCESSION_ESCAPE_VERSION` 1,
   `ROOT_HISTORY_WINDOW` 86400, `PAUSE_COOLDOWN` 86400,
   `ESCAPE_PAYOUT_GAS` 100000, `CIRCUIT_ID_HASH`
   `0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687`
   (keccak256 of `zkapi-v2-concession-v1`), and the VK hashes of
   `protocol/setup/v2-concession/manifest.json`. Compare the four key getters
   with the printed keys as numbers, and the codehashes with the published
   expected values. Then read the paymaster's state:
   `node scripts/paymaster-status.mjs --deployment "$OUTPUT_PATH" --rpc "$RPC_URL"`
   must show the deposit and both stakes, the policy with `escapes_enabled`
   false, the ceilings, `owner` the multisig (or `pending_owner` until it
   accepts) and nothing lost or owed.
5. **Profiles.** Every consumer takes its pins and `deploy_block` from the
   finalized manifest only, never from `.pending` or `deployBlockLowerBound`.
   Generate them with `scripts/deployment-profile.mjs`, which refuses a
   pending or simulated manifest, checks that the setup directory's
   verifying keys are the vault's, and writes the four signing-key
   coordinates as `0x` hex (the manifest holds decimal strings, and
   serverd, `zkapi db init` and clientd parse hex only):

   ```sh
   PROFILE_ARGS=(--finalized "$OUTPUT_PATH" --deployment-id zkapi-native-eth-sepolia-concession-v1
     --protocol-server-url https://API_HOST --indexer-url https://API_HOST
     --verifier-url https://OA_VERIFIER_HOST --bundler-url https://BUNDLER_HOST)
   node scripts/deployment-profile.mjs "${PROFILE_ARGS[@]}" --rpc-url "$PINNED_RPC_URL" \
     --price-feed 0x694AA1769357215DE4FAC081bf1f309aDC325306 --settlement-window-seconds 14705 \
     --out deployment.json
   node scripts/deployment-profile.mjs "${PROFILE_ARGS[@]}" --format sdk \
     --base sdk/assets/config/sepolia.json --out sdk/assets/config/sepolia.json
   node scripts/deployment-profile.mjs "${PROFILE_ARGS[@]}" --format clientd \
     --base zkapi-clientd/internal/zkapi/deployments/sepolia.json \
     --out zkapi-clientd/internal/zkapi/deployments/sepolia.json
   ```

   - `deployment.json` is `{"trusted_deployment": ...}`, the server stack's
     `/etc/zkapi/deployment.json`.
   - The SDK profile keeps its browser fields and takes the RPC, price feed
     and settlement window of the file it replaces.
   - clientd's file keeps its own names: `challenge_period_seconds`,
     `note_ttl_seconds`, `max_pause_duration_seconds`,
     `settlement_window_seconds`, `deployment_evidence.{vault,adapter,poseidon}_runtime_keccak256`,
     `proof_setup.*` and `privacy_mode.verifier_url`.
   - `deployment_id` must be new: never a legacy ID (they contain
     `note-bound`, and the script refuses them). Both browser builds keep
     their wallets in one store keyed by it.
   - On mainnet, add the canary with `--canary '{"per_note_max_wei": ..., "aggregate_max_wei": ..., "until": ...}'`.
   - Every format carries the `gasless` object (the EntryPoint, paymaster,
     factory and account pins, the gas policy, `bundler_url`); serverd, the
     indexer and the challenger ignore it.

   Pass `--bundler-url` only once the
   [gasless release gates](#gasless-release-gates) have passed. Without it
   the profiles carry `gasless` with `bundler_url: null`; regenerate them
   with it, and republish, after the gates.

   Review the three diffs. Write a profile by hand only with the script's
   rules: decimal coordinates written as `0x` hex (`cast to-hex`), a new
   `deployment_id`, and clientd's names above.
6. **Stack.** Configure it from [the Docker guide](../docker/aws/README.md)
   with the Sepolia values of
   [`deployment.env.example`](../docker/aws/deployment.env.example): the new
   `VAULT_ADDRESS` and `DEPLOY_BLOCK`, a signer with a new private key and
   `ZKAPI_CHALLENGE_VAULT` set to the new vault, a new funded sender, the
   transaction fee cap in `signer.env` and `deployment.env`,
   `ZKAPI_CHALLENGE_RETIRE_ON_MISS` equal in both files, and no
   `ZKAPI_ALLOW_LEGACY_CLEARANCE` (serverd refuses it). Fund the sender for
   `⌈m/2⌉` defeats per note (a user holding `m` archived states can force that
   many), at most 64 concurrent escapes and a 20% margin, plus leaf
   retirements: at 100 gwei, about 0.06 ETH per defeat and 0.72 ETH per
   retirement. Run the operator's ERC-4337 bundler at `BUNDLER_HOST` with the
   paymaster and the factory whitelisted, as
   [Operating gasless withdrawals](deployment.md#operating-gasless-withdrawals)
   describes.
7. **Start in this order:** the indexer from `DEPLOY_BLOCK`, `zkapi db init`
   (the `db-init` service), the challenger, the API server, then the
   gateway that publishes it (`up` never starts the services that depend on
   the ones it names, so the gateway needs its own line).

   ```sh
   dc up -d --wait indexer
   dc run --rm db-init
   dc up -d --wait challenger
   dc up -d --wait server
   dc up -d --wait gateway
   ```

   `zkapi db init` creates the schema, the append-only `request_evidence`
   table and the `deployment_binding` row; the challenger refuses a database
   without it ("run `zkapi db init` first"). Use a fresh data directory, never
   a copy of the legacy one: `zkapi db init` and serverd read the recorded
   binding before they migrate anything, and refuse a database bound to
   another deployment, including the legacy vault's, and one whose binding
   cannot be read. Each daemon refuses a placeholder or provisional
   manifest, and checks the vault, the adapter and the library against it.
   **The challenger must be healthy, with its alerting armed, before the
   first deposit.**
8. **Acceptance.** Run the Docker guide's acceptance checks: `/health` and
   `/v1/attestation` report `circuit_id` `zkapi-v2-concession-v1`,
   `setup_id` `mpc-1`, `exit_concession` 1 and the deployment's
   `settlement_window_seconds`; the server log shows
   `the vault, adapter and Poseidon library match the deployment manifest`.
   Then a funded lifecycle on Sepolia: deposit, a paid request, a mutual
   close (which sends a kind-2 ownership proof), an escape with `c = 0` from a
   fresh state, and an escape from a served state that the challenger raises.
   Then a gasless close (`fees: 'payout'`) to a payout address with no ETH
   through the operator's bundler: the paymaster's `Settled` pays it the
   payout less the charge, and the float does not shrink.

### B3. Publish clients for Sepolia

- **New browser build.** Pin the deployed profile in
  `sdk/assets/config/sepolia.json`, run
  `node scripts/sync-sdk-assets.mjs --setup mpc-1 --network sepolia`, then
  `npm run verify:assets` and `npm run build:browser`. Hosts serve it at
  `/zkapi/v2c/` on the same origin as the legacy build
  ([Side-by-side browser builds](#side-by-side-browser-builds)).
- **Legacy Sepolia re-cut** with `"deposits": "closed"`
  ([Phase E, step 1](#phase-e-drain-and-retire-the-legacy-vault)).

### B4. Soak

Run production Sepolia for at least 14 days with weekly drills on the drill
vault. Watch every alert of the Docker guide's Monitoring section, the raise
and defeat counters, the settlement dashboard's `exit_deferred` and
`exited_unsigned` counts, and the paymaster's alerts
([Operating gasless withdrawals](deployment.md#operating-gasless-withdrawals)).

The [gasless release gates](#gasless-release-gates) passed before B2
generated a profile with a `bundler_url`. Re-run gate 3 on the drill vault
during the soak, and all four again before mainnet.

## Phase C: mainnet

1. **Deploy** with the mainnet parameters, as in B2, steps 1 to 4
   (`CHAIN_ID=1`; `Deploy.s.sol` refuses a `dev` setup there). Re-check both
   canonical EntryPoint codehashes on mainnet with `cast code | cast keccak`
   before the broadcast (B2, step 2; [gasless release gate](#gasless-release-gates) 4),
   and pass gates 1 to 3 again for the mainnet build before its profiles
   carry `--bundler-url`.
   Finalize with `--confirmations 64` and publish the manifest and the
   expected codehashes.
2. **Start the daemons** in the order of B2, step 7.
3. **Smoke tests with small notes:** deposit, request, settle, mutual close;
   an escape with `c = 0` from a fresh state, then finalize; a served
   request, then a deliberate escape with `c = 0`, which the challenger
   raises to the charge, then finalize, and check that the client state is
   `closed`.
4. **Publish the new mainnet build with the canary for 30 days.** The
   profile's `canary` caps a note at 0.25 ETH (`per_note_max_wei`) and the
   vault's balance at 25 ETH (`aggregate_max_wei`) until `until`; the server
   runs with `ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS=6000000` (recommended
   permanently). The SDK caps protect honest SDK users; direct depositors
   bypass them. Build with `node scripts/sync-sdk-assets.mjs --setup mpc-1 --network mainnet`,
   `npm run verify:assets` and `npm run build:mainnet`, which refuses
   anything but an `mpc-1` bundle. In the same host release, publish the
   legacy mainnet re-cut with `"deposits": "closed"` and close the legacy
   deposit routes at the gateway (Phase E, step 1). That moment is **day 0**
   of [the 30-day transition](#the-30-day-transition-for-existing-users):
   record `N_C` and `X` as described there.
5. **Announce day 0, the legacy cutoff `X`** (the last transition note's
   expiry, before day 31) **and the sweep policy** at least 14 days before
   day 0, and repeat them at day 0. Each owner's own deadline is their note's
   expiry.
6. **Users.** New users deposit into the new vault. Browser users with a
   legacy note are routed to the legacy build to close it, then deposit.
   A legacy note with a request in flight waits for its settlement: publicly
   commit to finalizing every legacy lease and to running the legacy
   challenger until retirement.

## Phase D: clientd releases

1. **Legacy point release 0.1.7 first.** It is on `release/v2-note-bound`:
   deposits closed (`deposits_closed`; a deposit signed earlier still
   activates), `withdraw --escape` for a fresh, settled state with its
   finalization and payout match, and the runbook
   `zkapi-clientd/docs/LEGACY_ESCAPE.md`. Push the branch, tag
   `clientd-v0.1.7`, package it, and run its Sepolia drill (a fresh-state
   escape, its finalization, and a refused deposit). Then check its record,
   `zkapi-clientd/packaging/releases/clientd-0.1.7.json`, into `main`:
   `scripts/assemble-release.py` refuses to assemble any other release until
   that file exists, because the new release's warnings name 0.1.7.
2. **New release.** Pin the deployed profiles in
   `internal/zkapi/deployments/*.json` (replacing the `not_deployed`
   placeholders), move `ZKAPI_SOURCE_COMMIT` in `packaging/zkapi-source.env`
   to a commit pushed to the public repository that holds every companion,
   protocol and `Cargo.lock` change, run `scripts/test-companion.sh` on a tree
   from `scripts/prepare-zkapi.sh` (with Foundry on `PATH`, so the companion's
   Anvil test runs) and the Go suite, run a Sepolia drill of its escape
   route, then release it. It reports `bridge_version` 5 and
   `exit_concession` 1, warns about an open legacy wallet without refusing to
   start, and keeps its payment state per deployment.
3. **Users** close their legacy note with 0.1.7 (mutual close, or
   `withdraw --escape` from a settled state), upgrade, and deposit. Tell them
   that 0.1.7 refuses deposits, and that the new release never opens the
   legacy wallet directory.

## Phase E: drain and retire the legacy vault

1. **Legacy re-cut and deposit routes (day 0).** Do this in the same change
   window as the new vault's go-live (Phase C, step 4). The re-cut, for each network, from `release/v2-note-bound`: the same
   WebAssembly, worker and key bytes, with only the profiles changed to
   `"deposits": "closed"` in `trusted_deployment` (and
   `"clearance_ownership_proof": "optional"` if not set yet). On that branch,
   regenerate the config hashes (`node scripts/sync-sdk-assets.mjs`), check
   them (`npm run verify:assets`), build (`npm run build:browser`,
   `npm run build:mainnet`), and tag it with the legacy line's next patch
   version, `v0.1.<n>` (0.1.7 is the clientd point release; the first re-cut is
   `v0.1.8`; see [versioning](versioning.md)). It keeps the
   existing `publicPath`. The runtime fetches `browser-config.json` with
   `cache: 'no-store'`, so a host that serves the new file reaches every
   loaded tab; confirm that every host serves this revision. The SDK then
   refuses a new deposit with `409 deposits_closed` before any chain read or
   wallet prompt, and a deposit already started stays completable. Builds
   older than the legacy line ignore the flag: hosts remove their deposit
   action. `zkapi-clientd` deposits stop with 0.1.7; to stop older clientd
   releases too, have the legacy gateway answer 410 on the two deposit-only
   routes, `/v1/tree/next-note-id` and `/v1/tree/notes/{id}/zero-path`
   (the legacy challenger reads zero-paths from the internal indexer, not
   through the gateway):

   ```nginx
   # Deposit cutoff: the drained vault no longer offers new deposit paths.
   location = /v1/tree/next-note-id { return 410; }
   location ~ ^/v1/tree/notes/[0-9]+/zero-path$ { return 410; }
   ```

   Put it before `location /v1/tree/` in the `nginx.conf` of the legacy
   checkout, build the legacy gateway under a new legacy `ZKAPI_IMAGE_TAG`,
   and recreate it. Never pause the legacy vault to stop deposits; anyone can
   still deposit directly, and such notes drain like any other. Then read
   `N_C` and `X` as in [the 30-day transition](#the-30-day-transition-for-existing-users)
   and publish them.
2. **From `X`: close legacy admission at the gateway.** `X` is the expiry of the
   last transition note (note `N_C - 1`), before day 31, so no owner who acted
   in time loses service. The design closes legacy admission at `X`
   (`--admission closed`, refusing new requests with `deployment_retiring`). The legacy serverd has no such switch, so the
   legacy gateway refuses new requests instead. `POST /v2/openrouter/leases`
   is the only route that admits a request; in the `nginx.conf` of the legacy
   checkout, replace its `location = /v2/openrouter/leases` block with:

   ```nginx
   # From X: no new request is admitted. Lease status, retirement and expiry
   # (/v2/openrouter/leases/{id}...), recovery and clearance stay open.
   location = /v2/openrouter/leases {
       default_type application/json;
       add_header Cache-Control "no-store" always;
       add_header Access-Control-Allow-Origin "*" always;
       return 410 '{"status":"error","client_request_id":"","error_code":"deployment_retiring","error_message":"This zkAPI deployment no longer admits requests. Withdraw the balance.","retriable":false}';
   }
   ```

   Build the legacy gateway under a new legacy `ZKAPI_IMAGE_TAG` and
   recreate it, as for the deposit cutoff of step 1. Check that
   `curl -s -o /dev/null -w '%{http_code}\n' -X POST "$API_URL/v2/openrouter/leases" -H 'content-type: application/json' -d '{}'`
   prints 410 while `curl -fsS "$API_URL/health"` still answers. The legacy
   serverd publishes no port of its own: the gateway is its only entrance.

   **Do not skip this step.** Deposits stay permissionless (step 1), so
   notes are still created after `X`. A note deposited at `X + k` could
   otherwise buy service until its own expiry, `X + k + noteTtl`, after the
   retirement bound of step 6. Once the legacy challenger stops, its owner
   could escape from the genesis state, which nothing then defeats, and be
   paid the whole deposit after consuming service. If admission closed later
   than `X`, count step 6's bound from the moment it closed. In-flight leases
   still settle, clearances for fresh nullifiers stay available, and the
   legacy challenger keeps running.
3. **Drain monitoring.** Track the legacy notes daily (Before you start, items
   1 and 2): notes by status, pending escapes, `nextNoteId()` for late direct
   deposits, and whether the treasury still accepts ETH. Anyone can finalize
   an escape after its deadline, which also pays the treasury, so finalize
   those their owners leave pending, simulating first:

   ```sh
   cast call "$VAULT" 'finalizeEscapeWithdrawal(uint32)' <noteId> --rpc-url "$RPC_URL"
   cast send "$VAULT" 'finalizeEscapeWithdrawal(uint32)' <noteId> \
     --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
   ```

   On a legacy vault, a simulation that reverts `0xf4b3b1bc`
   (`NativeTransferFailed()`) while the treasury check still passes means the
   escape's destination rejects ETH: that escape cannot finalize until the
   destination accepts ETH. Record its note ID, destination and final
   balance, announce it through the hosts, and keep simulating it, also after
   retirement. Anyone, the owner included, can finalize it without a zkAPI
   client once the destination accepts ETH, as long as the treasury does too.
4. **Expired notes.** A legacy note can still exit after its expiry until
   someone calls `claimExpired`, which pays the full deposit to the
   treasury. Announce the expiry dates early, and publish in advance what the
   operator does with deposits it claims (for example, a refund on request
   outside the protocol).
5. **Disable legacy clearance** once the legacy re-cut and 0.1.7 are adopted
   and owners of older releases were warned. In the 30-day transition, decide
   on day 14 and again on day 21, switch it off only if the count below is 0,
   and never in the last 7 days before `X`: an owner of an older release has no
   time left to move then. Remove
   `ZKAPI_ALLOW_LEGACY_CLEARANCE` from the legacy `deployment.env`, recreate
   the legacy server, and check that `/health` reports
   `clearance_ownership_proof_required: true` and
   `legacy_clearance_window_limit: 0`. Before that, count recent proof-less
   reservations:

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT count(*) FROM nullifiers WHERE status = 'ClearanceReserved' AND clearance_auth = 'legacy' AND created_at > strftime('%s', 'now', '-7 days');"
   ```

   `zkapi-clientd` 0.1.6 and earlier cannot withdraw afterwards. A legacy
   browser build cannot mutual-close a state whose request proof left the
   device and never settled; such an owner exits after a chat from that state
   settles.
6. **Retire the legacy stack** when every transition note (ID below `N_C`) is
   `Closed` or swept, no late note (ID of at least `N_C`) deposited before `X`
   is still `Active`, and the last challenge deadline has passed. With no late
   note that is about day 32: `X` plus the 24-hour `challengePeriod`. With late
   notes it is at most `X` + `noteTtl` + `challengePeriod`, before day 63
   (the older form of the bound, `X` + `noteTtl` + pauses + post-challenge
   grace + `challengePeriod`, has two more terms that are zero on the deployed
   vaults: the owner never pauses them and they have no grace), with `X` the
   moment admission closed (step 2). Notes
   deposited after that moment hold only their genesis state, because the
   gateway admitted no request for them, so they need no challenger; they
   exit at their deposit by escape (the legacy build or 0.1.7) or are swept
   at expiry, as announced. An escape
   stuck on a destination that rejects ETH (step 3) does not block retirement
   once its deadline has passed. Then, with the legacy deployment's `dc`:
   stop the challenger and signer and move the sender's balance; stop the
   server, indexer and gateway and remove the legacy origin; archive the data
   directory as sensitive data (it holds request proofs and transcripts);
   keep the legacy SDK bytes, keys and client releases available.

## Side-by-side browser builds

There is no multi-circuit loader. A host serves the legacy build at its
existing `publicPath` (`/zkapi/`) and the new build at `/zkapi/v2c/` on the
same origin. Both share IndexedDB `zkapi-browser-wallet-v1` (version 3) and its
Web Lock; each runtime refuses a runtime slot holding the other deployment's
note, and neither rewrites the other's records.

- The host lists two package entries, `zkapi-sdk-legacy` (`#v0.1.<n>`)
  and `zkapi-sdk` (`#v0.2.<n>`); each resolves its own WebAssembly, keys and
  worker.
- A small loader calls `readBrowserWalletHoldings()` from the store export and
  `import()`s the legacy entry while a legacy runtime holds an open note, and
  the new entry otherwise. A legacy withdrawal still open while the runtime
  slot is empty (a set-aside close or a pending escape) needs the legacy
  build; it cannot load while the new runtime holds a note. One SDK runs per
  page: switching builds reloads the page.
- [`examples/sample-host`](../examples/sample-host/README.md) builds both and
  holds that loader; `sdk/test/sample-host.test.mjs` and
  `sdk/test/browser-wallet-coexistence.test.mjs` test it.
- Do not offer a deposit while `snapshot().config.other_deployment_withdrawals`
  is non-empty. The exception is a legacy escape announced as stuck on a
  destination that rejects ETH (Phase E, step 3): show the owner its note ID
  and how to finalize it on chain. Never clear site data to get past these
  checks.
- Hosts that route protocol calls through a same-origin rewrite need one for
  the new hostname too.

See [Moving to a newly pinned deployment](../sdk/README.md#moving-to-a-newly-pinned-deployment)
and [Two builds on one origin](../sdk/README.md#two-builds-on-one-origin).

## Two stacks on one VM

Prefer a separate VM per deployment. On one VM, run the legacy deployment as a
second Compose project with its own configuration directory, data directory,
HTTP port and image tag, as in
[Upgrades and running two deployments](../docker/aws/README.md#upgrades-and-running-two-deployments).
Stop all of its services to move it, then use, for every legacy command:

```sh
dc() { sudo docker compose -p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi-legacy API_URL=http://127.0.0.1:8081
```

Run that project from a checkout of `release/v2-note-bound` and the new one
from `main`: the images differ, and the gateway image contains its checkout's
`nginx.conf`. Never repoint the legacy signer or challenger at the new vault.

## Operations runbooks

These apply to the concession vault (`NEW_VAULT`) unless they say otherwise.
The commands assume a key in a Foundry keystore (`--account`); a Safe submits
the same calls as Safe transactions.

### Pause

`pause()` blocks `deposit`, `claimExpired`, `setTreasury`, `acceptTreasury`,
`withdrawTreasuryArrears` and `renounceOwnership` until `unpause()`. It blocks
`initiateEscapeWithdrawal` and `mutualClose` for at most `maxPauseDuration()`:
from `pausedAt() + maxPauseDuration()` they reopen while still paused.
Defeats, raises, `finalizeEscapeWithdrawal`, `claimEscapePayout`,
`retireClosedLeaf`, `cancelTreasuryChange`, `transferOwnership` and
`acceptOwnership` stay open. A new pause needs `PAUSE_COOLDOWN()` (one day)
since the latest unpause (`PauseCooldown()` otherwise). Paused time extends
every note's claim time, and after any unpause `claimExpired` waits at least
`unpauseClaimGrace()`. A pause does not move pending escapes' deadlines: the
challenger must still act in each window, which it can while paused. Alert on
`Paused` and `Unpaused`.

The gasless paymaster refuses sponsored closes and escape initiations for as
long as the vault is paused (`ExitsPaused(reopenAt)`), even after
`maxPauseDuration`: its validation cannot read the clock. Clients refuse them
before proving (`exits_paused`). Users who exit while paused use the wallet
path. Sponsored finalizations and forwards stay open.

### Treasury change

```sh
cast send "$NEW_VAULT" 'setTreasury(address)' "$NEW_TREASURY" --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast call "$NEW_VAULT" 'pendingTreasuryReadyAt()(uint64)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'totalPausedDuration()(uint64)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'acceptTreasury()' --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast send "$NEW_VAULT" 'cancelTreasuryChange()' --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
```

`pendingTreasuryReadyAt()` is on the active clock (wall time minus paused
time): while unpaused, `acceptTreasury()` succeeds from
`pendingTreasuryReadyAt() + totalPausedDuration()`, and every later pause
pushes that further. A scheduled change gives users at least
`treasuryChangeDelay()` of unpaused time to exit. On a legacy vault
`setTreasury` takes effect at once; follow the Phase 0 owner policy.

### Owner key rotation

Ownership moves in two steps on the concession vault, both open while paused:
`transferOwnership(address)` nominates (`OwnershipTransferStarted`) and the
nominee calls `acceptOwnership()` (`OwnershipTransferred`). Until then the old
key keeps every power and can replace or cancel the nomination
(`transferOwnership(address(0))`). Alert on any `OwnershipTransferStarted` you
did not send.

If the current owner key may be compromised, never send the nomination alone
through the public mempool. Sign both transactions in advance and submit them
together, nomination first, as one bundle to a block builder's private bundle
endpoint (`eth_sendBundle`), so that they land consecutively in one block or
not at all; a Safe nominee's transaction is a pre-signed `execTransaction`
calling `acceptOwnership()`. Otherwise prepare the acceptance, then:

```sh
cast send "$NEW_VAULT" 'transferOwnership(address)' "$NEW_OWNER" --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast send "$NEW_VAULT" 'acceptOwnership()' --rpc-url "$RPC_URL" --account "$NEW_OWNER_ACCOUNT"
cast call "$NEW_VAULT" 'owner()(address)' --rpc-url "$RPC_URL"          # the new owner
cast call "$NEW_VAULT" 'pendingOwner()(address)' --rpc-url "$RPC_URL"   # zero
```

### Treasury arrears

`TreasuryPaymentDeferred` means a treasury payout failed and was kept in
`treasuryArrears()` (gwei). Fix the treasury (it must accept ETH within
100,000 gas), then anyone can pay it out while unpaused:
`cast send "$NEW_VAULT" 'withdrawTreasuryArrears()' --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"`.

### Escape payout credits

`EscapePayoutDeferred(noteId, destination, amount)` means an escape closed but
its push to `destination` failed (it rejected ETH or needed more than 100,000
gas). The amount waits in `escapePayoutCredits(destination)`. The browser SDK
reports an escape it started as credited and offers the claim, and
`zkapi-clientd` shows the claim (`withdraw --claim`); other owners learn of it
only from you, so announce each credit with its note ID and destination
through the hosts. Anyone can deliver it, also while paused, and only
`destination` is paid:

```sh
cast call "$NEW_VAULT" 'escapePayoutCredits(address)(uint128)' <destination> --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'claimEscapePayout(address)' <destination> --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
```

The claim forwards all gas; it reverts and keeps the credit while the
destination still rejects ETH. Legacy vaults have no credits (Phase E, step 3).

### Missed defeat or raise

The challenger records a **missed defeat** when an escape finalized although
verified request evidence at its successor nullifier existed before its
deadline, and a **missed raise** when an escape finalized with a concession
below what the server was owed. Each logs `MISSED escape deadline`
(`missed="defeat"` or `missed="raise"`), stays a critical alarm for an hour,
and counts in `escapes_finalized_with_successor_evidence_total` or
`missed_raises_total`. After a missed defeat, with `--retire-on-miss` (the
default, and `ZKAPI_CHALLENGE_RETIRE_ON_MISS` in both `deployment.env` and
`signer.env`), the challenger retires the closed note's leaf with
`retireClosedLeaf`, so the server, which admits only requests at the current
root, refuses every later proof built on that note. The obligation shows
`retiring_leaf` until the retirement mines; it needs the indexer's path at
the live root, about 7.2M gas, and the signer's retirement budget
(`ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY`, default 2 per rolling day, counted
per nonce). A refusal shows as `signer_refused`, and the signer's
`challenge_refused` line names its reason:

- `retirement_budget_exhausted`: raise `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY`
  in `signer.env` and recreate the signer (repeated root races spent it);
- `retirement_not_after_escape` after an outage longer than
  `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS` (about seven days): raise the
  lookback past the escape's finalization and recreate the signer;
- `retirement_in_flight`: an earlier retirement of the note may still mine;
  if it persists, the daemon or its upstream misbehaves;
- `retirement_disabled`: set `ZKAPI_CHALLENGE_RETIRE_ON_MISS` to the same
  value in both files.

The operator's loss keeps growing until the retirement mines. A miss means
the challenger was down, blocked or out of funds through a whole window: find
the cause before the next deadline (see
[the signer's refusals](challenge-service.md#the-signers-retirement-budget)).

### Settlement reviews

Alert on `settlement required operator review`, list open reviews, handle
each and acknowledge it by its `review_id`, as in the
[Docker guide](../docker/aws/README.md#monitoring). A `binding_corrupt` review
means a lease row and its reservation disagree, and the server signs nothing
for it until the operator repairs and reopens it with
`zkapi settlement reopen`, as in
[Reopening a cancelled lease](native-eth-billing.md#reopening-a-cancelled-lease).
On the concession vault its owner is not stranded meanwhile: the request stays
unresolved, so the owner's client escapes at its time `T` conceding the
state's bound, which already covers the most the challenger could raise to.
Reopening lets the owner install the real successor instead.
On a legacy vault a reserved nullifier leaves most owners without an exit
(legacy browser builds refuse to escape there, and the server grants no
clearance), so reopen such a lease before its note expires.

### Receipt journal missing (legacy vault)

A legacy client that reports `receipt_journal_missing` holds a note whose
current nullifier the server finalized for a request the client cannot apply,
usually one an older client discarded. The remedy, turning that `Finalized`
row into a clearance reservation, rests on the owner's word and can cost up
to the note's whole balance at that state. It is documented, with its
conditions and the one tested statement, in the copy of the earlier guide on
`release/v2-note-bound` (Operations runbooks, "Receipt journal missing").
Grant it only before legacy clearance is disabled (Phase E, step 5). The
concession vault needs no such remedy: an owner who lost a response escapes
conceding `min(charge, bound)`.

### Indexer divergence

Follow [Indexer resync](../docker/aws/README.md#indexer-resync). On the
concession vault, escapes, defeats, raises, closes and expiry claims change no
leaf, so the indexer's `/v1/escapes/pending` is not covered by its root check
at all: it is a hint. The challenger tracks escapes from its own event scan
and reads `pendingWithdrawals` and `pendingConcessions` from the vault, and a
defeat or a raise needs no indexer. A diverged indexer still blocks deposits,
leaf retirements, the server's admission (`root_unavailable`) and clients
without a saved deposit-time path or an exit RPC for a log rebuild.

### Gasless withdrawals

The paymaster's runtime (bundler, float, fee ceilings, metrics, alerts) is in
[Operating gasless withdrawals](deployment.md#operating-gasless-withdrawals).
The owner (the multisig) holds these levers:

- **Stop sponsoring:** `setPolicy` with `sponsorshipPaused: true` (the
  current values otherwise unchanged). New operations fail validation within
  a block, and are never charged. Users keep the wallet path.
- **Release a key:** `release([key])` after an operation was included and
  reverted, for a user who must retry the same state sponsored. The key is
  `keyFor(kind, nullifier, noteId, sender)`. An operation the bundler held, or
  one that failed on-chain validation, never consumed an attempt.
- **A balance stranded without evidence** (a close replayed on the vault
  before any sponsored operation): `allowForward(S)` lets the user's
  sponsored forward collect it. Otherwise anyone can `S.sweep()` it from a
  funded account.
- **A defeated escape's debt:** `writeOffDebt(S)` once the note has closed
  elsewhere. It changes accounting only.
- **Fees and limits:** `setFeeCeilings` (owner or `feeKeeper`) moves the fee
  ceilings anywhere up to the immutable hard caps (500 gwei and 20 gwei), and
  `setCallCap` (owner) moves each kind's call cap between its floor and its
  hard cap. Lowering them narrows what is sponsored; raising them widens the
  float's exposure (a higher `priorityFeeCeiling` raises a griefing
  bundler's gain linearly). The `feeKeeper` can therefore raise the ceilings
  to the hard caps: protect it like a key that sets risk policy.
  `deposit()` (anyone) and `withdrawTo` move the float.

**Retire** a paymaster in this order:

1. `setPolicy` with `escapesEnabled: false` (the published default), so no
   new escape debt is recorded, and keep the profiles' `gasless` pins
   published for now: a sponsored operation for an existing record (the
   FORWARD of a collect, a sponsored FINALIZE, a new, re-sent or re-signed
   operation of a sponsored close or escape) needs the current pins to name
   the record's paymaster and factory, so sponsored recovery ends with the
   pins. New closes stay
   sponsored meanwhile; each settles inside its own operation and adds no
   debt.
2. Keep sponsoring until `paymaster-status.mjs` shows `open_owed` and
   `stranded_open` empty. Each pending sponsored escape finalizes once its
   challenge period ends, sponsored by its client, or by anyone with
   `finalizeEscapeWithdrawal` from a funded account followed by the
   permissionless `S.sweep()`, which pays the payee and settles `S`'s debt
   (`S` exists: the initiation created it). Collect or sweep each stranded
   balance the same way, and `writeOffDebt` a defeated escape's debt.
   Draining while sponsorship is still possible lets users recover without
   ETH.
3. Publish profiles whose `gasless` is `null`, so no new proof binds a
   transit account of this paymaster.
4. Stop sponsoring.
5. `unlockStake` the paymaster and the factory, wait the unstake delay, then
   `withdrawStake` and `withdrawTo` the float.

After step 3 both clients refuse a new sponsored withdrawal with
`gasless_unavailable` (the SDK's `reason: 'not_pinned'`), and a sponsored
operation for an existing record of this paymaster with
`gasless_record_not_pinned` (also returned when a profile pins another
paymaster than the record's; it names the wallet-paid close or escape
initiation first while the record's exit is not on chain yet), while the
wallet-paid recovery of an existing record keeps working from the
addresses journaled with it, never the profile's: the SDK's
`sweepTransit`, `claimGaslessCredit` and `finalizeEscape(…, { fees:
'wallet' })`, and zkapi-clientd's `withdraw --sweep`, `--claim-credit` and
`--escape --fees wallet` (a sweep, and zkapi-clientd's credit claim, first
checks that the journaled factory's `getAddress(owner, payee)` is the journaled `S`; the
wallet-paid finalization is a plain vault call). They need an account with
ETH for gas. An operation sent before step 3 and not yet included is not
sent again: the clients follow it through the journaled EntryPoint on the
read RPC (zkapi-clientd also asks the bundler it sent it to for a receipt,
read-only), settle the record if it lands, release it if it landed
reverted, and otherwise release it after the five-minute
re-send window so the wallet-paid action takes over (zkapi-clientd's resume
without `--fees` releases it and names the next command; the SDK releases a
close or escape initiation in its background sync and a finalization in
`finalizeEscape(…, { fees: 'wallet' })`; a forward in flight never blocks
the SDK's sweep). See [Retirement](deployment.md#operating-gasless-withdrawals).

Sponsorship stops every kind at once, FINALIZE and FORWARD included
(`SponsorshipPaused` is validation's first check). A balance that appears
later (an operation in flight at step 3 that landed or was released, or an
escape left pending) is recovered by its user's client with those
wallet-paid actions, or by hand from any funded account: after the challenge period, `cast send "$VAULT" 'finalizeEscapeWithdrawal(uint32)'
<noteId>`, then `cast send "$S" 'sweep()'` (for a stranded balance, only the
sweep; an `S` with no code needs `cast send "$FACTORY"
'createAccount(address,address)' <owner> <payee>` first, with the values
its client holds). `sweep()` pays the payee, settling `S`'s debt on the
way; see [Retirement](deployment.md#operating-gasless-withdrawals).
Neither `sweep()` nor `claimCredit` needs the float or a stake, and
`createAccount` needs no stake: the contracts stay deployed (immutable
code), and "retiring" the factory means only withdrawing its stake. A new paymaster means new transit-account
addresses for new proofs.

**Escape exposure.** Sponsored escape initiations stay disabled in every
published profile. Each defeated sponsored escape costs the float the
initiation (about 1.25M gas) on top of the operator's challenge (about 435k
gas), against the attacker's deposit gas (about 0.3M, recovered later):
about 5:1 against the operator. Enable them only on the Sepolia drill, and
decide for mainnet from the `EscapeInitiationOwed` and `owedPaid` data.
Without them, escapes are sponsored at finalization only.

**Uneconomic floor per network.** Clients refuse a sponsored withdrawal whose
`maxCost + flatFee` exceeds 25% of the payout (`gasless_uneconomic`, unless
the host passes `allowExpensiveGas`). `maxCost` is about 1.7M gas of limits
times `maxFeePerGas`. Both clients take `maxFeePerGas = min(2 × base fee +
tip, maxFeeCeiling)` and refuse (`gas_above_paymaster_ceiling`) only when
`base fee + tip` exceeds `maxFeeCeiling`, so a ceiling of `c` sponsors base
fees up to `c − tip`, and from a base fee of `(c − tip) / 2` on every
operation is priced at `c` ([Fee ceilings](deployment.md#operating-gasless-withdrawals)).
The smallest payout sponsored by default is about
`4 × 1.7M × maxFeePerGas`, at most `4 × 1.7M × maxFeeCeiling`:

| `maxFeePerGas` | Smallest payout | `maxSponsoredCost` needed |
| --- | --- | --- |
| 5 gwei | about 0.034 ETH | the default 0.05 ETH |
| 28 gwei | about 0.19 ETH | the default 0.05 ETH |
| 62 gwei (a 30 gwei base fee) | about 0.42 ETH | at least about 0.11 ETH |

The policy's `maxSponsoredCost` refuses anything above it first
(`max_cost_above_policy`): at the default 0.05 ETH, nothing is sponsored
above about 28 gwei, whatever the payout. The 62 gwei row applies only with
a raised policy, and the hard cap of 0.25 ETH stops sponsorship above about
139 gwei. Publish the floor with the network's typical fees and the live
policy. Smaller balances keep the wallet path.

### Fee spikes

When the challenger reports `base_fee_above_fee_cap`, `fee_cap_reached`,
`tip_cap_reached`, `fee_reserve_held`, `tx_fee_cap_reached` or
`insufficient_balance`, raise the signer's caps in `signer.env` and recreate
the signer, then the daemon's (no higher) in `challenge.env` and recreate the
challenger, or fund the sender. A container reads its environment files only
when created: use `dc up -d --no-deps --wait signer`, then `challenger`. For
`tx_fee_cap_reached`, `tx_fee_above_cap` or `upstream_tx_fee_cap`, raise the
node's `--rpc.txfeecap` first, then `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` in both
files. At the default 1 ETH ceiling a 600,000-gas defeat can bid about 1,666
gwei and a 450,000-gas raise about 2,222 gwei, so fee spikes threaten mostly
leaf retirements and legacy challenges (about 7.53M gas, about 132 gwei). See
the [fee-spike runbook](../docker/aws/signer/README.md#fee-spike-runbook) and
[challenge operation](challenge-service.md#when-no-valid-bid-remains).

## Rollback

| Stage | Action |
| --- | --- |
| Phase 0 | Roll forward where possible. The previous image tags bring back the defects the hardening fixed: the previous signer needs `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` and refuses the new challenger's fee fields; the previous challenger treats reserved leases as evidence, which burns nullifiers on a legacy vault; the previous server restores the seed fallback and proof-less clearance; the previous indexer needs `indexer.cursor` moved aside and replays from `DEPLOY_BLOCK` (never restore a `.v1-*.bak`). Never restore an older database over newer wallet activity. |
| Before Phase C, step 4 | Do not publish; the contracts stay unused. An unannounced deployment can be abandoned before anyone deposits. |
| After new deposits; a client or server bug | Fix forward. Exits never depend on server or client cooperation. Optionally close deposits as in the next row. |
| After new deposits; a vault or circuit bug that leaves exits sound | Close deposits: set the new SDK profiles to `"deposits": "closed"`, and have the new stack's gateway answer 410 on its two deposit-only routes, `/v1/tree/next-note-id` and `/v1/tree/notes/{id}/zero-path` (the snippet of [Phase E, step 1](#phase-e-drain-and-retire-the-legacy-vault), in this checkout's `nginx.conf`, under a new `ZKAPI_IMAGE_TAG`). The profile flag reaches only the SDK: clientd's profile is compiled in and has no deposits switch, but its companion takes every deposit path from those two routes, so the gateway stops clientd deposits at once. Then ship a clientd release that refuses deposits. Reopen the legacy profiles only while the legacy stack runs, before `X`. Keep the new stack running until the new vault drains. Deploy a corrected vault with a new circuit ID if needed. |
| An exit-soundness bug (forgery) | Pausing stops only new escapes and closes, and only for up to `maxPauseDuration`. Pending escapes finalize at their deadlines unless defeated or raised, and the challenger must act in each window; a forged escape with no successor evidence cannot be defeated. Decide in advance: pause, publish, keep the challengers running, and let honest users exit when exits reopen. The vault has no upgrade path. The canary caps bound honest SDK users' exposure, and the server's lease ceiling bounds per-request service. |
| The server signs non-derived anchors (a bug) | Clients reject such successors (S4), and the request circuit makes them unspendable. Fix the server; nothing on chain changes. |
| A clientd release | The new line never reads or changes the legacy wallet and payment files, so reinstalling 0.1.7 finds them as it left them. Each line withdraws only its own vault's notes. |

## If development or mismatched keys were ever served

If a server ever ran with a development key (seed `0x1` or `0x2` in any
spelling) or with keys other than its vault's, treat the deployment as
compromised: anyone could forge state signatures and obtain provider keys
beyond their deposit, and with the development clearance key forge
clearances for their own notes.

1. Stop the server.
2. Rotate `ZKAPI_OPENROUTER_MANAGEMENT_KEY` or the OA org shared secret, and
   delete all outstanding runtime keys at the provider.
3. Audit `openrouter_leases` since the first start (`spending_limit_usd`,
   `usage_usd`, `charge_applied`) and the provider's usage, with the queries
   of Before you start, item 5.
4. Generate new seeds and deploy a new vault with their keys (Phase B or C);
   vault keys are immutable.
5. Publish new client profiles and move users (Phases C to E). If the vault
   itself pinned a development key, its notes stay forgeable until drained:
   retire it as fast as its owners can exit.

`Deploy.s.sol` refuses the development keys off local chains, and serverd
refuses them everywhere.

## Residual risks

**Concession vault** (design §9.2, plus the implementation):

- **Chain censorship** and **operator liveness**: the challenger must land one
  cheap transaction for each escape that needs a defeat or a raise. If it
  misses a defeat, the operator loses at most the stale payout plus service
  from the owner's newest state until `retireClosedLeaf` lands.
- **The retirement budget.** The signer bounds leaf retirements per rolling
  day, counted per nonce. Anyone who forces root races by front-running
  deposits can spend it and delay a retirement after a missed defeat; the
  miss itself is already critical.
- **Strategic under-conceding.** A raise costs about 335,000 gas, more than
  small request tiers; a modified client may bet that the operator does not
  raise. `ZKAPI_CHALLENGE_RAISE_MIN_UNITS` sets the smallest raise worth it.
- **Forced early exits conceding the bound** forfeit the bound minus the
  actual charge; clients ask the user.
- **Exit-time linkage.** An escape from a served state links the note's last
  request to the note and destination for the server and gateway; a raise
  publishes that request's public inputs on chain (design §8).
- **Leaked keys.** A leaked state key forges states, each capped at the
  deposit; a leaked clearance key lets a dishonest owner close at a spent
  state.
- **Permanent clearance reservations** (harmless while clients never request
  from a state after sending its ownership proof).
- **Setup trust.** An honest public phase 1 that the ceremony used and one
  honest phase-2 contributor (A2).
- **Stale backups.** Restoring a stale wallet or exit kit is caught by the
  stale-device pre-check only when the operator serves evidence; otherwise
  the escape is defeated and costs gas.
- **Owner pause** blocks new exits for up to `maxPauseDuration` (45 days on
  mainnet) per cycle.
- **Browser host dependence** without a current exit kit; the companion's
  `exit-kit escape` works without the host.
- **An exit RPC that is down, or none.** With `--exit-rpc-url` set, clientd
  and the companion stop an escape with an error rather than fall back to the
  pinned RPC; the owner retries or changes the setting. Without an exit RPC,
  the pinned RPC, which the operator may run, is trusted for the escape
  itself: it sends the escape's transactions and decides when a dead exit
  lock is released and whether the escape landed, was defeated or paid. No
  client releases a lock before its own clock says the released proof is
  dead, and clientd reads a reported defeat again on every run instead of
  recording it for good, so a lying pinned RPC cannot release a lock while
  the escape proof can still land, nor make a defeat permanent. It can do
  more than delay an exit, though: by dropping the escape's transactions and
  faking their receipts and logs, it can make clientd and the companion
  record the escape as finalized and paid, and archive the note, while the
  note is still open on chain, where the operator can sweep it with
  `claimExpired` at expiry. Owners should set an exit RPC before they escape,
  or check through an independent source (their own node or a block
  explorer) that the payout reached the destination. clientd warns on every
  open escape while no exit RPC is set, and repeats that check on an escape
  it completed without one. The SDK's chat path still releases a dead exit
  lock on the pinned RPC's reading when no exit RPC is set.
- **Deployment manifests.** Finalizing needs forge's broadcast log, and owner
  and treasury are checked only when it runs.

**Legacy vault, until it retires:**

- **Withholding operator.** An operator that withholds a signed successor can
  still defeat the owner's legacy escapes and take the deposit at expiry. Only
  the operator's public commitment to finalize every legacy lease, and the
  legacy challenger's finalized-only evidence rule, protect owners there.
- **Nullifier burn.** A legacy challenge consumes the escaped nullifier.
- **Unbounded pause** and an instant treasury change; only the Phase 0 owner
  policy protects owners.
- **Destinations that reject ETH** lock a legacy escape until they accept.
- **Root races.** Legacy exits and challenges need siblings at the live root,
  so an unrelated deposit can revert them; the challenger retries with fresh
  siblings. During the 30-day transition every close and escape moves the
  root, and a determined depositor can keep it moving, so a stalled exit near
  a note's expiry is possible; the answer is the spread-out announcements, the
  72-hour "close by" margin and the delayed sweep of the transition section.
- **The legacy clearance budget** is one shared pool while legacy clearance
  is on.
- **Admission closes at the gateway.** The legacy serverd has no admission
  switch; from `X` the legacy gateway refuses new leases (Phase E, step 2).
  The retirement bound depends on it: a note that could still buy service
  after `X` would need the legacy challenger until its own expiry. A legacy
  server cannot tell a late note (a direct deposit after day 0) from a
  transition note, since a request hides its note ID, so admission stays open
  to both until `X`; late notes are tracked by ID instead.
