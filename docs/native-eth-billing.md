# Native ETH browser billing

The protocol uses native ETH billing with the browser SDK and the
server, indexer, and challenger services.

Native ETH deployments hold ETH and use integer **gwei** in the proof
ledger: one unit is 1,000,000,000 wei. The browser displays an approximate USD reference value;
the USD value changes with ETH's price. This is not a stable-dollar deposit or a
swap into USDC. Fractional gwei are never credited to a private note.

The native vault exposes `billingToken() == address(0)` and
`nativeAssetWeiPerUnit() == 1000000000`. Its deposit selector accepts
integer gwei and requires exactly `amount * 1 gwei` in `msg.value`. Wrong values
revert atomically. Native deposits are capped at JavaScript's maximum exact
integer, 9,007,199,254,740,991 units. Withdrawal and expiry payouts convert ledger
units back to wei and enforce proof, nullifier, destination, timing
and reentrancy protections. A failed transfer to a mutual-close destination
reverts the complete close; the user can prove the close again to another
destination. A mutual close forwards all gas, so only a destination that
rejects ETH reverts it. `finalizeEscapeWithdrawal` pushes the payout with at
most 100,000 gas
(`ESCAPE_PAYOUT_GAS`); if the destination rejects it or needs more gas, the
escape still closes and the treasury share is paid, and the balance is
credited to `escapePayoutCredits(destination)` (`EscapePayoutDeferred`) for a
later `claimEscapePayout(destination)`, which anyone can call, also while
paused. This release's browser SDK reports such an escape that it started as
credited, not returned, and offers that claim; see
[Credited escape payouts](../sdk/README.md#credited-escape-payouts). Earlier
SDK builds report such an escape as returned, and clients detect a credit
only for an escape that the same browser started (the browser SDK) or a
relayed escape whose transaction hash the user enters (`zkapi-clientd`), so
operators still announce credits; see
[Escape payout credits](migration-concession-vault.md#escape-payout-credits).
On the legacy vaults an escape to a destination that rejects ETH cannot
finalize.
Likewise, a treasury that rejects its
share, or needs more than 100,000 gas to receive it, cannot block a close: the share accrues to `treasuryArrears()` with a
`TreasuryPaymentDeferred` event, and anyone can pay it out later with
`withdrawTreasuryArrears()`.

The deployment manifest pins the vault address, native asset, and circuit
`zkapi-v2-concession-v1` with its setup, its exact WASM and key hashes, and the
runtime code hashes of the vault, adapter and Poseidon library. The circuit
binds each signed balance to its deposit note. An escape concedes an amount up
to its state's request budget; the challenger raises it to what the request at
that state owes, or defeats it with a request proof at the state's successor.
See [Note-bound commitments](note-bound-commitments.md) and the
[concession exit design](design/concession-exit.md).

## Pinned configuration

The public deployment manifest and browser trust configuration must agree on:

```json
{
  "billing_asset": "native_eth",
  "billing_unit": "gwei",
  "billing_token_address": null,
  "native_asset_wei_per_unit": "1000000000",
  "native_price_feed_address": "0x694AA1769357215DE4FAC081bf1f309aDC325306",
  "native_price_feed_decimals": 8,
  "native_price_max_age_seconds": 4500
}
```

Pin the RPC URL, chain, vault and protocol/signing/proof-asset
fields too. Both manifest `proof_setup.circuit_id` and browser
`trusted_deployment.circuit_id` must equal `zkapi-v2-concession-v1`, the setup
IDs must agree, and all request/withdrawal proving and verifying key hashes
must match that setup. The example feed is Sepolia; it does not select a production feed.
The server checks chain ID, feed decimals and the vault's native-unit getter
before answering or accepting a quote. There is no symbol-only fallback.

Chainlink's reference directory lists the ordinary ETH/USD proxies as
`0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` on Mainnet and
`0x694AA1769357215DE4FAC081bf1f309aDC325306` on Sepolia, both eight decimals
with a 3,600-second heartbeat. The server and SDK read
oracle rounds at the RPC `finalized` block tag; the USD reference can therefore
lag the chain head, and `updated_at` identifies the actual feed observation.
The native deployment pins a 4,500-second maximum age: the heartbeat plus a
900-second finality allowance. Freshness remains configurable and fails closed
if finality or feed updates lag beyond the pinned allowance. The RPC must support
`finalized`; there is no fallback to head/latest pricing. Quotes with a future
timestamp, incomplete round, nonpositive price or expired timestamp fail.
Review feed provenance and freshness policy before each deployment.

Sources: [official documentation feed-directory configuration](https://github.com/smartcontractkit/documentation/blob/main/src/features/data/chains.ts#L294),
[Chainlink API](https://docs.chain.link/data-feeds/api-reference),
[Mainnet directory](https://reference-data-directory.vercel.app/feeds-mainnet.json),
[Sepolia directory](https://reference-data-directory.vercel.app/feeds-ethereum-testnet-sepolia.json).

## A quote belongs to one private lease

`GET /v2/billing/quote` is a read-only, `Cache-Control: no-store` endpoint:

```json
{
  "asset": "native_eth",
  "units_per_eth": 1000000000,
  "chain_id": 11155111,
  "feed_address": "0x694aa1769357215de4fac081bf1f309adc325306",
  "round_id": "123",
  "answer": "250000000000",
  "decimals": 8,
  "updated_at": 1700000000,
  "expires_at": 1700004500
}
```

This is a schema example, not a usable current quote. Round and price are
canonical decimal strings. `expires_at = updated_at + configured max age`.
The browser independently verifies the round through the pinned RPC and adds
this entire object as `billing_quote` to the existing prompt-free lease
authorization before generating a proof. The canonical payload hash and request
authorization tag bind the quote to that request and its proof. It carries no
prompt, account identity, funding address or wallet secret.

Before reserving a new nullifier, the server verifies the quoted round with
`getRoundData` and requires it to equal `latestRoundData` on the pinned feed,
both read at `finalized`, as well as checking freshness. A user cannot choose a
favorable historical round. Head-only updates do not invalidate a prepared
finalized quote. If a newer round finalizes while a proof is being prepared,
new issuance rejects it with `native_quote_superseded`; the exact old request
must be recovered before constructing a new proof. The exact accepted request,
including its quote, is persisted before upstream key provisioning. The rate is
never refreshed on a matching retry or during settlement. In particular, a
restart or an oracle outage cannot reprice an existing lease. Settlement checks
the saved quote only for internal consistency and never compares it with the
server's current `--native-price-*` settings, so changing the feed address,
decimals or maximum age affects only new admissions (and the acknowledgement of
an unaccepted quote that has not yet expired). Keep those settings equal to the
published manifest.

Wallets follow the same rule for a request the server has admitted. The browser
SDK and the `zkapi-clientd` companion check the quote saved with a journaled
request only for internal consistency and its chain, never against the current
pins. After a client release changes `native_price_feed_address`,
`native_price_feed_decimals` or `native_price_max_age_seconds`, a wallet with an
unsettled request still opens, recovers and withdraws, and installs the
request's finalized receipt. A journaled request that the server never admitted
is different: the server compares a new admission's quote with its pins before
its freshness, so it refuses that request with `invalid_request`, not
`native_quote_expired`. A wallet retires such a request through
`POST /v2/openrouter/leases/{id}/expire` only after its quote has expired, at
most the old maximum age after it was quoted, and only on the server's matching
`expired_unaccepted` acknowledgement. The SDK does this in the recovery it runs
before each lease. `zkapi-clientd` does it when the server refuses the request
on a lease at the request's original model budget; a lease at another model
budget reports `lease_pending` without contacting the server. Until then the
wallet's next lease may fail with `invalid_request`; status, recovery and
withdrawal keep working, and a `zkapi-clientd` withdrawal settlement discards
the request once the server knows neither the request nor its nullifier. Prefer
to change native-price pins when no wallet has a request in flight.
`zkapi-clientd` 0.1.6 and earlier check journaled quotes against the pinned
manifest and cannot open such a wallet at all; later releases, whose
companion is built from this repository, check them only for consistency.
The clientd companion converts only 8-decimal ETH/USD answers.

An accepted reservation does not authorize new access after its state has been
withdrawn. Before contacting either provider to create a key, including an exact
reserved/provisioning retry, the server checks the configured chain ID and the
vault's `usedNullifiers(request_nullifier)` at `latest`. Only an explicit ABI
`false` permits issuance. Consumed nullifiers return `nullifier_used`; unavailable,
wrong-chain or malformed RPC responses fail closed with a retriable server error.
This live authorization read does not refresh the frozen quote or require the
original Merkle root to remain current after unrelated deposits.

The lease row is created, with its frozen TTL and write-once settlement
deadline, right after the reservation and before that check. After provider
creation, the server durably activates the lease and repeats the same check
before returning its secret, and it records that the key was delivered only
immediately before returning it. If a withdrawal consumed the nullifier during
provider I/O, or the read fails, no key is returned; the active record stays for
status and settlement, which charges such an undelivered key nothing, and a
direct key is queued for deletion at once. RPC availability is therefore
required for new key delivery, including retries. Existing lease status and
settlement do not require this issuance check.

A key is only ever returned for a lease that settles from usage. Issuance holds
the issuance lock from its first check until it has returned or abandoned the
key. The background settler and a client's retirement settle a never-delivered
lease at zero only while holding that same lock (a retirement waits for it) and
read the lease again once they hold it: a key delivered meanwhile settles from
usage instead. Before signing the zero-charge successor, the settlement also
commits the lease row to it, after which the key can neither be activated nor
marked delivered, and an issuance whose delivery mark is refused never returns
its key. Such a direct key is deleted in the background. The OA org offers no
key revocation: an OA key that was never returned was seen only by the org, its
station and this server, and lapses at its TTL.

A withdrawal started after key delivery still requires timely operation of the
challenger. An escape from a lease's state is raised to the lease's charge once
settlement fixes it, which the settlement deadline below bounds, or to its
solvency bound at the raise lead; an escape from an older state is defeated by
the request proof at its successor, whatever that request's settlement status.
These checks do not replace the configured challenge window, a trustworthy view
of the selected chain, or sufficient operational time to observe and act on an
escape. The challenge window is fixed when the vault is deployed (172,800
seconds planned for mainnet, 43,200 for Sepolia).

For ledger units `U`, oracle integer answer `P`, and decimals `D`, the upstream
budget in micro-USD is:

`floor(U * P * 1,000,000 / (1,000,000,000 * 10^D))`.

The OA org still receives and signs micro-USD limits and measured usage; it does
not need native-token pricing support. For measured usage `C` in micro-USD the
native charge is:

`ceil(C * 1,000,000,000 * 10^D / (P * 1,000,000))`.

Zero usage stays zero. Settlement clamps measured usage to the micro-USD limit
of the proof's solvency bound before converting it, so the conversion cannot
overflow and the signed charge never exceeds the solvency bound; a clamped
charge carries `charge_basis: "clamped"` with the reported and charged usage,
and records a `usage_clamped` review. OA receipts above the lease limit are
clamped the same way. Issuance and the settlement response payload echo the
exact quote so the browser can compare it with its persisted journal.

A `native_quote_expired` response is emitted only before any nullifier
reservation. Freshness is rechecked after all oracle awaits and after proof
verification immediately before reservation, with equality treated as expired.
Issuance attempts share one lock, so an exact POST that returns this rejection
has also waited for earlier in-flight attempts. A local clock or an unknown GET
alone does not authorize deleting a journal; startup remains read-only.
`POST /v2/openrouter/leases/{id}/expire` accepts the exact saved request. It
returns `expired_unaccepted` when the server clock says expired, or
`superseded_unaccepted` when a newer finalized round exists, with the exact
request ID, nullifier and payload hash. Both acknowledgments require that
neither its nullifier nor request ID has a reservation. That is checked under
the same issuance lock, which waits for earlier in-flight attempts, before and
again after the oracle reads; the lock is not held across them. An issuance
that reserved the request meanwhile is seen, and a later one reads the clock
and the oracle later, so it cannot accept an expired or superseded quote.
Superseded recovery relies on Ethereum finality: an ordinary head
reorganization cannot revive the old quote. A finalized-chain safety violation is outside this model,
as it is for the private note's confirmed chain state. This endpoint is
read-only: it never generates a key, signs, reserves or cancels anything. Every
other result preserves the journal. It allows interrupted startup/withdrawal recovery without
starting a chat solely to test whether an old proof is still issuable. Matching
reserved/provisioning requests retain their old quote and remain recoverable
after expiry. Other errors do not authorize discarding a
pending journal. `POST /v2/requests` has been removed; all new authorizations
require prompt-private leases with a proof-bound native quote.

## Clearance

`POST /v2/withdraw/clearance` signs a mutual-close clearance only against a
kind-2 ownership proof of the same nullifier (`ClearanceRequestV2C`): its
destination, conceded amount and successor nullifier are zero, its
`valid_until` lies between now and an hour ahead, and its root is one the
server saw within `--clearance-root-window-seconds`, the vault's
`currentRoot()`, or any root the vault ever held (`knownRoots`), so a wallet's
deposit-time path serves. This circuit has no proof-less clearance: the
legacy clearance budget is gone, and `--allow-legacy-clearance` refuses
startup. A nullifier with any request row is refused (`nullifier_used`); a
granted clearance reserves it for good, and asking again signs again. See the
[API reference](../docs-site/content/docs/api-reference/serverd.mdx).

## Deployment

The deploy script creates a native-only vault and accepts `REQUEST_CHARGE_CAP`
in gwei. It checks an optional `CHAIN_ID` against the connected chain and, off
local chains, requires an explicit `OWNER`; see
[deployment](deployment.md#contracts). Publish a manifest that pins the
resulting vault, circuit artifacts, signing keys, and native asset
configuration.

Start the native server with its vault/chain/request cap and
signer, indexer, proof and OA-source settings, plus:

```sh
zkapi ... serverd ... \
  --native-billing-rpc-url "$RPC_URL" \
  --native-price-feed-address "$ETH_USD_FEED" \
  --native-price-feed-decimals 8 \
  --native-price-max-age-seconds 4500
```

The server requires native oracle and prompt-private lease configuration, with
one key source; to change it, see
[Changing the key source](#changing-the-key-source).
`--openrouter-settlement-deadline-seconds` (default 21600) sets the settlement
deadline described below. The server also requires `--deployment` (the
deployment manifest the database was initialized from with `zkapi db init`),
admits a request only at the exact current root while its indexer's root and
the vault's `currentRoot()` agreed within `--root-max-staleness-seconds`
(default 60; otherwise `503 root_unavailable`), and, with
`--request-limit-max-usd-micros` (6,000,000 during the canary, and recommended
permanently), refuses a request whose lease budget exceeds that ceiling before
anything is reserved (`400 request_limit_exceeded`). This ceiling bounds the
operator's per-request exposure.

The reservation is written in one SQLite transaction with the provisioning
lease row and an append-only `request_evidence` row holding the request's
public inputs and proof. Triggers refuse any update or delete of that table;
keep it until the deployment retires. Operate the
[challenge daemon](challenge-service.md) alongside server and indexer, with a
dedicated funded signer restricted to the configured vault. It defeats an
escape with any verified evidence row at the escape's successor nullifier, and
raises an escape's concession with the row at its nullifier, to the settled
charge, or to the solvency bound of a request that may have been delivered and
is still unsettled near the deadline. After a defeat,
`usedNullifiers(nullifier)` reads `false` and
`challengedNullifiers(nullifier)` reads `true`: no escape can use that state
again, and the owner exits from its newer state.
Do not reuse a daemon, verifier or setup from another circuit. Configure the published manifest separately; these flags do
not rewrite static frontend manifests. The browser SDK handles funding and
withdrawals; the operator CLI runs setup, signing-key, server and indexer
commands, and `zkapi settlement reopen` (see
[Reopening a cancelled lease](#reopening-a-cancelled-lease) and
[Restoring an unreadable pending lease](#restoring-an-unreadable-pending-lease)).

OA provisioning retries accept a shortened remaining lifetime only when the
relay explicitly marks the station response `replayed: true`. Its original
expiry stays unchanged and must remain in the future and within the requested
maximum TTL; absent flags and ordinary new issuance retain strict lifetime
bounds. A resumed OA issuance uses the lease's frozen TTL, and is refused with
`lease_pending` when the lease's settlement deadline no longer leaves room for
TTL + grace + 900 seconds; such a lease is later finalized at zero. A replay
never creates a second key for the same accepted request.

Native OA issuance uses a deployment-bound upstream request ID: a versioned
Keccak domain hash of the complete accepted request binding (chain, vault,
nullifier, browser request ID, payload/quote, and proof). This separate ID is
persisted atomically with the lease and reused for key issuance and usage
recovery. It prevents two deployments that share an org from redeeming the same
key by choosing the same browser request ID. The browser-visible ID stays
unchanged. OA lease recovery rejects a missing or mismatched native upstream ID.

## Recovering OA provisioning

The server records whether a new OA lease has ever attempted issuance. Before
provider I/O, it durably changes `not_started` to `may_have_issued`; a timeout,
lost reply, malformed success or restart therefore preserves uncertainty. The
only automatic rejection classification is HTTP 400 with an exact org
pre-provider validation detail: `credit_limit exceeds zkAPI policy`,
`credit_limit_credits exceeds zkAPI policy`, or
`duration_minutes exceeds zkAPI policy`. These are a contract with the org's
`request_key` validator, which runs before station/provider I/O. A generic
400, 429, missing key hash, or expired local lease is not nonissuance evidence.
Even a recognized rejection cannot clear uncertainty from an earlier attempt.

A definitive first-attempt rejection becomes `confirmed_unissued` and receives
a normal signed zero-charge successor state. The issuance request returns
`oa_key_policy_rejected` (HTTP 400, nonretriable); this error alone does not
authorize deleting a wallet journal. Clients retrieve and verify the signed
response using ordinary request recovery. The receipt keeps the original quote
and has type `oa_org_unissued_lease_cancellation`, `issued: false`, and zero usage.
The nullifier is finalized, never deleted or made reusable.

If finalization is interrupted, the next background scan or exact saved-proof
settlement request finishes it. A persisted signed successor is reused after a
crash; it is never replaced with a new signature. A provisioning row is
finalized at zero only while it still has no key and only while holding the
issuance lock, so never during an issuance attempt; see
[Settlement terminality](#settlement-terminality) for when.

Every other OA lease that never returned a key to the client is also finalized
at zero once its settlement is due, whatever its outcome: `not_started`,
`may_have_issued`, or a historical row whose outcome is unknown. Its receipt has
the same type with `reason` `issuance_not_started` or `issuance_not_completed`,
and no provider or chain call is needed. A key the org may have issued was never
delivered through this lease, so nothing can have used it. The read-only issuer
reconciliation of earlier releases (`POST /api/zkapi/reconcile_key`) is no
longer used. Rows that an earlier release reconciled are treated as possibly
delivered and settle from measured usage. Usage settlement uses the TTL frozen
in the lease row; only rows created by earlier releases, which have none, use
the server's current setting.

A crash after nullifier reservation but before the lease row is created still
requires exact issuance replay. Nothing can infer an outcome from that
incomplete state, nothing settles it automatically, and the challenger never
treats it as evidence.

## Settlement terminality

Every accepted lease's charge is fixed by a deadline, so a lease can no longer
hold its note state reserved indefinitely. Settlement and signing are two
steps:

- **Settle.** The charge is computed as below and written once, with its basis
  and time, on the nullifier row (`settled_charge`, `settled_basis`,
  `settled_at`), which stays `Reserved`. The lease row already reads
  `finalized` from then on; a client reads the nullifier's recovery status to
  learn when the successor is signed.
- **Sign.** The successor is signed at the anchor derived from the request's
  nullifier, and only while the vault reports that nullifier unused
  (`usedNullifiers` at `latest`). When an exit has consumed it, the signature
  is deferred: the row records `exit_deferred_since` and the lease reads
  `exit_deferred`. Every pass checks it again. If the exit is defeated, the
  successor is signed with the settled charge; if the nullifier is still
  consumed one challenge period plus 3,600 seconds after the first
  observation, the row becomes `ExitedUnsigned` (lease `exited_unsigned`) and
  no successor is ever signed. The challenger raises such an escape to the
  settled charge. Each signing pass pages never-deferred and deferred requests
  separately, at most 200 of each per pass, so a deferred request is checked
  again within a few passes rather than on every one.

The charge itself:

- The deadline (`settlement_deadline_at`) is written once, when the lease row is
  created: issuance + TTL + grace + `--openrouter-settlement-deadline-seconds`
  (`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`, default 21600). Retirement
  steps, timing updates and a provider that keeps reporting a key enabled never
  move it, and the first error time is never reset. A row created by an earlier
  release receives one at first sight: the later of its expiry and that moment,
  plus grace and the deadline setting.
- A lease that never delivered a key is finalized at zero, signed, without any
  provider or chain call: a provisioning row (direct, or OA in any outcome), or
  an activated lease whose key was never returned. The receipt keeps its
  source's type (`openrouter_ephemeral_lease_settlement`, or
  `oa_org_unissued_lease_cancellation` for OA) with `charge_basis: "unissued"`,
  `issued: false`, `delivered: false` and a `reason`
  (`issuance_not_started`, `issuer_policy_rejected`, `issuance_not_completed`
  or `key_never_delivered`).
- Such a lease is due once its `settle_after` passes (for a provisioning row,
  normally its creation plus TTL and grace; for an activated one, its key's
  expiry plus grace) or its settlement deadline passes, and at once after a
  confirmed OA rejection or once the lease is committed to its zero charge.
  Its zero settlement needs the issuance lock (see above). A settlement tick
  (every `--openrouter-settlement-poll-seconds`) finalizes a due lease when that
  lock is free and otherwise defers it to the next tick. Once the lease is past
  its settlement deadline, the tick instead queues for the lock, in arrival
  order, for up to 30 seconds after its other zero settlements, then finishes
  its other work. Lock holders that come and go, such as issuance attempts or
  `/expire` checks, can therefore no longer postpone it; only a lock held, or
  a queue of holders waiting, for longer than 30 seconds defers it to the next
  tick. Its owner can also finalize it at once by retiring it with the exact
  saved request, which waits for the lock within the 45-second retirement
  timeout.
- A lease that may have been delivered (active, retiring, disabled or revoking)
  is settled from measured usage, clamped to its solvency bound
  (`charge_basis` `measured` or `clamped`). Transient failures, such as an
  unavailable provider, org or RPC or an unconfirmed key deletion, are retried
  until the deadline. At the deadline it is finalized without further I/O: a
  revoking direct key whose usage was already captured is charged that usage
  (`key_deleted: false`, review `finalized_before_key_deletion`); any other is
  charged its solvency bound (`charge_basis: "worst_case"`,
  `settlement_reason: "settlement_deadline"`, review `deadline_worst_case`).
- Each tick starts provider attempts for at most 120 seconds (each attempt is
  bounded at 150 seconds). It draws them alternately, by time spent, from two
  orders over the due leases: nearest settlement deadline first, and least
  recently attempted first. The lease closest to its deadline is therefore
  attempted first, and leases that keep failing slowly cannot starve the
  others. A receipt that the OA org reports as still pending, or a direct key
  still in its drain interval, is not a failure: it changes neither `attempts`
  nor `last_error`, and the lease is not asked again before the retry time it
  was given (`retry_after_seconds`; at least the poll interval, at most 300
  seconds, and never more than half of the time left before its deadline).
  The lease also moves behind every other lease in the least recently
  attempted order. A usage read that the OA org answers with HTTP 429 is
  handled the same way, with the org's `Retry-After` (bounded as above) as the
  retry time and without counting a failure. Because the org limits all of the
  server's requests together, no other OA usage read starts before that time
  either: not for the rest of the tick, not in later ticks, and not for a
  retirement. A lease that reaches its settlement deadline meanwhile is
  finalized as described above. A failed attempt is retried on the next tick.
  An owner's retirement honours the same retry times: until they come, the
  retirement answers `lease_settlement_pending` with the time left, without
  asking the provider again.
- Each lease is settled under its own lock. A retirement waits only for work
  on its own lease (and checks the owner's proof before it waits). The tick
  never waits for a lease's lock: it leaves a lease whose lock is held or
  awaited to that retirement, which applies the same rules, including the
  deadline, and sees it again on the next tick. Retirements of one lease,
  however frequent, therefore never slow the settlement of the others.
- A deterministic failure, such as a corrupt saved quote, missing revocation
  usage, or an invalid saved TTL, namespace or limit, is finalized at the
  solvency bound at once (`settlement_reason: "unsettleable"`, review
  `unsettleable_worst_case`).
- A charge is final once settled; there is no refund transaction. The
  solvency bound is the most the user's own proof authorized, and the provider
  key's spending limit was derived from it.
- `cancelled` is used only for a lease whose saved binding does not match its
  nullifier record. The server never signs it and records a `binding_corrupt`
  review naming the first mismatching field, and a retry of the request returns
  `nullifier_used`. A direct key that may have been delivered is first disabled
  and its usage captured, so that a reopening can charge that usage. The
  capture is retried like any settlement until the deadline; the corruption is
  reviewed as soon as it is found, and the lease is cancelled, with a second
  review, once its usage is read, or at its deadline without it. The
  cancellation queues the key's deletion. Its nullifier stays reserved and
  unsettled, and a reserved nullifier never receives a mutual-close clearance.
  The owner's client therefore escapes at its time `T`, conceding the state's
  bound, and the challenger raises nothing beyond the solvency bound. The
  operator's remedy is to [reopen the lease](#reopening-a-cancelled-lease) once
  its binding is repaired, so that the owner installs the real successor and
  pays only its charge. Conceding its charge (`--zero-charge`) is a choice of
  charge within that remedy, not a way around the repair.
- A pending lease row that cannot be decoded, normally because its saved
  request (`api_request_json`) cannot be, is skipped by every tick: neither
  provider I/O, nor its settlement deadline, nor a cancellation reaches it,
  and its nullifier stays reserved, with the same consequences for its owner
  as a cancellation (and the challenger treats an unreadable lease row as
  possibly delivered). Each tick logs
  `unreadable OpenRouter lease row cannot be settled` at error level with the
  row's `client_request_id`; alert on that line. Lease routes answer it with
  `lease_record_unreadable`. The dashboard counts include it, but its `pending`
  list does not. The deadline guarantee above applies to it only once the
  operator [restores its saved request](#restoring-an-unreadable-pending-lease),
  or repairs by hand another column that cannot be decoded.
- Keys of terminal direct leases that may still exist at the provider (worst
  case, never delivered or cancelled) are disabled and then deleted in the
  background, outside every lease lock; a 404 counts as done, and failures
  are retried with backoff up to one hour.

Lease status responses carry `charge_basis` and, until the lease is terminal,
`settlement_deadline`; nullifier and request recovery responses for a reserved
lease request carry `settlement_deadline` too. Every settlement payload carries
`charge_basis` and the original `billing_quote`, and fallback settlements add
`settlement_reason`. The payload `type` of each key source is unchanged.

The server refuses to start unless TTL + grace + deadline + twice the settlement
poll interval + 600 seconds is at most half the vault's `challengePeriod()`
(read with the startup key check), unless the deadline leaves at least 900
seconds of retries after the grace, and unless TTL + grace + deadline is at
most the manifest's `settlement_window_seconds`, the window clients wait for
before they escape conceding a request's bound. A settled charge therefore
exists before half of the challenge window has passed. The challenger
separately checks that a raise decided at its raise lead still lands within
the window. Use a deadline of 21,600 seconds for the planned mainnet challenge
period of 172,800, 14,400 for Sepolia's 43,200 and 1,800 for the drill vault's
7,200 (`settlement_window_seconds` 21,905, 14,705 and 2,105).

## Operator review

Every clamped, deadline, deletion-pending, unsettleable or corrupt-binding
settlement writes a row to the `settlement_reviews` table with one of the
reasons `usage_clamped`, `deadline_worst_case`, `unsettleable_worst_case`,
`finalized_before_key_deletion` or `binding_corrupt`, and logs
`settlement required operator review` at error level. Alert on that line.
Reopening a cancelled lease adds a `binding_reopened` row, as do conceding the
charge of a reopened lease later and
[restoring an unreadable pending lease](#restoring-an-unreadable-pending-lease).
The table is a log: one lease can have several rows, such as its cancellation,
its reopening and its final settlement.
A `binding_corrupt` row's detail names the first disagreeing field; either side
of the disagreement may be the corrupt one, which the reopen command tells
apart. A direct lease that may have been delivered gets one such row when its
corruption is found and another when it is cancelled.
`GET /v1/dashboard/settlement?limit=N` (operator-only and never proxied by the
gateway; password-gated like the other dashboard routes on Sepolia) returns:

- `counts`: `pending`, `retrying`, `provisioning`, `cancelled`,
  `exit_deferred`, `exited_unsigned`, `unknown_status`, `open_reviews`,
  `pending_key_cleanups` and `next_deadline_in_seconds`;
- `pending`: each unsettled lease with its status, delivery, charge basis
  already committed (`unissued` or `operator_conceded`, otherwise null),
  deadline, seconds remaining, attempts, first error time and last error;
- `reviews`: each review with its reason, charge basis, reported usage, applied
  charge, solvency bound and acknowledgement time.

`GET /v1/dashboard/summary` includes the same counts as `settlement`.
Acknowledge each handled review row by setting its `acknowledged_at`, selected
by its `review_id`; the [Docker guide](../docker/aws/README.md#monitoring) has
the commands.

Keep backups of the server database, for example with sqlite3's online backup
(`sudo sqlite3 -readonly /var/lib/zkapi/server.db ".backup /var/backups/zkapi/server.db"`
on the Docker host), without stopping the server. A backup is never restored
over the live database; it is a source of the authentic saved request when a
lease's own copy is corrupt (see
[Reopening a cancelled lease](#reopening-a-cancelled-lease)).

Every file-backed signing processor holds an exclusive database sidecar lock
for its lifetime. Challenger reads remain available. Stop all older server
writers before deployment: old binaries and manual database writes do not honor
this lock. Preserve the sidecar, database and backup together; never unlink the
lock to bypass an active writer. Do not downgrade a migrated live database to an
older writer. An older writer ignores the settlement deadline, delivery and
review columns, compares saved quotes with its live settings again, treats
`cancelled` and direct provisioning rows as not due, so its settlement can stall
again, and ignores both a lease's commitment to a zero charge and an operator
concession; rows already finalized stay finalized. Rollback requires a
compatible writer or stopped-service reconciliation of affected rows, not
restoring an old database over newer wallet activity.

## Changing the key source

A server issues and settles leases with one key source: direct OpenRouter
(`ZKAPI_OPENROUTER_MANAGEMENT_KEY` or `--openrouter-management-key`) or an OA
org (`--oa-org-url` with `ZKAPI_OA_ORG_SHARED_SECRET`). Only the source that
issued a lease can measure its usage, and only the direct source deletes direct
keys. A server started with the other source could only finalize each possibly
delivered lease of the previous source at its settlement deadline without a
usage measurement (normally at its full solvency bound), and would never
delete the previous source's keys queued for deletion.

Moving to a different OA org, or to a different OpenRouter API base
(`--openrouter-api-base`), is a key-source change too: another org or API base
cannot read or delete the keys the previous one issued. Each lease activated by
this release records the endpoint of the source that issued its key: the OA org
URL or the API base, without credentials, query or trailing slash. Rotating the
org's shared secret or the management key keeps that endpoint and is not a
change.

The server therefore refuses to start while its database holds, of another key
source or endpoint, a lease that only that source can settle (one that may have
been delivered and has no committed charge) or, when leaving direct OpenRouter
or its API base, a queued deletion of a key that has not expired yet. Rows any
server finalizes without provider I/O do not count: never-issued provisioning
rows, leases whose key was never delivered, leases committed to a zero or
conceded charge, and leases past their settlement deadline, which are finalized
at once at the same charge whatever the configuration. Nor do deletions of
expired keys, which can no longer be used. The error names the counts, the
recorded endpoint, and this procedure:

1. Keep the server running with its current key source, and stop routing new
   requests to it, for example by taking it out of the gateway. Settlement
   continues without clients.
2. Watch `GET /v1/dashboard/settlement` until `counts.pending` is 0 (or, when
   changing the source type, `pending` lists no lease of the current
   `key_source`) and, when leaving direct OpenRouter or its API base,
   `counts.pending_key_cleanups` is 0. A delivered lease settles once its key
   has expired and the grace has passed, unless its usage stays unavailable
   (an OA receipt can stay pending longer); none waits past its settlement
   deadline.
3. Stop the server, change the credential (and the org URL or API base), start
   it with the new key source, and route requests to it again.

The check cannot detect two moves, which need the same procedure:

- **Another OpenRouter account behind the same API base.** The server knows
  the management key, not its account, so the new account's key passes the
  check. It cannot read or delete the previous account's keys: each of their
  possibly delivered leases would be charged its solvency bound at its
  settlement deadline, and a queued deletion of one of their keys would fail
  until the key expires, or count as done if the provider answers 404.
- **Leases activated by an earlier release**, which record no endpoint. They
  are taken to be the configured source's whenever their key source type
  matches, unless the database also holds, recorded under another endpoint
  of that type, leases or queued deletions that block startup as above. That
  endpoint has then been serving since the upgrade, so they are taken to be
  its own: a start under it passes and settles them, and the error under any
  other names them as activated before this release. While they are the only
  such rows, a start under another org or account passes, so drain them
  before moving to one.

`--allow-key-source-switch` (or `ZKAPI_ALLOW_KEY_SOURCE_SWITCH=true`) starts
the server anyway and accepts that each such lease of the other source is
finalized at its settlement deadline without a usage measurement; the server
logs what it strands. Use it only where the procedure above cannot work, and
remove it once those leases are settled:

- **A database holding such leases of two or more sources** (two source types,
  or two orgs or API bases), which an earlier release could leave behind (a
  source switch, at 045b444 or f7c99837, with leases of the previous source
  outstanding), as can an earlier use of this flag. No single credential
  drains it, so the server refuses under any source, and the error says so.
  Start under one source with the flag, stop routing new requests, and wait
  until its leases are settled: for two source types, until `pending` lists
  none of its `key_source` in step 2; for two orgs or API bases, until a start
  under the other one without the flag no longer refuses (with more, until
  that start's error no longer lists them). Then restart under the other
  source without the flag (with more, under each remaining source in turn the
  same way, the last one without the flag), before its remaining leases reach
  their settlement deadlines (by default 6 hours after their keys expire):
  they are then still measured. Finally switch to the source you want with the
  procedure above.
- **A previous key source that can no longer be reached** (its org is gone, or
  its management key was revoked), or an outage of one source that the
  operator decides to fail over from: the flag starts the other source at
  once instead of waiting for the unreachable source's deadlines. Each
  possibly delivered lease of the unreachable source is then charged its
  solvency bound at its settlement deadline, as any lease whose usage stays
  unavailable.
- **The same org or OpenRouter account at a new URL**, such as a renamed
  host: its leases still settle there, so nothing is charged without a
  measurement.
  Each restart needs the flag until the leases recorded under the old URL
  are settled.

Queued deletions of direct keys whose management key was revoked never
complete, but those keys expired with their leases, and they stop blocking
startup once expired: to clear `counts.pending_key_cleanups`, remove the
queued rows while the server is stopped, with
`sudo sqlite3 /var/lib/zkapi/server.db "DELETE FROM provider_key_cleanup WHERE key_source = 'openrouter'"`
on the Docker host.

Rows of a key source this release does not know never block startup; this
release never settles or charges them.

## Reopening a cancelled lease

A `binding_corrupt` review names the first field in which the lease row
disagrees with its nullifier reservation. The server has not checked which side
is corrupt: the saved request (`openrouter_leases.api_request_json`), the lease
row's other columns, or the reservation (the `nullifiers` row). Wait until the
lease is `cancelled` (read its row's `status`; the dashboard's `pending` list
holds at most `limit` leases, so a lease missing from it may still be
pending): a direct lease that may have been delivered is reviewed when its
corruption is found but cancelled only once its key's usage is captured (at
its deadline at the latest), and the command refuses it until then. Then stop
the API server and run the command against its database, with its proof setup.
In the [Docker deployment](../docker/aws/README.md), with `dc` defined as under
its Monitoring section:

```sh
dc stop server
dc run --rm --no-deps --entrypoint zkapi server settlement reopen \
  --db-path /data/server.db --client-request-id "$ID"
dc start server
```

`$ID` is the `client_request_id` the review names. The container sees the
database as `/data/server.db`, and the default `--proof-setup-dir`
(`protocol/setup/v2-concession` under the image's working directory, or
`ZKAPI_PROOF_SETUP_DIR` from the deployment) is the server's setup. On a host
install, run
`zkapi --proof-setup-dir <the server's setup> settlement reopen --db-path <the server's --db-path> --client-request-id "$ID"`;
the global `--proof-setup-dir` goes before `settlement`. The command takes the
server's database writer lock: it refuses while a server holds it, and no
server starts while it runs. It changes nothing unless the lease is `cancelled`
with a `binding_corrupt` review and passes these checks in order; a refusal
names the first field that fails and its repair:

1. The nullifier is not `ClearanceReserved`: that owner already holds a
   clearance and exits by mutual close. Its charge is not settled yet: a
   settled charge (`nullifiers.settled_charge`) is refused with
   `AlreadySettled` (its successor is signed at that charge once its nullifier
   is unspent on chain, and the charge cannot be conceded), and `--rebind` of
   such a reservation with `RebindSettled` (restore the `nullifiers` row from a
   backup first).
2. The saved request verifies as admission verified it: its payload hashes to
   its `payload_hash`, its proof's authorization tag binds its
   `client_request_id` and payload, and its Groth16 proof verifies against its
   public inputs. Together these cover every field of the request. A request
   that fails, or cannot be read, is the corrupt side. Never recompute the
   reservation from it: the server would then sign a successor for a request
   that its owner never authorized. Instead run the command again with
   `--saved-request FILE` (`-` reads standard input), a JSON copy of the
   authentic request from either source:
   - a backup of the server database:
     `sqlite3 -readonly backup.db "SELECT api_request_json FROM openrouter_leases WHERE client_request_id = '$ID'" > request.json`;
   - its owner's copy, which the wallet keeps until the lease settles:
     `prepared_request` in zkapi-clientd's `pending_journal.json`, in its state
     directory (`jq .prepared_request pending_journal.json > request.json`), or
     in the browser SDK's request journal.

   The copy is accepted only if it verifies, its binding is the
   `api_request_binding` its reservation recorded at admission, and it shares
   the lease row's `client_request_id` or `request_nullifier`. A tampered copy,
   another request its owner authorized for the same note state, and another
   lease's request are refused. If the reservation's `api_request_binding` is
   corrupt too, restore that column from a backup first. In the Docker
   deployment, pass the copy on standard input:
   `dc run -T --rm --no-deps --entrypoint zkapi server settlement reopen --db-path /data/server.db --client-request-id "$ID" --saved-request - < request.json`.
3. The lease row agrees with the verified request: its `client_request_id` and
   `request_nullifier`. The request having verified, the lease row is the
   corrupt side: run the command again with `--rebind`, which sets both columns
   from the request and moves the lease's reviews to its corrected id. It
   refuses while another lease row holds the request's id or nullifier. Do not
   set these columns by hand: `client_request_id` also keys the lease's reviews
   and key cleanup. (A row renamed by hand is still found by its nullifier,
   and a key deletion that its cancellation queued under the former id is
   withdrawn as well.)
4. The reservation agrees with it: its row exists, its kind is
   `openrouter_lease`, and its `client_request_id`, `payload_hash` and
   `api_request_binding` match. The request having verified, the reservation is
   the corrupt side. Its `api_request_binding` is a keccak digest of the
   request, which `sqlite3` cannot compute: run the command again with
   `--rebind`, which rewrites a `Reserved` row's fields from the verified
   request, or re-creates a missing row as `Reserved`. It refuses a `Finalized`
   row (a successor is already signed: restore that row from a backup) and a
   row of the request kept under another nullifier (mis-keyed, not missing:
   repair its `nullifier` column instead). Re-creating a missing row assumes
   that no successor was signed for it: a transcript lost with the row is
   signed again.

Three refusals ask for a repair that the command cannot make: a corrupt
`api_request_binding` together with a saved request that does not verify
(restore that column from a backup), a `Finalized` reservation (restore its
`nullifiers` row from a backup), and a reservation kept under another
nullifier (set its `nullifier` column to the lease's `request_nullifier`).
These are hand edits of the server database, outside the supported runbooks,
and no tested statement is given for them. Make them only with the server
stopped and a fresh copy of the database kept, restore values only from a
backup taken before the corruption, and run `sqlite3` as the server's user
(uid 10001 in the Docker deployment). Then run the command again, which
repeats every check.

`--saved-request` and `--rebind` combine. Once every check passes, the command
returns the lease to settlement with its write-once deadline unchanged, and
prints the lease's new state as JSON:

- `client_request_id`: the lease's id, as corrected by `--rebind`.
- `status`: a lease without a key resumes `provisioning`, a direct lease whose
  usage was captured resumes `revoking`, and any other resumes `active`.
- `settles`, how the restarted server settles it:
  - `zero_never_delivered`: a lease never delivered is committed to its zero
    charge at once, so that a retry of the request cannot issue its key.
  - `captured_usage`: a direct key that may have been delivered was disabled
    and its usage captured before the cancellation. That usage, clamped to the
    solvency bound, is charged at the first tick.
  - `measured_until_deadline`: usage is measured until the deadline, then the
    lease falls back to captured usage or its solvency bound. The command
    withdraws a key deletion the cancellation queued and that has not run yet
    (`key_cleanup_withdrawn: true`), so that the key can still be read.
  - `deadline_fallback`: no usage can be measured, because the deadline has
    passed or because a direct key was deleted before its usage was captured.
    The lease is charged its full solvency bound at its deadline (at once if it
    has passed), and the output adds a `warning`.
  - `operator_conceded` or `signed_transcript`, below.
- `reservation`: `unchanged`, or, with `--rebind`, `rewritten` or `recreated`.
- `lease_row`: `unchanged`, or, with `--rebind`, `rewritten`.
- `saved_request`: `unchanged`, or `restored` from `--saved-request`.

With `--zero-charge` the lease is finalized at zero instead, with `charge_basis`
and `settlement_reason` `operator_conceded`: the operator concedes the request's
charge, as the owner's escape would have, and a direct key is deleted. The same
checks apply: a request that does not verify, or a binding still corrupt, is
not conceded either. `--rebind` and `--saved-request` repair it as for a
reopening, also for a lease reopened earlier whose binding was found corrupt
again: `--zero-charge --rebind`. `--zero-charge` also concedes a lease
reopened earlier that is not settled yet, for instance after a
`deadline_fallback` warning; run it before restarting the server. A request
whose successor is already signed settles from that transcript and cannot be
conceded. Each reopening, and each later concession of a reopened lease,
acknowledges the lease's open `binding_corrupt` reviews and records a
`binding_reopened` review, so a lease has one such review for each of those
runs to acknowledge.

The restarted server verifies a reopened lease's saved request again, and
checks its binding, deployment and signing key, before it signs anything; a
lease that fails is cancelled again with a new review. The owner's wallet
installs the signed receipt through its ordinary recovery, as for any finalized
lease. If the owner already escaped from that state, the server defers the
signature while the escape is pending and the challenger raises the escape to
the settled charge. Reopen before the note expires, or its deposit goes to the
treasury.

## Restoring an unreadable pending lease

A pending lease (`provisioning`, `active`, `retiring`, `disabled` or
`revoking`) whose row cannot be decoded, normally because its saved request
cannot be, is never settled, as described under
[settlement terminality](#settlement-terminality). The server
cannot cancel it either, because it cannot read the request that a review
needs. Restore the request with the reopen command and `--saved-request`, with
the server stopped, exactly as for a cancelled lease:

```sh
dc stop server
dc run -T --rm --no-deps --entrypoint zkapi server settlement reopen \
  --db-path /data/server.db --client-request-id "$ID" --saved-request - < request.json
dc start server
```

`$ID` is the `client_request_id` that the log line names. Take `request.json`
from a backup of the server database or from the lease's owner, as in step 2
of [Reopening a cancelled lease](#reopening-a-cancelled-lease). The copy is
accepted only after the same checks: it verifies against its proof with the
server's proof setup, its binding is the `api_request_binding` that its
reservation recorded at admission, and it shares the lease row's
`client_request_id` or `request_nullifier`. The lease row and its reservation
must then agree, or the command refuses and names the field, which `--rebind`
repairs as for a reopening. A `ClearanceReserved` nullifier is refused. The
command refuses a pending lease whose saved request can be read. When the rest
of its row can be read too, the server settles that lease itself, and cancels
it if its binding is corrupt. When another column cannot be decoded, the lease
is skipped just the same: it still answers `lease_record_unreadable` and the
log line keeps naming it. The command then refuses with `another column of its
row cannot be decoded`, naming the column, and that column needs a hand repair
as described under [Reopening a cancelled lease](#reopening-a-cancelled-lease)
before the server settles the lease.

The restored lease keeps its status, its write-once deadline and any charge
already committed, and the command prints `"result": "restored"` with the same
fields as a reopening. Its `settles` field says how the restarted server
settles the lease:

- `measured_until_deadline` while its deadline is ahead;
- `deadline_fallback` with a `warning` once its deadline has passed, because
  the deadline applies at once on restart and charges the full solvency bound;
- `captured_usage`, `zero_never_delivered`, `operator_conceded` or
  `signed_transcript` as for a reopening.

To concede the charge instead, run the command again with `--zero-charge`
before starting the server, or pass `--zero-charge` together with
`--saved-request`. The restoration records a `binding_reopened` review, and the
server verifies the restored request again before it signs, as for a reopened
lease. Acknowledge that review once the lease is `finalized`. Restore before the
note expires, or its deposit goes to the treasury.

A row that stays undecodable after its request is restored has another corrupt
column. The command then fails with a database error, and that column needs a
hand repair as described under
[Reopening a cancelled lease](#reopening-a-cancelled-lease).
