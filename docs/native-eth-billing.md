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
and reentrancy protections. Failed recipient transfers revert the complete close.

The deployment manifest pins the vault address, native asset, and circuit
`zkapi-v2-note-bound-v1` with its exact setup/WASM/key hashes. The circuit binds
each signed balance to its deposit note. Challenges preserve the historical
request root and use a current restoration path. See
[Note-bound commitments](note-bound-commitments.md).

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
`trusted_deployment.circuit_id` must equal `zkapi-v2-note-bound-v1`, and all
request/withdrawal proving and verifying key hashes must match that setup. The example feed is Sepolia; it does not select a production feed.
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
restart or an oracle outage cannot reprice an existing lease.

An accepted reservation does not authorize new access after its state has been
withdrawn. Before contacting either provider to create a key, including an exact
reserved/provisioning retry, the server checks the configured chain ID and the
vault's `usedNullifiers(request_nullifier)` at `latest`. Only an explicit ABI
`false` permits issuance. Consumed nullifiers return `nullifier_used`; unavailable,
wrong-chain or malformed RPC responses fail closed with a retriable server error.
This live authorization read does not refresh the frozen quote or require the
original Merkle root to remain current after unrelated deposits.

After provider creation, the server durably activates the lease and repeats the
same check before returning its secret. If a withdrawal consumed the nullifier
during provider I/O, or the read fails, no key is returned. The active record is
retained for challenge evidence and normal status/settlement recovery; the server
does not erase an already issued key's accounting obligation. RPC availability
is therefore required for new key delivery, including retries. Existing lease
status and settlement recovery do not require this issuance check.

A withdrawal started after key delivery still requires timely operation of the
challenger. These checks do not replace the configured challenge window, a
trustworthy view of the selected chain, or sufficient operational time to observe
and challenge a stale escape. The deployment's 24-hour window is unchanged.

For ledger units `U`, oracle integer answer `P`, and decimals `D`, the upstream
budget in micro-USD is:

`floor(U * P * 1,000,000 / (1,000,000,000 * 10^D))`.

The OA org still receives and signs micro-USD limits and measured usage; it does
not need native-token pricing support. For measured usage `C` in micro-USD the
native charge is:

`ceil(C * 1,000,000,000 * 10^D / (P * 1,000,000))`.

Zero usage stays zero. Integer conversion is checked for overflow and browser
safe bounds. The signed state transition charges gwei and remains capped by the
proof's solvency bound. Issuance and the settlement response payload echo the
exact quote so the browser can compare it with its persisted journal.

A `native_quote_expired` response is emitted only before any nullifier
reservation. Freshness is rechecked after all oracle awaits and after proof
verification immediately before reservation, with equality treated as expired.
Issuance attempts share one lock, so an exact POST that returns this rejection
has also waited for earlier in-flight attempts. A local clock or an unknown GET
alone does not authorize deleting a journal; startup remains read-only.
`POST /v2/openrouter/leases/{id}/expire` accepts the exact saved request and waits
on the same issuance lock. It returns `expired_unaccepted` when the server clock
says the quote expired, or when the exact request's public `request_time` is
older than the 300-second admission window (`request_time + 300 < now`), which
admission can never accept again because its age only grows. A future
`request_time` alone never justifies expiry, because such a request can become
admissible; an independently expired or superseded quote still can, under the
same exact-binding and unaccepted checks. It returns
`superseded_unaccepted` when a newer finalized round exists,
with the exact request ID, nullifier and payload hash. Both acknowledgments
require that neither its nullifier nor request ID has a reservation. Superseded
recovery relies on Ethereum finality: an ordinary head reorganization cannot
revive the old quote. A finalized-chain safety violation is outside this model,
as it is for the private note's confirmed chain state. This endpoint is
read-only: it never generates a key, signs, reserves or cancels anything. Every
other result preserves the journal. It allows interrupted startup/withdrawal recovery without
starting a chat solely to test whether an old proof is still issuable. Matching
reserved/provisioning requests retain their old quote and remain recoverable
after expiry. Other errors do not authorize discarding a
pending journal. `POST /v2/requests` has been removed; all new authorizations
require prompt-private leases with a proof-bound native quote.

## Deployment

The deploy script creates a native-only vault and accepts `REQUEST_CHARGE_CAP`
in gwei. It checks an optional `CHAIN_ID` against the connected chain. Publish
a manifest that pins the resulting vault, circuit artifacts, signing keys, and
native asset configuration.

Start the native server with its vault/chain/request cap and
signer, indexer, proof and OA-source settings, plus:

```sh
zkapi ... serverd ... \
  --native-billing-rpc-url "$RPC_URL" \
  --native-price-feed-address "$ETH_USD_FEED" \
  --native-price-feed-decimals 8 \
  --native-price-max-age-seconds 4500
```

The server requires native oracle and prompt-private lease configuration.
Operate the compatible v2 [challenge daemon](challenge-service.md)
alongside server and indexer, with a dedicated funded signer restricted to the
configured vault. It reads the exact historical request root from the native server's
finalized transcript or exact active-lease request and uses a current zero-slot
restoration path. A missing station usage receipt does not prevent an already
issued lease from being challenged. Native usage
settlement preserves the original proof/public inputs required for that challenge.
Do not reuse a daemon, verifier or setup from another circuit. Configure the published manifest separately; these flags do
not rewrite static frontend manifests. The browser SDK handles funding and
withdrawals; the operator CLI runs setup, signing-key, server and indexer commands.

OA provisioning retries accept a shortened remaining lifetime only when the
relay explicitly marks the station response `replayed: true`. Its original
expiry stays unchanged and must remain in the future and within the requested
maximum TTL; absent flags and ordinary new issuance retain strict lifetime
bounds. Expired replays remain pending/error recovery rather than creating a
second key for the same accepted request.

Native OA issuance uses a deployment-bound upstream request ID: a versioned
Keccak domain hash of the complete accepted request binding (chain, vault,
nullifier, browser request ID, payload/quote, and proof). This separate ID is
persisted atomically with the lease and reused for key issuance and usage
recovery. It prevents two deployments that share an org from redeeming the same
key by choosing the same browser request ID. The browser-visible ID stays
unchanged. OA lease recovery rejects a missing or mismatched native upstream ID.

## Recovering rejected OA provisioning

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
settlement request finishes it. A tracked request with no issuance attempt can
also be retired, or recovered by the scanner after its original settlement
deadline. Cancellation excludes concurrent issuance, verifies the saved full
request, deployment, signer, quote, allowance and upstream ID, and requires an
explicit unspent-nullifier RPC result before signing. A persisted signed
successor is reused after a crash; it is never replaced with a new signature.
Active leases still require normal provider usage reconciliation. Their network
waits do not hold the global issuance lock.

Historical rows migrate conservatively to `may_have_issued`. After their
settlement deadline, these and ambiguous attempts enter read-only issuer
reconciliation. An exact saved-proof settlement request can also start it.
Authenticated `POST /api/zkapi/reconcile_key` reads the org's existing durable
issuance binding; it never creates, replays or returns a plaintext key, consumes
issuance quota, or writes issuer state. The server validates request namespace,
cap, integer credits, duration, station request ID and expiry bounds, then
atomically records the existing key hash and original expiry. Normal
station-signed actual-usage settlement supplies the successor signature using
the frozen quote. Expired provider keys can follow this path. Usage outages
preserve the active metadata and retry normal settlement after restart.

A missing issuer binding, unavailable endpoint, malformed/mismatched response,
or unknown outcome stays pending. This API has no durable cancellation fence
for unknown issuance and never authorizes an automatic zero-charge refund.
Reconciliation does not apply current issuance policy caps, but the existing
usage endpoint still requires those caps and the server's configured TTL to
be compatible with the historical lease. Incompatible policy changes fail
closed and need operator reconciliation rather than refunding automatically.

A crash after nullifier reservation but before the lease row is created still
requires exact issuance replay. This cancellation path cannot infer an outcome
from that incomplete state and does not clear the reservation.

Every file-backed signing processor holds an exclusive database sidecar lock
for its lifetime. Challenger reads remain available. Stop all older server
writers before deployment: old binaries and manual database writes do not honor
this lock. Preserve the sidecar, database and backup together; never unlink the
lock to bypass an active writer. Do not downgrade a migrated live database to an
older writer, whose issuance does not update the new outcome field. Rollback
requires a compatible writer or stopped-service reconciliation of affected
provisioning rows, not restoring an old database over newer wallet activity.
