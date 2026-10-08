# Client privacy and recovery boundaries

`zkapi-clientd` runs on the user's computer. An OpenAI-compatible UI sends its
prompt to the loopback API; the daemon acquires a short-lived OpenRouter key
through the zkAPI proof protocol and sends inference directly to the provider.
The wallet/prover helper receives neither prompts nor responses nor model IDs.
The provider sees the inference content. Client applications may store their
own transcripts; the daemon cannot hide content already given to that UI.

Embeddings and video requests take the same path. A video job's record holds
the local and provider job IDs, its key until release, status and cost; it
holds no prompt or video and is kept only in memory. The provider retains
generated video briefly so it can be retrieved; OpenRouter does not offer
zero data retention for video generation.

Direct HTTPS is the default. It exposes the source IP to destination services
and uses local DNS, so network timing/IP can correlate activity even though
credential issuance is unlinkable. Optional Wisp carries destination TLS with
certificate verification and hides the source IP from destination services;
the relay still sees connection metadata. A configured relay failure never
falls back to direct HTTPS. A loopback SOCKS5 route can send destination DNS
and HTTPS traffic through Tor when Tor is running locally. It also fails closed
if the proxy is unavailable. Environment proxy variables are ignored.

The client keeps the deployed manifest/contract pins and normal station/key
verification binding. Unverified continuation requires the compiled `oa-station`
Ed25519 public key, scoped to `https://verifier2.openanonymity.ai`, and local
verification of the station signature over the exact station ID, provider key
and integer expiry. This fallback pin remains scoped to the Sepolia verifier;
Mainnet's production verifier requires ordinary matching verifier approval.
The web client has the same pin scope. A station name,
`station_recently_attested` flag or live broadcast cannot add a trusted station. Unknown stations still need a matching
successful verifier approval, including during rate limiting and outages.

For that pinned station, the client may continue through a verifier outage or
refusal such as HTTP 401 `Invalid org signature`. Invalid station signatures block
fallback. Known bans at verification, expired keys and mismatched verifier
bindings block access. TLS,
redirect, cancellation, response-size and lease/cap/origin checks remain in
force. The same compiled pin is used by the web app. Its initial provenance is
the HTTPS verifier broadcast observed on October 1, 2026; operator identity was
not independently confirmed through another channel. This release accepts that
one-time trust bootstrap. A pin rotation requires a reviewed client release.

This exception trusts the station identity; it does not establish org-signature
validity, provider-account ownership or provider logging/training settings.
Fallback remains `verified: false`, with `verifier-unavailable` status and the
fixed `trusted_station_fallback` detail. A fixed warning explains the reduced
assurance without exposing keys, station signatures or verifier response bodies.
One verification result remains with its acquired key for the configured fixed
reuse window; there is no background re-verification or ban polling. The gateway
accepts fallback only with the `trusted_station_fallback` detail that identifies
this station-pin check.

The default key-reuse window is a fixed 60 seconds from acquisition, capped by
the provider's expiry; reusing a key does not extend it. Compatible requests can
share access, including different chats, local clients, and automatic title and
follow-up requests.
The provider can link all requests using the same key, and its original
aggregate spending cap is shared. Expiry, errors and cancellation discard
cached access. The cache is memory-only and does not survive a restart.

An explicitly saved window is preserved across updates. Profiles without a
saved window use the default. Stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve` to
disable reuse; keep the same `--config-dir` if set.

With reuse disabled, every inference request gets fresh access without needing
a conversation identifier from the UI. A value from 1 to 300 sets the fixed
reuse window in seconds. The daemon starts settlement when the window ends,
without waiting for another request. Any active provider response finishes
first. With reuse disabled, settlement starts after each response. When an
earlier lease blocks the next fresh key, the daemon also requests settlement
instead of waiting for the key's full expiry. The helper recovers pending or
ambiguous outcomes without repeated retirement requests. Signed settlement
can still take several minutes.

For interrupted provisioning, settlement first sends the exact saved proof to
the server's authenticated retirement endpoint. A server that still reports
`lease_pending` can be retried using that original issuance request, including
its frozen quote and spending bound. The helper validates the returned lease
and OA key before retiring it; that recovered credential never enters the
inference cache or bridge response. A confirmed unissued cancellation advances
the wallet only through the normal matching signed response. Missing keys,
expiry, HTTP errors and ambiguous issuance never authorize clearing a journal.
Stopping or failing recovery keeps the original note and request for retry.

Inference is loopback-only and key-free by default. Other local processes can
use it. Optional local API-key authentication affects only the UI-to-daemon hop.
Browser Origins, unexpected Host values and nonloopback peers are rejected.
Wallet routes always require both the local API credential and a separate
owner-only management credential. Incoming cookies, identity headers and
account/storage metadata are stripped before inference.

A local Ethereum signing key and private recovery journals are stored in
owner-only files. Public funding addresses, amounts, withdrawal destinations
and chain transactions are visible to RPC providers and chain observers.
Deposit/withdrawal QR codes are generated locally and contain only public
payment address, chain and amount. No external QR service receives them.
A withdrawal fee QR funds the local signing address, never the private payout.

Waiting for ETH and refreshing quotes do not authorize transactions. For a
guided deposit, Enter approves the fixed principal with fees that adjust
automatically while the receiving balance covers the deposit and required
fees. The signer caps fees to the fresh quote and available balance. A renewed
shortage requires another Enter once funded. Withdrawal fee increases still
require renewed approval. Fresh quotes preserve network/deployment/address/
note/payout/nonce bindings. A lost reply is recovered from durable state, not
a blind second approval. Signed pending operations resume their exact bytes;
reverts never automatically sign a replacement. Wallet state is preserved
across updates.

Successful native ETH deposits activate after the saved transaction's successful
mined receipt, canonical block and deposit event are validated, matching the web
wallet. Success does not wait for Ethereum finality. Failed receipts retain the
finality gate before explicit retry; missing or ambiguous receipts preserve the
exact signed transaction without authorizing a replacement. Withdrawals and
public ETH returns require their own finality checks.

Pre-finality activation exposes the same reorganization risk as the web wallet:
a block can be replaced after a private note or inference credit becomes usable.
Current wallet/indexer state does not provide complete rollback and reconciliation
for that event. Local reset cannot undo credit already issued, and later inference
or withdrawal may require recovery. Canonical receipt validation establishes the
observed chain state, not a guarantee against a later reorganization.

The daemon creates no request-history log files. Foreground output includes
HTTP route/method/status/timing, local sequential `request=` numbers and local
key serials (`key_ref=`). Selection reports `source=fresh` or `source=reused`;
release reports `response_complete=true` or `false` and whether the key is
retired locally or available for reuse. Local retirement describes the daemon's
reuse policy, not proof of provider revocation or wallet settlement. Wallet
session numbers are independent of these key serials, especially after restart.
Background settlement logs include the local key serial, start, result and
duration.
Session ends, costs and remaining ETH balances are logged only after signed
settlement. Terminal redirection or service managers can retain that activity
and financial metadata. Prompts, responses, secrets, raw session identifiers,
proofs and provider credentials are not printed. Session events are a bounded
in-memory feed, not a ledger.

Only coarse reviewed model spending buckets reach the helper. The client
continues reading the existing public `/chat/model-tickets` pricing-policy
endpoint, which is also used by the web client; that does not add ticket
wallet, issuance or redemption support. Exact balances and prompt sizes do
not choose the bucket.

The protocol is experimental and uses a single-party Groth16 setup. See the
repository's [note-bound commitments](../../docs/note-bound-commitments.md)
and [native ETH architecture](../../docs/architecture.md).
