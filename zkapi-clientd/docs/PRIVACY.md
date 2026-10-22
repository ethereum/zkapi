# Client privacy and recovery boundaries

`zkapi-clientd` runs on the user's computer. An OpenAI-compatible UI sends its
prompt to the loopback API; the daemon acquires a short-lived OpenRouter key
through the zkAPI proof protocol and sends inference directly to the provider.
The wallet/prover helper receives neither prompts nor responses nor model IDs.
The provider sees the inference content. Client applications may store their
own transcripts; the daemon cannot hide content already given to that UI.

The wallet companion fetches `/v1/tree/snapshot` and derives note paths locally,
as the web client does. It checks the leaf count and recomputed Merkle root
before using the snapshot for requests or withdrawal checks, and proves a
request against it only once the vault's `currentRoot()` at the snapshot's
block confirms that root. These lookups send no note ID to the indexer. An
unavailable, invalid or unconfirmed snapshot never triggers a per-note lookup:
request preparation rebuilds the path from the vault's own state through the
deployment's RPC instead, and exits need no path at all (vault revision 4).
This requires an indexer with the snapshot endpoint and downloads the whole
leaf vector, including retired leaves. The indexer still sees the connection
and lookup timing.

Web search is enabled by default through OpenRouter's web plugin. OpenRouter
or its search provider processes search queries derived from the inference
content, and search charges apply to every completion, including background UI
requests. Stop `serve`, run `zkapi-clientd config --web-search=false`, then
restart `serve` to disable automatic search. Explicit `:online` model requests
still enable search. The saved preference is preserved across updates.

Direct HTTPS is the default. It exposes the source IP to destination services
and uses local DNS, so network timing/IP can correlate activity even though
credential issuance is unlinkable. Optional Wisp carries destination TLS with
certificate verification and hides the source IP from destination services;
the relay still sees connection metadata. A configured relay failure never
falls back to direct HTTPS. A loopback SOCKS5 route can send destination DNS
and HTTPS traffic through Tor when Tor is running locally. It also fails closed
if the proxy is unavailable. Environment proxy variables are ignored.

Explicit `tor://IP:PORT` mode additionally assigns random SOCKS authentication
identities to conversations. Tor must enable `IsolateSOCKSAuth`; the daemon
cannot inspect that setting through SOCKS. The full previous request's messages
must be a prefix of the current messages to keep the identity. A new identity
also discards the cached provider key. Payment and other background traffic get
separate per-connection identities. No raw prompt is retained for matching,
only message hashes in memory. Identical histories are indistinguishable;
interleaved or edited chats rotate conservatively. This is not a multi-user
security boundary, a guarantee of different exit IPs, or protection against
traffic timing analysis. See [Tor mode](CLI_ZKAPI.md#tor).

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
follow-up requests. In explicit Tor mode this is restricted to prefix-continuing
conversations; unrelated histories never share the cached key.
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
The journal is written and synced to disk, under a temporary name and then
under its own, before its request is sent, and the note state it settles into
is synced the same way before the journal is cleared, so a power loss leaves
neither a sent request without its journal nor an empty journal file.
A journal that was sent is never deleted without installing its signed
response. When an unsigned answer sets one aside, it moves, whole, into an
append-only archive (`request_archive/` in the companion's state directory,
owner-only like the journal, never pruned, and holding the same
prompt-free lease authorization and proof as the journal). Each record is
written and synced under a temporary name before it gets its
`<milliseconds>-<sequence>.json` name; other files there are ignored, and a
record that cannot be read is skipped by recovery and treated as an
unsettled request by withdrawal. A journal is set aside after a
`stale_root` reply, or when withdrawal settlement finds a request the
server reports unknown, but in both cases only once the pinned vault's
`currentRoot()` (read over the packaged RPC) no longer equals the request's
root and the server reports the request's nullifier unknown too; while the
vault still has that root, or the root cannot be read, the request stays
pending and the next lease attempt resends it unchanged. Withdrawal
settlement also sets aside a request whose nullifier the server reports
reserved for a clearance (an earlier withdrawal, or the operator's release
of a stuck state), without reading the root: the server refuses every
request at such a nullifier whatever the root, so it could never settle.
Chats at such a state stop with `clearance_reserved_state` and keep the
request, resending only it. Once withdrawal settlement has set it aside, a
chat first asks the server's record of that nullifier again and proves
nothing while the server still reports the reservation, or cannot be asked,
so chats send no new request proof from that state. A journal is
also set aside after the server's
`/expire` acknowledgement of a never-admitted native request, when a wallet
reset replaces an unspent note, and, as superseded, when the note has
already moved past the state it was proved at. Explicit recovery
(`/wallet/recover`), a chat request that opens a new lease, withdrawal settlement and
withdrawal preparation also ask the server's nullifier record about
requests archived at the note's current state, and install a finalized
response for one of them only when it verifies. The daemon's background
recovery, every 5 seconds, asks only about a pending request, so it sends
nothing while the note is idle. Stopping or failing recovery keeps the
original note and request for retry.

Inference is loopback-only and key-free by default. Other local processes can
use it. Optional local API-key authentication affects only the UI-to-daemon hop.
Browser Origins, unexpected Host values and nonloopback peers are rejected.
Wallet routes always require both the local API credential and a separate
owner-only management credential. Incoming cookies, identity headers and
account/storage metadata are stripped before inference.

A local Ethereum signing key and private recovery journals are stored in
owner-only files. Public funding addresses, amounts, withdrawal destinations
and chain transactions are visible to RPC providers and chain observers. The
client sends chain reads and transactions only to the RPC packaged with the
release, and to your own exit RPC when you configure one
(`config --exit-rpc-url`), and refuses a wallet companion that reports another
RPC, indexer or protocol server. Deployment checks then also run through the
exit RPC, and an escape reads and sends its transactions only through it, so
that RPC's provider sees the note's exit and your interest in the vault, as
any wallet's RPC would. A gasless escape (`--escape --fees payout`, its
initiation or its sponsored finalization) is the exception: its operation is
sent to the bundler, the deployment's (run by the operator) unless you set
your own `--bundler-url`, never through the exit RPC, so that bundler learns
of the escape before inclusion and can delay or drop it. For an escape that
must not depend on the operator, use `--fees wallet` or your own bundler. An
exit RPC on another chain is never trusted.
Deposit/withdrawal QR codes are generated locally and contain only public
payment address, chain and amount. No external QR service receives them.
A withdrawal fee QR funds the local signing address, never the private payout.
With the fee paid from the payout (the only new withdrawal where the
deployment sponsors withdrawals) no local signing address pays for the
withdrawal and no withdrawal fee QR is needed; a quote shows the RPC and the
bundler neither the exit proof nor a valid signature, only the approved
operation reaches them; a fresh owner key per withdrawal signs the
operation and the payout address appears on chain only as the transit
account's payee. The bundler (the deployment's, or your own `--bundler-url`)
sees the operation and your client IP before inclusion, as an RPC does.

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
mined receipt, canonical block and deposit event are validated, and the vault
agrees: `noteRecord(noteId)` at the receipt's block hash must show the note
Active with exactly this deposit's leaf. A vault of revision 4 stores only each
note's leaf, which commits to the note ID, the commitment, the amount and the
expiry (from the receipt's `NoteDeposited`), so Go recomputes the leaf and
compares it. When the zkAPI indexer's whole-tree snapshot covers the receipt's
block, it must show the same leaf at that note; an indexer that is down or
behind is skipped. The note secret reaches the wallet companion only after
this. The vault read goes to the packaged RPC, which already serves the
deposit and sees its note ID in the public deposit event. The snapshot is the
same response for every client, so the indexer does not learn which note is
yours. Disagreement leaves the deposit in `verification_conflict`; nothing is
activated, retired or replaced until a later check agrees. Success does not
wait for Ethereum finality. Failed receipts retain the finality gate before
explicit retry; a deposit signed by this release is also retired only after
the indexer shows its note did not land. Because the RPC can withhold a
deposit and relay it after that check, a retry is signed only when a bounded
search of the indexer tree it is built from finds none of the note's earlier
deposits (CLI_ZKAPI.md describes the bound). That search uses the same
whole-tree snapshot. A quote repeated while the tree is unchanged reads only
the tree's root, which is also the same response for every client. So the
indexer still cannot tell which note is yours. Repair (rebind) reads the
vault's own leaves (`noteLeaves`) at the finalized block instead, the same
call for every note range it covers. Missing or ambiguous receipts preserve
the exact signed transaction without authorizing a replacement. Withdrawals
and public ETH returns require their own finality checks, and a withdrawal
completes locally only after the vault shows the note Closed at the payout
block, through the packaged RPC and, when you configured one, your exit RPC.
A close leaves the note's leaf in the tree, so the indexer cannot attest it.

Pre-finality activation exposes the same reorganization risk as the web wallet:
a block can be replaced after a private note or inference credit becomes usable.
The wallet does not provide complete rollback and reconciliation for that
event. Local reset cannot undo credit already issued, and later inference
or withdrawal may require recovery. Canonical receipt validation establishes the
observed chain state, not a guarantee against a later reorganization.

A withdrawal builds two withdrawal proofs. The first, an ownership proof
(kind 2), goes to the protocol server with the clearance request; its public
statement shows the server the note ID, the payout amount and the note
state's nullifier before the close transaction publishes them. It names no
destination (it is zero) and the vault accepts it neither as an escape nor
as a close. The companion keeps the proof it sent in `exit_lock.json`
(owner-only) so a retry resends the same statement instead of a new one, and
it sends no chat request from that note state afterwards. The close (kind 1)
publishes the note ID, payout and destination on chain, as before. Every
withdrawal statement of vault revision 4 also carries the note's leaf, its
deposit amount and its expiry; all three are already public through the
note's `NoteDeposited` event, and no Merkle root or path is involved.

An escape (kind 0) publishes the note ID, the balance, the destination, the
conceded amount, the proof's validity time (to within 3 hours) and the next
state's nullifier, which is never used. Just before it is sent, the
companion asks the server whether that next nullifier was already spent by
another device; the server then learns it slightly earlier than the chain
does, and if the escape never lands, a later request at that nullifier is
linkable to the question by timing and network address. An escape conceding
the state's bound links the note's last request to the note ID and the
destination for the server and the gateway, and the amount publishes that
request's tier. An escape conceding nothing can be raised by the operator
with the last request's signed charge, which publishes that request's public
inputs (time, tier, root, tag) on chain. Waiting for settlement and a mutual
close link nothing new, so the companion prefers them, and escapes only when
the exit rules require it or you ask for an early exit. An exit kit contains
the note secret, encrypted with your passphrase; it never leaves the files you
write it to.

A request discarded by an earlier release left no archive record, so its
state is not recognized. When the server reports the note's current
nullifier settled by a request the wallet holds no record of, chats and
withdrawal stop with `receipt_journal_missing` and show that nullifier
locally, for the owner to give the operator; giving it links the owner to
that request.

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

The protocol is experimental. Production companions load only the keys of
the multi-party setup, which has not run yet; until then the Mainnet profile
is a placeholder and no Mainnet note can be funded. The Sepolia staging
deployment (zkAPI v0.2) uses the committed development setup, whose keys come
from no ceremony, so it must only ever hold test ETH. See the
repository's [concession exit design](../../docs/design/concession-exit.md)
and [native ETH architecture](../../docs/architecture.md).
