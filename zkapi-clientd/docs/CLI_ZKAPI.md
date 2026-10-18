# Client configuration and use

The public commands are `zkapi-clientd config`, `zkapi-clientd serve`,
`zkapi-clientd withdraw`, and `zkapi-clientd list-models`.
The client only supports zkAPI private ETH balances. Ticket issuance, import,
redemption and ticket-based inference are not included.

## Per-response costs and Tor diagnostics

Every chat response logs `response cost: provider-reported USD=...` when its
JSON/SSE `usage.cost` is present and valid and delivery completes. This is an
**unverified provider figure**, not the wallet's ETH charge. Missing/invalid usage
or incomplete delivery logs `unavailable`, never an invented zero. Streaming
requests set `stream_options.include_usage=true`; extra usage frames are forwarded
unchanged. No extra paid request or per-response key retirement is performed.
Verified ETH charges still arrive separately at key-session settlement and can
cover multiple responses sharing that key. Cost logs contain no prompt content
and are emitted in normal and diagnostic modes. Successful Tor dials are silent;
diagnostic mode reports failures only, without claiming circuit/exit verification.

## Configuration

Bare `config` prints only pretty JSON with credentials/secret URL components
redacted. It has no wallet or network side effects. All saved options, including
vault/model/rewriter/cover, are under `config`; see [settings reference](CONFIGURATION.md).
The top-level `set-*` commands are removed.

Explicit `config --setup` creates the private configuration directory and defaults to
Ethereum Mainnet, direct HTTPS and a loopback listener at `127.0.0.1:8787`.
It asks for the deposit amount in USD, defaulting to $20 on Enter, and shows the
ETH amount, receiving address and locally generated QR. It waits automatically
for ETH and updates the receiving balance. Once funded, Enter approves the
fixed deposit with network fees that adjust automatically while the receiving
balance covers the principal and required fees. It checks a fresh quote before
signing, deposits, and saves the private note once its successful mined
receipt is validated against the canonical block and saved deposit, and the
vault state and the zkAPI indexer record the same note (see
[chain verification](#chain-verification-and-recovery)). There is
no additional 15-minute finality gate for successful native ETH deposits, matching
the web wallet. No model is selected or priced during funding.

A deposit only records its note in the vault (vault revision 4). The
operator's batches then activate recorded notes in order, inserting each
into the vault's tree, usually within a minute. A recorded note can be
withdrawn at once, by a mutual close or an escape, but pays for requests only
once it is activated. Until then the funding status reports deposit stage
`awaiting_activation` with `activated: false`, the vault's
`activation_cursor` and the note's `activation_queue_position` (the notes
activated before it), as the wallet companion reads them from the vault;
`zkapi-clientd status` reports the same `activated`, `activation_cursor` and
`activation_queue_position`. A request in the meantime waits up to five
minutes for the activation, then fails with `note_not_activated` (no key is
issued; retry later).

If the last fee or balance check leaves the deposit unsigned, configuration
refreshes the same fixed deposit and continues watching instead of exiting.
Interrupted approval responses are checked against saved progress before any
retry. Higher fees do not require another Enter while the deposit remains
funded, even if the recommended buffer is no longer fully covered. A renewed
funding shortage requires Enter again once funded. The recommended fee buffer
remains optional; the signer caps fees to the fresh quote and available balance.

After signing, progress distinguishes waiting to be mined, waiting for network
fees to fall below the signed cap, saving the private note, and its
activation. In an
interactive terminal, payment details and progress update in place, with a
spinner and elapsed time while waiting. Enlarge a short terminal to show the
payment QR; the receiving address and amounts remain available as text. Prompts
pause the display while you answer. Redirected output and `TERM=dumb` use plain
status messages without animation. The same signed transaction is retried; the
client never silently raises its fee cap or sends a second deposit.

A failed receipt still waits for Ethereum finality before an explicit retry is
allowed. An unavailable or ambiguous receipt does not establish success or
permit a replacement transaction; recovery retains the exact saved transaction.
Withdrawals and public ETH returns require their own finality checks.

As on the web, activation before finality accepts the possibility of a chain
reorganization after the note becomes active. The wallet and indexer do not
provide complete rollback/reconciliation for that case, and already issued
inference credit cannot be undone by resetting the local wallet. See
[recovery boundaries](PRIVACY.md).

```sh
zkapi-clientd config --status           # show saved settings
zkapi-clientd config --edit             # change settings
zkapi-clientd config --usd 50           # amount for a new deposit
zkapi-clientd config --menu             # withdrawal and wallet actions
zkapi-clientd config --require-api-key  # require a local inference key
zkapi-clientd config --api-key          # show that key when requested
zkapi-clientd config --key-reuse-window-seconds 0  # fresh key per inference request
zkapi-clientd config --exit-rpc-url https://rpc.example  # your own RPC for exits ('none' clears it)
```

Use the arrow keys (or `j`/`k`) and Enter to select wallet actions and networks.
Esc or `q` cancels a selection. Text prompts remain available when output is
redirected. Ctrl+C stops safely and preserves saved progress; run
`zkapi-clientd config --setup` again to continue.

### Model catalog and default selection

```sh
zkapi-clientd list-models                 # sorted IDs and per-query USD caps
zkapi-clientd config --model provider/model    # validate syntax and save offline
zkapi-clientd config                           # show all saved settings
zkapi-clientd config --clear-model           # remove it
```

These use the selected configuration profile (`--config-dir` goes before the
command). Catalog listing uses public endpoints through the saved relay/Tor
transport; setting a model only validates syntax offline. No funded note,
running daemon, companion or paid key is needed. The list marks the saved default. Caps are spending authorizations,
not predicted token charges.

Stop `serve` before changing the default: `config --model` uses the same exclusive
configuration lock and atomic update as other settings, preserving credentials
and wallet files. The saved default supplies `model` only when an inference
request omits the field; explicit models take precedence and invalid explicit
values still fail validation. It also supplies the funding recommendation model.
`serve --model MODEL` overrides only the funding recommendation for that run.
With neither a saved default nor `--model`, the conservative funding cap applies.
Saved selection is validated again by inference policy when requests are made.

The saved `default_model` field requires this updated binary; older releases
with strict configuration decoding may reject it. Use `config --clear-model` before
rolling back to an older binary.

### One-command funding and withdrawal

```sh
zkapi-clientd serve --model anthropic/claude-sonnet-4.5
zkapi-clientd withdraw          # guided full private-balance withdrawal
zkapi-clientd withdraw --public # return unused ETH from the funding address
```

**Starting `serve` authorizes opening a missing private note** using the available public ETH minus the quoted maximum network fee allowance,
once the funding address meets the minimum threshold. It displays the chain, ETH receiving address, total required balance and
additional ETH to send, then polls every five seconds. No terminal confirmation
is required for this deposit. Ctrl+C stops waiting and preserves saved progress.
A funded existing note is reused without another deposit. A depleted but still
open note must be closed with `withdraw` before opening another.

For a new deposit the recommended principal is
`max(3 × model per-query spending cap in ETH, 10 × estimated deposit gas in ETH)`.
The total to fund includes the quoted network fee reserve/buffer **in addition**
to this principal; existing public ETH reduces the top-up. The model cap is the
same reviewed policy used by inference, converted using the verified native ETH
price quote—not a prediction of actual token usage. `--model` only selects the
recommendation; it does not constrain subsequent application requests. Without
it or a saved default, the highest currently supported tier ($6 per query) is used. Price/gas are
snapshots. The recommendation is a minimum threshold, not a deposit cap.
When funded, `serve` resizes the unsigned draft to
`floor((public balance − maximum fee allowance) / 1 gwei)` and re-quotes/simulates
that amount before approval. Gas changes can require a smaller requote; repeated
instability stops without approval rather than looping indefinitely. The final
amount becomes fixed for approval/recovery. ETH arriving after that sizing step
is not automatically added. Unused fee allowance and sub-gwei dust remain public.
An older saved unsigned amount serves as the minimum threshold and can grow;
explicit manual/config deposits still keep the selected amount.
A pending signed deposit is recovered, not replaced or enlarged. Uncertain/reverted states
and reserved withdrawals require recovery and are not automatically approved.

`withdraw` prompts for a destination, quotes fees, asks for approval, then waits
for finality or resumes saved progress. This legacy deployment needs public ETH
for withdrawal gas; the command shows any shortfall. After private completion,
`withdraw` also quotes a sweep of the remaining public balance to the same
destination and asks for that transaction's fee approval, without another command.
An interrupted public return resumes its saved transaction. A completed return
is not repeatedly swept for fee dust; use `withdraw --public` for a standalone
return or later funds. Tiny balances may be below the cost of a return.
Actual fees can be lower than the reserved maximum, leaving a public remainder.
Both work without a running daemon by owning a temporary runtime, and leave an
existing compatible daemon running. Missing installation/network prerequisites
still point to `config`. Stop a running service before editing configuration.

## Sepolia

```sh
zkapi-clientd config --network sepolia
zkapi-clientd serve
```

Sepolia requires the deployment's shared access password; configuration asks
with input hidden. Fund with Sepolia ETH, never mainnet ETH. Mainnet and
Sepolia have separate signing keys and wallet state. Switching networks keeps
the other network's recovery data.

## Tor

Run Tor with a numeric loopback SOCKS listener and authentication isolation:

```text
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
```

Select explicit Tor mode once, then use the daemon as an ordinary
OpenAI-compatible server (no `zkapi-tor-cli.sh` wrapper is needed):

```sh
zkapi-clientd config --relay-url tor://127.0.0.1:9050
zkapi-clientd serve
```

Point your application's OpenAI base URL at the daemon's `/v1` endpoint.
For each queued completion the daemon compares the canonical JSON messages
with the immediately preceding request:

- The full previous message array must be a prefix of the new one. Equal
  histories (retries/regenerations) also count. JSON object-key order and
  whitespace do not matter; role, tool calls and multimodal content do.
- A continuation keeps its random SOCKS authentication identity and may reuse
  its OpenRouter key within the configured fixed reuse window, provider expiry
  and unchanged spending cap. A fresh key does not itself change that identity.
- A non-prefix request gets a fresh isolation identity and cannot reuse the
  previous key, even if the key is unexpired. Normal lease retirement/settlement
  completes before another key is obtained. Inference is never auto-retried.
- Comparisons are serialized through the end of the preceding response stream.
  Only the previous request's message hashes are retained in memory, not raw
  prompts; restarting forgets both conversation identity and reusable keys.

This is a history heuristic, not conversation authentication. Identical
histories from different apps are indistinguishable. Interleaved chats,
truncation, edited history, or changing a system message can rotate identity.
Changing only model/generation parameters does not; key-budget checks still
apply. Do not use a shared daemon as an isolation boundary between users.

Tor must honor `IsolateSOCKSAuth`; SOCKS authentication alone cannot verify that
Tor configuration. Different identities cannot share circuits under that
setting, but may use the same exit IP. Keeping an identity lets Tor reuse a
circuit; it does not pin the circuit indefinitely. No global `NEWNYM` is sent.
TLS connections are not pooled across requests. Payment, verifier, model and
RPC traffic use separate per-connection identities, never the conversation's.
The managed companion uses the same Tor SOCKS listener through its local
CONNECT bridge; external companions are rejected in explicit Tor mode.

Remote DNS and HTTPS certificate verification remain enabled. Tor mode requires
SOCKS username/password authentication and never falls back to unauthenticated
SOCKS or direct access. It does not install or start Tor, provide cover traffic,
or hide prompt content from OpenRouter. Timing correlation remains possible.
Plain `socks5://IP:PORT` remains available but has no conversation isolation.

Keep the local API at its loopback URL. Stop `serve` before changing saved
transport settings. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, or `torify` alone
do not select the Go client's route. See [PRIVACY.md](PRIVACY.md) for other limits.

## Live diagnostics

```sh
zkapi-clientd serve --semi-verbose  # compact previews and operation lines
zkapi-clientd serve --verbose       # message content/chunks plus detailed request events
```

These are runtime-only, mutually exclusive flags. Normal mode does not log
prompt/response content. Both diagnostic modes deliberately expose private
content to stdout (and potentially journald, terminal scrollback or log files).
Never enable them on shared logs. Provider keys, SOCKS identities, wallet secrets
and raw remote error messages are not logged. Control characters are quoted to
prevent messages from injecting terminal commands or fake log lines.

Semi-verbose shows received prompt text and final response text using the first
32 and last 32 Unicode characters plus a character count (short messages are
shown once). Prompt messages are joined with newlines; structured multimodal
content and tool calls are represented as JSON. Response previews include
reasoning/tool content when present. Verbose prints content as it arrives,
including SSE deltas, without waiting for the response to finish. A response
record above 1 MiB is omitted from diagnostics and marked `preview_incomplete`;
inference forwarding is not truncated. Partial/cancelled responses are marked.

Conversation lines distinguish new histories from prefix continuations. Tor
start/finish lines measure SOCKS connection establishment, **not** an observed
circuit build: SOCKS does not expose Tor circuit IDs or build/reuse decisions.
Payment lines show the authorized micro-USD cap and key acquisition; wallet
settlement events report the verified ETH charge and remaining private balance.
The current wallet event feed does **not** expose a separate refund/change
amount. The logger says so rather than inventing a refund by subtracting an ETH
charge from a USD cap. Session events are polled every five seconds; transport
and message events are emitted as they happen. Historical retained wallet
session events can be displayed on startup.

The daemon must be restarted with the flag to enable diagnostics; these flags
do not attach to or reconfigure an already-running daemon.

## Deployment origins

The default protocol stack serves circuit `zkapi-v2-concession-v2`, vault
revision 4, with note-bound exits and operator-activated deposits. Sepolia pins
`zkapi-native-eth-sepolia-concession-v2-r4-20261017`, vault
`0x7ff4ba0662a8218d0954c1a11ae61df6c3548ea4`, and the `/v0.3` protocol API.
Its keys are the testnet-only development setup. Mainnet's new-protocol profile
remains `not_deployed` and refuses funding, requests and withdrawals.

Existing revision-3 Sepolia notes use the pinned `concession-v1` engine and
original profile; note-bound-v1 notes use `legacy`. See
[protocol selection](VAULT_PROTOCOL.md). Neither path rewrites a note or uses
revision-4 proof keys for an older vault.

The embedded profiles pin the deployment IDs, contracts, the proof adapter
and Poseidon library, their runtime-code hashes, signing keys, oracle,
challenge period, note term, maximum pause, the settlement window `W`, the
deploy block and the proof setup (circuit, setup ID and key hashes). Wallet
funding and recovery records are bound to the configured network and
deployment. Unknown origins or unapproved manifest differences fail closed.
Do not delete recovery data to bypass a configuration mismatch.

A note of the earlier vault (circuit `zkapi-v2-note-bound-v1`) lives in its
own wallet directory, which this release never opens. When one is still open,
startup prints a warning naming its directory: withdraw it with zkapi-clientd
0.1.7 from the earlier release line (`release/v2-note-bound`), which closes
deposits on that vault and keeps its mutual close and an escape (`withdraw
--escape`, with a runbook in that release's `docs/LEGACY_ESCAPE.md`), then
fund this release.

Payment state (the local signing address and its key, pending deposits and
their recovery records) is kept per deployment as well, in
`funding/<network>/<deployment_id>/` under the configuration directory. The
earlier release kept its own in `funding/<network>/`; this release neither
reads nor changes those files, and startup prints a warning naming them while
they exist. Keep them for the earlier release until its note is withdrawn and
its signing address emptied.

### Deployment checks and the exit RPC

At startup and before every deposit, the client checks through the pinned
RPC, and through your exit RPC when one is configured, that the deployment it
trusts is the one on chain: the runtime code of the vault, its proof adapter
and the Poseidon library hash to the pins, the vault's `proofAdapter()` is
the pinned adapter, and the vault's and adapter's getters
(`stateSigningKeyX/Y`, `clearanceSigningKeyX/Y`, `challengePeriod`,
`noteTtl`, `maxPauseDuration`, `CONCESSION_ESCAPE_VERSION`,
`NOTE_BOUND_EXIT_VERSION`, `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`,
`WITHDRAWAL_VK_HASH`) and `eth_chainId` return the pinned values. A mismatch
refuses deposits with `deployment_mismatch`; exits stay available.

`config --exit-rpc-url URL` saves your own Ethereum RPC (HTTPS, or plain HTTP
to a node on this machine; no credentials, query or fragment). Deployment
checks use it as well, and so do deposit recording, when the operator's
indexer does not record a final deposit, and withdrawal completion (see
[chain verification](#chain-verification-and-recovery)), so its provider
sees those transactions and note IDs (and, under direct HTTPS, your IP
address). An HTTPS exit RPC is reached through the configured transport
(direct, Wisp relay, SOCKS5 or Tor); plain HTTP to this machine is dialed
directly, since no relay or Tor exit can reach it. An escape needs an HTTPS
exit RPC for now: the wallet companion also reads the escape's state
through the exit RPC, and it reaches the network only through the
configured transport, which carries HTTPS alone, so those reads fail for a
plain-HTTP exit RPC and the escape cannot proceed (the saved settings
summary says so). With an HTTPS exit RPC, an escape reads the chain and sends its
transactions only through it (a gasless escape's operations excepted, see
below): the balance, nonce, fee and simulation reads,
the receipts, the raise and finalization logs, the vault's record of the
note the escape proof binds, and the wallet companion's exit state (note
status and logs). The pinned
RPC, which the operator may run, is never asked in its place: a call your
exit RPC does not answer (a timeout, a 429 rate limit, a 5xx) is retried
twice, then the escape stops with an error naming the exit RPC, and you
retry later or configure another one. So a pinned RPC that is down or
answers falsely can neither block an escape nor end one, nor choose the
nonce, gas limit or note record an escape is signed with. `config
--exit-rpc-url none` clears it; escapes then use the pinned RPC, and every
open escape's status warns about it: the pinned RPC then decides when the
escape's exit lock is released and reports whether it landed, was defeated
or paid. Even so, no lock is released before this machine's clock says the
released proof is dead, and a defeat it reports is read again on every run.
But a pinned RPC that fakes the escape's receipts and logs can make it look
finalized and paid while the note stays open on chain, where the operator
can sweep it at expiry. A gasless escape (`--escape --fees payout`: its
initiation or its sponsored finalization) is not a transaction the exit RPC
sends: it is an ERC-4337 operation sent with `eth_sendUserOperation` to the
bundler, which is the deployment's, so the operator's, unless you set your
own (`config --bundler-url URL`, or `--bundler-url` on the command). That
bundler sees the escape before inclusion and can delay or drop it (an
initiation is given up 60 s before its proof's `valid_until`); only the
reads and the inclusion check go through the exit RPC. To escape without
depending on the operator, use `--fees wallet` or your own bundler. Set an
exit RPC before you escape; without one, check
through your own node or a block explorer that the payout reached the
destination (a completed escape's status repeats this). The companion takes
the same setting from `--exit-rpc-url` or `ZKAPI_EXIT_RPC_URL`.

Stop `serve` before installing an update. The installer preserves private files;
updating the repository alone does not update an installed binary.

## Chain verification and recovery

The embedded manifest also pins the payment RPC (`rpc_url`), the zkAPI indexer
(`indexer_url`) and the protocol server (`protocol_server_url`). The wallet
companion must report the same three endpoints; scheme and host case, an
explicit `:443` and one trailing slash are ignored, and any other difference
stops funding before any network read with "reinstall the zkAPI bundle". The
client always sends its chain and indexer requests to the packaged strings.
Transactions are signed for the network's pinned chain ID; the RPC's
`eth_chainId` is only a consistency check.

The RPC is a third party, so its answers are corroborated before they change
private state:

- **Deposit recording.** After a successful receipt, the vault's
  `notes(noteId)` is read at the receipt's own block hash (EIP-1898, canonical
  only), and the indexer's whole-vault snapshot (the same response for every
  client, so it does not reveal which note is yours) must have applied that
  block and record this deposit's leaf at the receipt's note ID. The client
  asks for the snapshot's records part (`/v1/tree/snapshot?parts=records`,
  the same request from every client) and still reads a whole snapshot from
  an indexer that ignores the request. Its
  `note_leaves` hold the recorded leaf of every deposited note, activated or
  not; the client recomputes the leaf with zkAPI Poseidon. The note secret is
  handed to the wallet only after both agree; the note need not be activated.
  While the indexer is behind, unavailable or an older version without
  snapshot block metadata or note records, the deposit stays in phase
  `confirming` with stage `verifying` and polling continues. Disagreement sets
  phase `verification_conflict`. The conflict is not final: running
  `zkapi-clientd config` again checks the saved transaction against the vault
  and the indexer once more, and saves the note if they now agree.
  Otherwise it stops and points to the repair below. The indexer is the
  operator's, so it alone never keeps a deposit from being escaped: with an
  exit RPC set (`config --exit-rpc-url URL`), once the deposit's block is
  final there, the exit RPC stands in for an indexer that is behind, down or
  disagrees. It must serve the same successful receipt in the same block,
  with this deposit's event at the same note, and the vault's `notes(noteId)`
  at that block (canonical only) must hold exactly this deposit. The note is
  then saved and can be withdrawn at once, by an escape if the operator does
  not cooperate; requests still wait for its activation. Its status says so.
  If the exit RPC disagrees, the deposit is a `verification_conflict` and
  nothing is saved. An exit RPC that does not answer or is on another
  network, or that refuses reads at a block hash (EIP-1898) once the deposit
  is final there, is named in the deposit's status (`exit_rpc_unusable`), so
  you can fix it or set another; the deposit keeps waiting, or stays a
  conflict. Without an exit RPC the deposit keeps waiting, and its status
  says how to set one. Repair (below) uses the exit RPC the same way:
  finalized vault state read through it binds a note the indexer does not
  record.
- **Reverted deposits.** A reported revert can be a deposit the RPC withheld
  and relays later, and a second deposit of the same note would share its
  nullifier. So the indexer's next note ID, the slot a deposit is prepared
  for, is saved with the note just before signing, and the slot of every
  deposit signed for the note is kept. Before a finalized failed deposit is
  retired or requoted, and before another deposit of the note is signed, the
  indexer's snapshot (at or after the receipt's block) must record no note
  with this deposit's commitment and amount. Every recorded note is compared,
  activated or not: a deposit is never removed from the note records, and a
  withheld deposit can land any number of notes after its slot. If the note
  is found, the deposit is reported as a `verification_conflict` and no
  replacement is signed. Running `zkapi-clientd config` again checks once
  more; **repair** (below) binds the note that landed. Deposits that reuse
  your public commitment with a different amount are ignored, so they cannot
  block a genuine retry. Quotes run the same search to refuse early. While
  the indexer is unavailable, a quote is still given, but approval signs
  nothing. A saved `verification_conflict` without a pending transaction is
  the exception: there the quote's search decides whether the conflict
  clears, so it must complete, and while the indexer is unavailable the
  quote is refused and the conflict stays. Nothing is signed while this
  device's clock is more than a day from the block time of the indexer view
  the deposit is prepared from, or while the payment RPC does not serve that
  view's header (`eth_getBlockByHash`) hashing to the block the indexer
  names: correct the system clock and retry. A deposit signed by 0.1.6 or
  earlier, or whose `pending-deposit.json` such a release rewrote (dropping
  `slot` and `signed_slots`), has no recorded slot: its reported revert is
  retired, and a retry signed, without this search.
- **Withdrawals.** Before the wallet companion deletes its note state, the
  vault (at the payout receipt's canonical block) must show the note closed;
  until then the withdrawal keeps waiting. When the payment RPC served the
  receipt and an exit RPC is set, both must agree: the exit RPC must serve
  the same successful receipt, final, in the same block and with the same
  logs, and show the note closed at that block. An exit RPC that does not
  answer, is on another network, or refuses reads at a block hash (EIP-1898)
  is named in the withdrawal's status, so you can fix it or set another; the
  withdrawal keeps waiting. A sponsored (`--fees payout`) withdrawal reads
  the chain through the exit RPC alone: one that does not answer or is on
  another network stops each check with an error naming it, which the guided
  session shows as a fixed label. Without an exit RPC the payment RPC's vault
  state alone decides. A close removes no leaf from the vault's tree, so the
  indexer's tree is not consulted: a note closed before
  its activation is still inserted by its batch, and only a missed defeat's
  retirement zeroes a leaf. A finalized escape of the same reservation (same note, nullifier,
  payout and destination) is accepted as an independently relayed payout:
  after a reverted withdrawal, choose `confirm` in the `withdraw` menu action
  and enter that transaction's hash. An escape pays `B − c_final`: the
  balance less the largest of the concession at initiation and every
  `EscapeConcessionRaised` for the note before finalization. A payout is
  accepted only when it equals that amount and is at most `B − c_init`; one
  below `B − b` (more than the state's bound `b` was conceded) still closes
  the withdrawal and is reported as `concession_exceeded_bound`. An escape
  can also close the note without paying the destination: when the
  destination rejects ETH or needs more than 100,000 gas to receive it, the
  vault credits the balance to `escapePayoutCredits(destination)` and logs
  `EscapePayoutDeferred` in the same receipt. The withdrawal then completes
  as **payout credited, not delivered**: nothing has arrived yet. Once the
  destination accepts a plain ETH transfer, anyone can deliver the credit,
  also while the vault is paused, by calling `claimEscapePayout(destination)`
  (selector `0x88c10aee`) on the vault. The withdrawal status names the vault
  (`vault_address`) and the transaction data (`claim_calldata`) with
  `payout_credited: true`. The guided setup repeats this before it asks for
  a new deposit. A new deposit replaces the withdrawal record but keeps the
  credit: the funding and withdrawal statuses then list it under
  `escape_payout_credits`, one entry per destination with its
  `credited_amount` (the vault's `escapePayoutCredits(destination)` now),
  `note_ids`, `transaction_hashes`, `vault_address`, `claim_calldata` and
  `message`, and **fund**, **withdraw** and the guided withdrawal print it as
  an unclaimed escape payout. An entry disappears once the vault's credit
  for its destination reads zero.

If a deposit stays in `verification_conflict`, compare its transaction on a
block explorer, then run `zkapi-clientd config --menu` (with the same
`--config-dir`, if set) and choose **repair**. It asks for the vault note ID
that holds the deposit (leave it blank to derive it from the saved
transaction) and for a wrongly bound wallet note to replace (blank if none),
and asks for confirmation before anything changes. The repair calls the
daemon's wallet-management route `POST /admin/funding/rebind` (optional JSON
fields `note_id` and `replace_note_id`), which verifies the deposit against
finalized vault state and the indexer itself. It succeeds when the private
note is saved again (activated or still waiting for its batch).

Rebind never changes the note secret, commitment or amount; it accepts a note
only when the finalized vault state and the indexer both hold exactly this
deposit there, or, when the indexer does not and an exit RPC is set, when
the exit RPC's finalized vault state holds it as well. Left blank, the note ID comes from a saved deposit's receipt
or, failing that, from the first note the indexer's note records hold with
this deposit's commitment and amount. It refuses while a withdrawal, public return or unconfirmed
deposit transaction is saved (including an earlier deposit of the note
retired after a reported revert), or while the wallet has an unsettled
request, and it replaces an existing wallet note only when you name it and it
is an unspent genesis note of the same amount. A withdrawal reservation of
that note is released first through the companion's `POST /oa/v1/withdraw/release`,
which refuses when the withdrawal has a prepared plan, when its clearance
request carried, or may have carried, an ownership proof
(`ownership_proof_sent`, described below), or when the
protocol server knows its nullifier; any other reservation blocks the rebind. The replacement
is saved before the wallet is reset, so an interrupted rebind resumes when
**repair** is chosen again with both fields left blank.

Every withdrawal sends the protocol server an ownership proof, a kind-2
withdrawal proof that shows the server the note ID and payout before the
close is on chain (see [privacy boundaries](PRIVACY.md)). It names no
destination and the vault accepts it neither as an escape nor as a close.
The wallet
companion must report bridge version 6 with `exit_concession: 1` and the
deployment's setup ID in its `/oa/v1/status`; an older companion is refused
before any note is reserved.

Once a clearance request carrying the proof has left the companion, whatever
came back (a gateway's 429, a server error, or no answer at all), the
companion makes no chat request from that note state: the server may hold
that state's clearance. The companion records this before the request leaves
and never releases that reservation: **repair** stops, explaining that the
withdrawal sent or may have sent its ownership proof, and the management
API's error body carries `"code": "ownership_proof_sent"`. The chat API
answers 409 `exit_locked` or `ownership_proof_sent`. Choose **withdraw**
again to finish the close; the companion resends the same proof while it is
valid rather than making a new one.

### Exit decisions

A withdrawal first takes the note's exit lock (`exit_lock.json` in the
companion's state directory): from then on the companion makes no request
proof from that note state, only the withdrawal's own proofs, and the chat
API answers 409 `exit_locked`. The lock is released when the note closes,
when you cancel a withdrawal that released no escape or close proof
(`withdraw --escape --cancel`), or once every released proof is dead (its
`valid_until` plus 15 minutes is before both the finalized block and this
machine's clock, and the note is still active). A decision that releases nothing (showing the escape's terms,
waiting for a sent request to settle, or a refusal before any proof) leaves
no lock behind, so chats continue.

Every request from one note state carries the same solvency bound `b`, the
largest charge the state can be asked to pay; a request needing a larger one
is refused with `bound_fixed_at_state` until the state settles. Near the
note's expiry, new requests are refused with `note_near_expiry`, leaving time
for a settlement window and an exit.

Before it asks for a clearance, the companion recovers every chat request
sent from the current state that has not settled: it asks the server for
each one's signed response (20 seconds per call, 120 seconds in all) and
installs any that passes its checks. Then:

- **Every sent request settled** (or the server can no longer admit it):
  the mutual close proceeds, an ownership proof then a close.
- **A sent request is still unsettled:** the companion asks for no clearance.
  The withdrawal waits (409 `pending_settlement`) until the request's
  settlement deadline plus 15 minutes, at most
  `unsettled_request_escape_after_seconds` (default 12 hours) after it was
  sent, and no later than 12 hours before the note's expiry. After that it
  needs an escape conceding the state's bound `b`: an honest operator would
  have settled the request by then.
- **The server refuses the clearance or cannot be reached**, or the note is
  less than an hour from that latest start: the withdrawal needs an escape
  conceding nothing. A server that answers `nullifier_used` while no request
  of that state is on record leaves nothing to wait for: the escape concedes
  the state's bound at once (nothing, when no request was sent).

A mutual close proof is valid for 3 hours. If it is not signed or mined in
time (a fee spike, waiting for gas funds, an owner's pause), asking again
proves a fresh close from the clearance the companion kept, with no new
request to the operator; and once a close has a final revert, `withdraw
--escape` may take over the same note.

A withdrawal that needs an escape stops with `escape_required` and the
decision; continue with `withdraw --escape` (below).

A request that an earlier release discarded left no archive record, so
its state is not recognized. If an earlier release discarded a request that
the server had in fact admitted, the note is stuck at that state: the server
refuses chat requests from it as replays, and chats and **withdraw** stop with
`receipt_journal_missing` and the state's nullifier. (A dishonest server
could claim the same.) Contact the zkAPI operator before the note expires
and give them that nullifier, the note ID and the withdrawal destination,
which tells them which of their requests was yours. Once the operator has
released it, the server holds a withdrawal
clearance for that state and refuses every chat request from it, so chats
stop with `clearance_reserved_state` ("reserved for withdrawal"); choose
**withdraw**.

## Withdrawals

Choose `withdraw` in `config --menu`. A new withdrawal asks for the destination
once and shows its full private payout. The vault's own contract address is
refused as a destination, before anything is reserved: the vault cannot
receive its own payout, so every close to it would revert. If gas is insufficient, it shows the
same address/QR and live balance UI as a deposit, but requests only public ETH
for fees. The QR pays the local signing address, not the withdrawal destination.
Partial incoming payments update the remaining top-up. Normal gas fluctuations
within the displayed buffer do not repeat the QR.

When funded, Enter approves the displayed operation and maximum fee. A fresh
quote checks the same chain, deployment, address, private note, payout, nonce
and recovery binding before signing. Higher fees or a new balance shortage
require another Enter. The optional fee buffer does not block an otherwise
funded transaction.

Ctrl+C preserves saved progress. A signed pending withdrawal resumes its exact
transaction without another approval. A reverted transaction is never retried
automatically. Explicit recovery offers a reviewed retry or confirmation of a
matching payout submitted independently. The public ETH return follows private
withdrawal in the same command, with its own approval. Return quotes expire after 30 seconds;
if one expires before signing, run the same wallet menu again and review a
fresh quote. A saved signed return resumes its original transaction instead.

Returning `all` supports ordinary and payable contract/delegated accounts.
Both a probe and the exact swept value are simulated. Value-dependent gas that
exceeds the quoted allowance fails closed; select an exact amount for such a
recipient. Unused maximum fee allowance may remain public.
For a delegated or contract recipient, choose an exact ETH amount and leave
room for the displayed maximum fee. The exact-amount path still simulates the
transfer and requires destination, amount and fee approval.

### Paying the fee from the payout (gasless withdrawals)

On a deployment that publishes a gasless withdrawal paymaster (the profile's
`gasless` object: an ERC-4337 EntryPoint v0.7.0, the `ZkApiWithdrawalPaymaster`
and its account factory), the withdrawal's network fee can be paid from the
payout instead of by the local signing address, so the destination needs no
ETH and no fee QR appears:

```sh
zkapi-clientd withdraw --to 0xDESTINATION --fees payout                       # quote a sponsored close
zkapi-clientd withdraw --approve QUOTE_ID                                     # sign and send the operation
zkapi-clientd withdraw --resume                                               # follow a sent operation
zkapi-clientd withdraw --to 0xDESTINATION --fees payout --fee-cap-gwei 2000000 \
    --bundler-url https://bundler.example/rpc --allow-expensive-gas          # bounds and your own bundler
zkapi-clientd withdraw --to 0xDESTINATION --collect                           # forward a payout waiting in the transit account (sponsored)
zkapi-clientd withdraw --to 0xDESTINATION --sweep                             # ... or sweep it, paid by the local signing address
zkapi-clientd withdraw --to 0xDESTINATION --claim-credit                      # deliver a payout the paymaster credited
zkapi-clientd config --withdrawal-fees payout --bundler-url https://bundler.example/rpc   # defaults
```

The guided **withdraw** menu offers "Pay the network fee from the payout (no
ETH needed)" whenever the pre-flight says the paymaster can sponsor the exit,
before any fee QR; a saved sponsored withdrawal that stopped as
`gasless_refused` while the sponsored path is unavailable falls back to the
wallet-paid fee without asking (its quote is still reviewed). `--fees` resolves from the flag, then
`zkapi.withdrawal_fees` (`wallet` by default); `--bundler-url` from the flag,
then `zkapi.bundler_url`, then the deployment's published bundler. The bundler
URL follows the exit RPC's rules (HTTPS, or plain HTTP to this machine). It
is resolved once, when the quote is made (the quote shows it), and
`--approve` sends the operation to that bundler; an approval that would
resolve another one is refused before it is contacted. `--fees wallet` named
on the command line (or chosen in the guided menu) is sent to the daemon even
when it is the default, so it switches a saved sponsored withdrawal to the
wallet-paid path; a rerun without `--fees` keeps a saved withdrawal's mode
(the configured `zkapi.withdrawal_fees` is sent only for a new withdrawal).
`--fee-cap-gwei` bounds what the payout may lose: the sponsored fee's maximum
plus, for a destination with code, the paymaster's credit surcharge of a
failed push.

The fee quote prefers the bundler's suggested priority fee (Pimlico's
standard tier, fast if standard is absent, or Rundler's priority-fee method).
An unsupported or malformed hint falls back to validated chain fee history.
The maximum fee still uses the current chain base fee and the paymaster's
live ceilings; a later hint cannot change an approved or journaled operation's
fee bounds. This avoids pricing a cheap Sepolia bundle from unrelated
transactions' much higher tips.

How it works. Before anything is reserved, the client checks the gasless
contracts against this release's pins (the runtime code of the EntryPoint,
its SenderCreator, the paymaster, the factory and the transit accounts'
implementation, which every transit account delegatecalls, the paymaster's
vault, factory, unit and gas policy, the factory's paymaster,
implementation and creation code, and its address derivation) through
the pinned RPC and your exit RPC when one is set, asks the bundler for its
chain and EntryPoints, reads the paymaster's live policy and deposit and the
vault's pause, and checks the fee against the private balance. A mismatch or
a refusal (`gasless_unavailable`, `bundler_unavailable`, `sponsorship_paused`,
`exits_paused`, `payout_below_gas`, `gasless_uneconomic` — the fee would take
more than the deployment's uneconomic fraction, 25%, of the payout, unless
`--allow-expensive-gas` — `gas_above_paymaster_ceiling`, `paymaster_underfunded`,
`gasless_attempts_exhausted`) disables only `--fees payout`; deposits and
wallet-paid exits are unaffected. A payout address the transit account's
factory never accepts as a payee (the vault, the EntryPoint, the withdrawal
paymaster or the withdrawal account factory of the deployment) is refused with
`invalid_payee` before anything is reserved: a transit account bound to it
could never be created, so neither a sponsored operation nor `--sweep` could
deliver the payout.

A fresh owner key is generated for every withdrawal and saved, hex-encoded, in
the mode-0600 payment journal (`transit.owner_key`); the funding key never owns
a transit account. The transit account `S` is `CREATE2(factory, 0,
creationCode ‖ abi.encode(entryPoint, vault, paymaster, owner, destination))`,
cross-checked with the factory's `getAddress`; the companion prepares the
proof with `S` as its destination (`proof_destination` in the journal, while
`destination` stays the payout address), so nothing after proving can change
where the money goes. The quote shows the payout, the most the fee can take
(the operation's maximum cost at the signed limits plus the paymaster's flat
fee), what `S` still owes from an earlier sponsored escape, what the
destination receives at least, and the most the fee may take should the
operation have to be re-signed (`fee_bump_cap_wei`: your `--fee-cap-gwei`
when the quote was made with one, else that same maximum); `--approve` binds
those exact gas fields and fees and the choices the quote was made with
(the cap and `--allow-expensive-gas`). The operation's `preVerificationGas`
is the rule the browser SDK shares, `clamp(max(A, ceil(1.1 × B), C),
pvg_floor, pvg_cap)` on the operation as built: A is ERC-7562's LIM-070
minimum at its worst (the calldata cost of `handleOps` with a 65-byte
signature and both fee fields at `2^128 − 1`, plus 50,000) with a 2,000
margin, B the reference bundler's minimum (21,000 + 18,300 + 4 per word +
4 / 16 per zero / non-zero byte of the encoded operation) and C 21,000 + 16
per byte of `handleOps` calldata + 10,000; a higher `preVerificationGas` from
the bundler's `eth_estimateUserOperationGas` within the paymaster's cap is
what that bundler requires and is adopted in the quote, and so in the signed
operation. The operation (`S.withdraw(mutualClose(...))`, packed per EntryPoint
v0.7.0, hashed locally and cross-checked with `getUserOpHash`, signed EIP-191
with the owner key, dry-run through `eth_call handleOps`) is journaled before
it is sent (`user_op` with its hash, nonce, bundler and every hash of a
re-signed copy), then sent with `eth_sendUserOperation`.

Phases: `quoted` → `op_built` (journaled, being sent) → `op_submitted` (at the
bundler) → `withdrawal_pending` (the bundle transaction is known) →
`confirming` → `complete`. Recovery follows `--resume` or the same `--to`: a
crash in `op_built` re-sends the identical bytes; the bundle transaction is
found by the operation's `UserOperationEvent` in the chain's logs (the
bundler's receipt is only a hint and must carry that event), read through
your exit RPC when one is set, and needs Ethereum finality; after five
minutes without inclusion the bundler is asked again, an operation it forgot
is re-sent, one it refuses because the transit account was created meanwhile
(`AA10`) is rebuilt without `initCode`, and one it refuses as underpriced is
re-signed with both fees raised an eighth (dry-run before it is journaled), within the paymaster's ceilings and within what the
approval allows: your `--fee-cap-gwei` when the quote was made with one
(without one an approved operation is never re-signed above its approved
maximum), the payout's floor, the uneconomic fraction, and the paymaster's
policy and deposit. A raise beyond them is not signed: the record stops as
`gasless_refused` (reason `fee_bump_needs_quote`), and rerunning `--to`
quotes again at the current fees, after looking once more for an inclusion
of any journaled copy of the dropped operation, which is adopted (so does
`--fees wallet`, which then refuses the wallet quote and names the resume). The operation is abandoned
60 seconds before the proof's `valid_until` (phase `gasless_refused`, reason
`op_expired`; rerun `--to` to prove again). An operation found on chain is
never taken for a dropped one later: an escape whose sponsored initiation was
included and whose finalization is then refused stops as `gasless_refused`,
and `--fees wallet` signs the wallet-paid finalization. `op_reverted` is an operation
included but reverted (its reason is shown): rerun `--to` to prove again, or,
when another transaction closed the note first (`NoteNotActive`), the payout
sits in `S`: `--collect` adopts that close, confirms it with the companion and
forwards the balance with a sponsored FORWARD operation (phases
`forward_op_built`, `forward_op_submitted`); `--sweep` does it with a
wallet-paid `S.sweep()` (creating `S` first when it has no code).
A sponsored forward that is refused (by the bundler at sending, or when a
re-signed copy is not allowed) or reverts leaves the record `complete` with
the payout waiting in `S` and the reason shown (a plain rerun of `--to` changes
nothing); `--collect` tries again without confirming the close with the
companion a second time, after looking for an inclusion of the refused
forward, which is followed instead (the quote is then refused with the resume
command), and `--sweep` delivers it wallet-paid (`--sweep` and
`--claim-credit` need no bundler). `gasless_refused` names why the
sponsored path stopped before the note closed; rerun `--to` to try again, or
`--fees wallet`, which reuses the plan bound to `S` (the companion's
reservation pins it), pays the fee from the local signing address, and leaves
the payout in `S`, which `--sweep` delivers (wallet-paid). `--collect` (a
sponsored forward) applies only when the paymaster recorded evidence for
`S`: a sponsored close or finalization of this withdrawal that was included
and reverted, a sponsored escape another transaction finalized, or the
owner's `allowForward`; a refused operation was never included and leaves
none, so `--collect` is then refused and names `--sweep`. While that
wallet-paid close is not signed yet, `--fees payout` takes it back to the
sponsored path. A
payout the paymaster could not push to the
destination (it rejected the ETH or needed more than 100,000 gas) is credited
there; `--claim-credit` delivers it with a wallet-paid `claimCredit`. A new
deposit is refused while a payout waits in `S` or the paymaster.

`--sweep` and `--claim-credit` on a saved gasless withdrawal use the
contracts journaled with it (`S`, the factory, the paymaster, the
EntryPoint, the owner and the destination), never the release's current
profile, so they keep working after a release publishes `gasless: null`
(the paymaster's retirement) or pins another paymaster; before anything is
signed the journaled factory's `getAddress(owner, destination)` must name
the journaled `S` through the read RPC. `--escape --fees wallet` finalizes
a pending escape with a plain `finalizeEscapeWithdrawal` on the vault, which
needs no gasless contract at all (only a record stopped as
`gasless_refused` first looks for a late inclusion of its operation, through
the journaled contracts and the same `getAddress` check). A sponsored
operation for such a record (`--collect`, a sponsored finalization, or
`--fees payout` on it) needs the current pins to name the record's paymaster
and factory, and is refused otherwise with `gasless_record_not_pinned`,
which names those wallet-paid alternatives, led by the wallet-paid close or
escape initiation (`withdraw --to Y --fees wallet`, `withdraw --escape --to
Y --fees wallet`) while the record's exit is not on chain yet. A new
sponsored withdrawal under a profile with `gasless: null` is refused with
`gasless_unavailable` instead. An operation already sent when
the pins went away is still followed by the resume (`withdraw --to`, or
`withdraw --escape --to`, without `--fees`), through the journaled
contracts and without re-sending it: included, the record settles from its
inclusion; not included five minutes after it was sent, it is released
(`gasless_refused`, or a complete record with the payout waiting in `S` for
a forward) with `gasless_record_not_pinned` and the wallet-paid step to
take next. The wallet-paid path waits until then (`a sponsored operation is
in flight`).

Amounts: before signing only "the destination receives at least" is promised.
The quote's expected charge is an estimate (the paymaster's charge formula at
the gas an operation of this shape uses and today's base fee plus tip), shown
beside the signed maximum. When the destination has code the push may fail
and the paymaster then credits the payout less a surcharge of up to
`credit_gas` × max fee per gas taken beyond the maximum: the quote says so
(`payee_has_code`, `credit_surcharge_wei`), its floor already deducts it, and
the status shows the advisory from the reservation on;
after settlement the status shows the paymaster's `Settled` figures
(`charged_wei`, `owed_paid_wei`, `received_wei`), or `received_wei` 0 with
`paymaster_credited`. The operation is sent to the bundler, which learns it and
your client IP before inclusion (the operator's bundler, unless you set your
own); the chain shows the bundler's transaction, the transit account and the
destination, never the funding address.

### Escape withdrawals

An escape exits without the operator: the vault pays after its challenge
period, during which the operator can raise the concession up to the state's
bound with the signed charge of a request you sent, or defeat an escape made
from a state that was already spent (a stale device or backup).

```sh
zkapi-clientd withdraw --escape --to 0xDESTINATION                    # show the decision
zkapi-clientd withdraw --escape --to 0xDESTINATION --conceded 1500    # quote it
zkapi-clientd withdraw --approve QUOTE_ID                             # sign and send
zkapi-clientd withdraw --escape --to 0xDESTINATION                    # later: quote finalization
zkapi-clientd withdraw --claim --to 0xDESTINATION                     # deliver a credited payout
zkapi-clientd withdraw --escape --cancel                              # drop an unsigned escape
```

With `--fees payout` the escape is gasless too: the decision reserves the
exit for the transit account, the initiation quote includes the
finalization reserve (the escape must leave enough for a sponsored
finalization at the same fee, the paymaster's minimum net and both flat
fees; the paymaster must have escapes enabled), nothing is paid at
initiation and the initiation's charge becomes the transit account's debt
(`initiation_debt_wei`, `EscapeInitiationOwed`), the finalization is quoted
after the challenge deadline with that debt deducted (`owed_wei`), and a
sponsored finalization settles it. The initiation quote promises no floor
for the payout: it shows the initiation's maximum charge and expected charge,
the paymaster's reserve, the finalization's expected charge at today's fee
(`finalize_estimate_wei`) and what the destination would receive after both
expected charges and the debt (`estimated_received_wei`), as estimates, since the
finalization is quoted at its own fees after the challenge period (what the
destination receives at least is stated by that quote). When the paymaster
has escapes disabled (`escapes_disabled`, the default of a deployment), the
refused `--fees payout` run still reserves the escape for the transit account
when a sponsored finalization passes its pre-flight: initiate with `--fees
wallet` (bound to the transit account); once the escape is on chain,
`withdraw --escape --to --fees payout` takes the sponsored path back for its
finalization from the transit account (the sponsored path takes over a
wallet-paid escape bound to the transit account whenever none of its
transactions is pending). When a sponsored finalization would be refused too,
nothing is reserved and the refusal names only `--fees wallet`: that escape
is bound to the payout address and its finalization is wallet-paid as well. Phases: `op_built`/`op_submitted` →
`escape_pending` → `escape_initiated` → `finalize_op_built` /
`finalize_op_submitted` → `finalize_pending` → `complete`. When someone else
finalized the escape (the vault paid the transit account), the same
`withdraw --escape --to` completes the record from that finalization and
quotes the sponsored forward right away (`withdraw --approve` sends it; the
debt is deducted from the forward); like every sponsored operation it is
refused as `gasless_uneconomic` when its fee may exceed the uneconomic
fraction of the balance in `S`, unless the command passes
`--allow-expensive-gas`; `--sweep` is the wallet-paid alternative.

`--escape --cancel` drops an escape whose proof was never released (only its
decision was shown, or it waits for a request to settle); chats resume. Once
the escape proof was released it cannot be cancelled: the exit lock stays
until the proof is dead or the note closes.

An escape defeated on chain (`device_not_newest`: another device or backup
spent the escaped state) shows phase `defeated`. A defeat counts only from
the vault's `EscapeWithdrawalChallenged` log in a finalized block, and it is
never final on one reading: every `withdraw --escape --to` reads the chain
again (through your exit RPC once one is set), follows the escape if it shows
pending after all, and decides again if your exit RPC shows the escape never
landed (a reading whose logs fail to load decides nothing). Exit from the
newest state instead (restore the newest backup, or
`zkapi-walletd exit-kit escape` with the newest kit). `--escape --cancel`
clears a defeated escape once the chain shows it neither pending nor closed
and its exit lock was released (its proof is dead).

The first run shows what the escape concedes (in gwei), why, and what it
pays; nothing is signed. `--conceded` repeats the concession you reviewed
and quotes `initiateEscapeWithdrawal`; a different amount than the exit
rules allow now is refused with `conceded_mismatch`. While a sent request
can still settle, the decision is to wait; `--early-exit nothing` escapes
now conceding nothing (the operator can raise it to the request's actual
charge), and `--early-exit bound` concedes the state's bound so the request
never appears on chain. The guided **withdraw** menu shows the same
decision and command when a mutual close needs an escape.

An exit proof binds the note itself, not a tree root: its registration
commitment and its deposit amount and expiry, which the vault checks against
`notes(noteId)` (`NoteBindingMismatch`). So an exit needs no Merkle path, no
indexer and no activation. Before the companion proves, the client reads that
record from the vault (through your exit RPC for an escape) and requires it
to be this wallet's deposit; the statement must bind exactly it. The
companion asks the server whether another device already spent the
note's state, and refuses with `device_not_newest` when the server shows a
valid request proof of the next state. The escape proof is valid for 3 hours;
the transaction is checked word by word against the decision you confirmed
(kind 0, destination, concession, `B − c`, `valid_until` and the note's
commitment and metadata) before it is
signed, and is sent through your exit RPC when one is configured. Its
simulation is advisory: when the RPC refuses to simulate or estimate it, the
quote carries a warning and a fixed gas limit, and you may still approve it
(an escape that would fail reverts cheaply). An escape transaction is never
signed below its entry point's measured cost, whatever the estimate: 900,000
gas for the initiation, 350,000 for the finalization and 150,000 for a
claim.

A signed escape transaction that can no longer be included is retired
unmined (phase `escape_expired`; a finalization or a claim is quoted again)
instead of being followed forever: its proof expired before inclusion,
another transaction took its nonce in a finalized block, or its nonce stayed
beyond the account's pending nonce for 15 minutes (it was signed at a nonce
an RPC answered wrongly). The receipt is read again before it is retired, so
one mined meanwhile is followed. Rerun `withdraw --escape --to` to review the
escape: it is proved again when its proof expired, and signed at the
account's nonce, replacing a transaction still waiting in a mempool with a
fee cap and tip raised by more than an eighth. After the
challenge period the same `withdraw --escape --to` quotes
`finalizeEscapeWithdrawal`. The payout is matched as described under
**Withdrawals** above; a credited payout is delivered with `--claim`.

The management API serves the same steps: `GET`/`POST /admin/escape`,
`POST /admin/escape/quote`, `POST /admin/escape/claim/quote`,
`POST /admin/escape/approve` and `POST /admin/escape/cancel`. The companion's
routes are `POST /oa/v1/withdraw/escape/prepare`,
`POST /oa/v1/withdraw/escape/submit`, `GET /oa/v1/withdraw/escape/status`,
`POST /oa/v1/withdraw/escape/finalize` and `POST /oa/v1/withdraw/escape/cancel`
(`escape_routes_version` 2).

### Exit kit

`zkapi-walletd exit-kit export --state-dir DIR --deployment MANIFEST --out
FILE` writes an encrypted copy of the note (format `zkapi-exit-kit-v1`, the
browser SDK's: PBKDF2 with SHA-256 and 600,000 iterations, then
AES-256-GCM) with the deployment profile, the note's secret and current
state and the state's bound; an escape needs no Merkle path, and one an older
kit carries is ignored. `exit-kit escape`
reads kits the browser SDK exported as well as this tool's. Export it again after each chat request: an
older kit escapes from a state that was already spent, and that escape is
defeated. `zkapi-walletd exit-kit escape --kit FILE --destination ADDRESS
[--rpc URL] [--conceded UNITS]` checks the deployment's code hashes through
`--rpc`, builds the escape with the companion's bundled keys, and prints the
vault, the calldata and the payout, or signs and sends it with a key you
supply (`--private-key-file`, with `--rpc`). `--offline` skips the
stale-device question to the server; `--work-dir` keeps the kit's exit lock
and released proofs between runs. The passphrase comes from
`ZKAPI_EXIT_KIT_PASSPHRASE`, `--passphrase-file` or standard input.

## Inference and activity

Use base URL `http://127.0.0.1:8787/v1`. No inference API key is required by
default; a placeholder is accepted if a client UI insists on a value. Admin
and wallet routes remain authenticated with separate local credentials.
Browser Origins are rejected. The listener must be loopback.

Open WebUI running directly on the same machine can use that URL. A Docker
container has its own loopback: use host networking where supported and enabled,
or run the client in the same network namespace. `host.docker.internal` alone
does not make a loopback-only listener reachable. Remote/container access is not
a reason to expose an unauthenticated listener on all interfaces.

Requests are serialized, including concurrent chat/title requests. By default,
compatible requests reuse an OpenRouter key for a fixed window of up to 60
seconds from acquisition, capped by the provider's expiry. Reuse does not extend
the window. Requests from **different chats and local clients**, including Open
WebUI's automatic title and follow-up requests, can share a key and its aggregate
spending cap; the provider can link all those requests. Each request checks
current model policy.
The daemon starts settlement automatically when the window ends, even if no
further request arrives. If a provider response is still active, it finishes
before settlement starts. A required spending-cap change can also retire the
previous key before its window ends. When an earlier lease blocks a fresh key,
the daemon requests settlement instead of waiting for the key's full expiry.
The helper recovers pending or ambiguous settlement outcomes without repeated
retirement requests. Signed settlement can still take several minutes.
Inference is never retried automatically after a provider/transport error.

The allowance follows the OA web client's public model-tier policy: $1, $2,
$3, $4.50 or $6 depending on the model. This is an aggregate spending ceiling,
not a fixed charge. Both clients strip only `:online` for tier lookup, keep
other variants distinct, and reject an explicit tier without a reviewed budget.
The production org's $20 per-key ceiling does not raise these client allowances.

If issuance was interrupted before a key reached the client, settlement first
asks the server to reconcile the saved authorization. For an older pending
server, it replays that exact request, verifies any returned key and retires it
without using it for inference. A finalized cancellation needs no key: the
helper verifies and installs the signed wallet response. Unknown outcomes stay
pending with the original recovery journal intact. Retrying uses the existing
wallet; deleting or resetting its files cannot safely release a server reservation.

The default `key_reuse_window_seconds` is 60 seconds. An explicitly saved
window is preserved across updates. Stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve` to
require a fresh key per inference request. Use the same `--config-dir` if set.
A value from 1 to 300 sets the fixed reuse window in seconds. Use 60 to restore
the default. Setting 0 gives every inference request a fresh key without
depending on a chat ID supplied by the UI, and starts settlement after the
response ends.

Normal output assigns each HTTP request a local sequential `request=` number.
Key selection includes `key_ref=`, a local key serial, and `source=fresh` or
`source=reused`. Different `key_ref` values show that requests used different
OpenRouter keys; no key material is printed. The release line reports
`response_complete=true` or `false` and whether the key is retired locally or
available for reuse within the configured window. Local retirement means the
daemon will not reuse the key; it is not proof of provider revocation or signed
wallet settlement. Background settlement logs identify the local `key_ref`
and report its start and result; the duration excludes queueing, key issuance
and inference. A waiting line identifies earlier-key settlement as the reason
an inference request is waiting.

Wallet key-session starts and ends use independent session numbers. These are
not the `key_ref` numbers, especially after a daemon restart. Session ends,
actual cost and remaining private balance in ETH appear only after signed
settlement, which can arrive after the response ends. Routine helper
readiness/retry messages are hidden. The foreground daemon stops if its helper
exits; only an external service manager can restart it.

### Mainnet production issuer and verifier

Version `0.1.4` switches Mainnet to issuer
`https://org-live.openanonymity.ai` and verifier
`https://verifier-production-20260917.openanonymity.ai`. Sepolia continues using
the staging org and `verifier2`. The Mainnet vault, signing keys, proof hashes,
protocol endpoints and wallet directory are unchanged.

Stop the running daemon, install the update and restart with the same profile.
Existing Mainnet profiles using the historical default `verifier2` origin use
the production verifier when loaded; custom verifier origins are preserved.
Loading alone does not rewrite the configuration file. New profiles and network
selection use the matching network default. The saved Mainnet manifest migrates
only when both complete old and new manifests match their reviewed SHA-256 pins;
any other manifest change is rejected. Wallet notes and recovery journals are
preserved, and Sepolia's existing migration behavior is unchanged.

This update does not add station trust exceptions, fund a wallet or clear an
unfinished lease. Existing lease recovery still uses the saved request and
server-signed settlement response.

### Trusted-station verification fallback

Version `0.1.3` adds the same pinned-station exception as the web app.
A new provider key normally needs matching OA verifier approval. If verification
is unavailable or refused, the client can continue only for the compiled
`oa-station` signing-key pin, after checking the station signature locally.
This permits a valid trusted-station key when the verifier reports
`Invalid org signature`; unknown stations cannot use the exception. Bans,
expired keys, invalid station signatures and mismatched approvals still block.

Fallback responses include `X-OA-Verification-Status: verifier-unavailable` and
`X-OA-Verification-Detail: trusted_station_fallback`. The terminal warns that
provider ownership and privacy settings were not confirmed. The key is never
reported as verified. See [privacy boundaries](PRIVACY.md) for the trust pin's
provenance and limits. Install the matching client/helper bundle together. The
gateway accepts fallback only with the `trusted_station_fallback` detail.

## Private files and recovery

The default private configuration directory is
`~/.config/zkapi-clientd` on Linux or
`~/Library/Application Support/zkapi-clientd` on macOS.
`ZKAPI_CLIENTD_CONFIG_DIR` or global `--config-dir` selects another directory.
Keep the same directory when updating or resuming the wallet; it contains the
signing keys and recovery journals. See [wallet storage and updates](CLI_PACKAGING.md#wallet-storage-and-updates).
Never initialize a new profile over orphaned recovery state or delete saved
transactions to bypass a recovery error.
