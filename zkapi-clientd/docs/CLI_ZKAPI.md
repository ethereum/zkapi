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
signing, deposits and activates the private balance once its successful mined
receipt is validated against the canonical block and saved deposit, and the
vault state and the zkAPI indexer confirm the same note (see
[chain verification](#chain-verification-and-recovery)). There is
no additional 15-minute finality gate for successful native ETH deposits, matching
the web wallet. No model is selected or priced during funding.

If the last fee or balance check leaves the deposit unsigned, configuration
refreshes the same fixed deposit and continues watching instead of exiting.
Interrupted approval responses are checked against saved progress before any
retry. Higher fees do not require another Enter while the deposit remains
funded, even if the recommended buffer is no longer fully covered. A renewed
funding shortage requires Enter again once funded. The recommended fee buffer
remains optional; the signer caps fees to the fresh quote and available balance.

After signing, progress distinguishes waiting to be mined, waiting for network
fees to fall below the signed cap, and private balance activation. In an
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
zkapi-clientd config --web-search=false  # disable automatic web search (default: on)
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
`max(3 × model per-query spending cap in ETH, 10 × estimated deposit gas in ETH,
the vault's minimum deposit)`.
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

## Web search

Web search defaults to on for new profiles and older profiles without a
`web_search` setting. Each chat completion includes OpenRouter's
[`web` plugin](https://openrouter.ai/blog/announcements/introducing-web-search-via-the-api/),
which supplies web results across models. The selected model ID, tools, and
generation options are preserved. Both ordinary JSON responses and streamed
responses retain the provider's citations and annotations.

Stop `serve` before changing the setting, then restart it:

```sh
zkapi-clientd config --web-search=false  # turn the default off
zkapi-clientd config --web-search=true   # turn it back on
```

You can also choose on or off in `config --edit`. The preference is saved as
`"web_search": true` or `false` in `config.json`, shown by `config --status`,
and preserved across updates. Use the same `--config-dir` if set.

Search applies to every completion, including background title and follow-up
requests. OpenRouter's search charges count toward the key's existing spending
cap. OpenRouter or its search provider processes the search query; see
[privacy boundaries](PRIVACY.md). Turning the default off stops automatic plugin
injection; an explicitly selected `:online` model still requests search.
Caller-supplied `plugins` remain filtered by the local API.

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

This release serves only the leaf-bound concession-exit vault (circuit
`zkapi-v2-concession-v2`, vault revision 4); it refuses a revision-3 profile
(circuit `zkapi-v2-concession-v1`) and a revision-4 profile without leaf-bound
exits. Its embedded profiles are:

| Network | Deployment | Shown as | Vault | Protocol server |
| --- | --- | --- | --- | --- |
| Sepolia | `zkapi-native-eth-sepolia-leaf-v4-20261020` | zkAPI v0.2 | `0x67eb750d9c0d63a99684ac3f3e65f0c610276993` | `https://zkapi-sepolia.openanonymity.ai/v0.4` |
| Mainnet | `zkapi-native-eth-mainnet-concession-v1` | (placeholder) | none | none |

"zkAPI v0.2" is the build's display name for the Sepolia deployment (vault
revision 4 in the deployment registry, leaf-bound exits, development proving
setup `protocol/setup/v2-concession-dev`); it is not
derived from the server path (`/v0.2` was the revision-3 server's path). The
configuration summary, the wallet menu, guided setup and `serve` show it with
the deployment ID and vault. Mainnet's profile ships as a placeholder
(`"deployment_status": "not_deployed"`, no contract, adapter, endpoints or
signing keys) and the client refuses to fund, use or withdraw a note there
with `deployment_not_deployed`. A release that pins the deployed vault
replaces the placeholder.

A wallet saves its deployment manifest's exact bytes
(`zkapi/<network>/<deployment_id>/deployment-manifest.json`) and refuses to
start with any other, so an embedded deployed manifest is never edited in
place: a test pins the SHA-256 of the Sepolia manifest, and existing leaf-v4
wallets keep loading. Another vault gets another deployment ID and so its
own directories.

The embedded profiles pin the deployment IDs, contracts, the proof adapter
and Poseidon library, their runtime-code hashes, signing keys, oracle,
challenge period, note term, maximum pause, the settlement window `W`, the
vault's minimum deposit (`min_deposit_units`, 1,000,000 gwei in both packaged
profiles), the network's fresh-slot gas (`fresh_slot_gas`: 22,100 under
mainnet rules, 110,000 on Sepolia under EIP-8037), the deploy block and the
proof setup (circuit, setup ID and key hashes). Wallet
funding and recovery records are bound to the configured network and
deployment. Unknown origins or unapproved manifest differences fail closed.
Do not delete recovery data to bypass a configuration mismatch.

All wallet state is kept per deployment under the configuration directory:

- `zkapi/<network>/<deployment_id>/`: the companion's wallet
  (`note_state.json`, `pending_journal.json`, `prepared_withdrawal.json`,
  `oa-withdrawal.json`, `exit_lock.json`, `escape_withdrawal.json`) and the
  saved manifest;
- `funding/<network>/<deployment_id>/`: the payment state (the local signing
  address and its key in `address-funding.json`, a pending deposit and its
  recovery record in `pending-deposit.json`).

A build opens only its own deployment's directories. It never migrates,
reads or changes another deployment's: an already funded note and a saved
in-flight withdrawal of an earlier deployment stay exactly where that build
left them. When an earlier deployment's recovery files exist in the profile,
`serve` (managed or external companion), `config --setup`, `config --menu`,
`withdraw` and guided funding (before it shows a new funding address) print a
warning naming the deployment, its directories and its way out. The warning
never asks a question or stops the command, and only checks which files
exist (it never reads them). Earlier deployments:

| Network | Deployment | Recovery |
| --- | --- | --- |
| Sepolia | `zkapi-native-eth-sepolia-concession-v2-r4-20261017` (vault `0x7ff4ba06…`, `/v0.3`, revision 4 without leaf-bound exits) | the local CLI bundle built from git branch `origin/v0.2`, with the same `--config-dir` (its default concession stack) |
| Sepolia | `zkapi-native-eth-sepolia-concession-v1-r3` (vault `0x1670d773…`, `/v0.2`, revision 3) | the same `origin/v0.2` bundle and `--config-dir`, with `--vault-protocol concession-v1` |
| Sepolia, Mainnet | `zkapi-native-eth-<network>-note-bound-v1-fresh-20260930`, `…-20260928` | the legacy dispatcher (`--vault-protocol legacy` with the original profile) or zkapi-clientd 0.1.7 from the earlier release line (`release/v2-note-bound`), which closes deposits on that vault and keeps its mutual close and an escape (`withdraw --escape`, runbook in that release's `docs/LEGACY_ESCAPE.md`) |

**Compatibility exception:** this build cannot load the exact manifests of
the two earlier Sepolia concession deployments (revision 3 proves circuit
`zkapi-v2-concession-v1`; `concession-v2-r4-20261017` has no leaf-bound exits
and other verifying keys). Their files are preserved and warned about, and
their notes and saved withdrawals are recovered with the `origin/v0.2`
bundle. A profile whose saved vault protocol is `concession-v1` (saved by
that bundle) is refused with that guidance, and the `vault-protocol` file is
left unchanged; so is `--vault-protocol concession-v1` or
`ZKAPI_VAULT_PROTOCOL=concession-v1`.

The earlier note-bound release kept its payment files in `funding/<network>/`
itself; this release neither reads nor changes them, and the same warning
names them while they exist. Keep them for that release until its note is
withdrawn and its signing address emptied.

A running daemon reports the deployment its build serves. A command from a
build pinning another deployment refuses to attach to it ("restart the daemon
with this build; your other wallet is untouched"); a daemon from a build that
predates this report gets a one-line warning and is used as before.

### Deployment checks and the exit RPC

At startup and before every deposit, the client checks through the pinned
RPC, and through your exit RPC when one is configured, that the deployment it
trusts is the one on chain: the runtime code of the vault, its proof adapter
and the Poseidon library hash to the pins, the vault's `proofAdapter()` is
the pinned adapter, and the vault's and adapter's getters
(`stateSigningKeyX/Y`, `clearanceSigningKeyX/Y`, `challengePeriod`,
`noteTtl`, `maxPauseDuration`, `CONCESSION_ESCAPE_VERSION` and
`LEAF_BOUND_EXIT_VERSION`, both 1, `minDeposit`, `CIRCUIT_ID_HASH`,
`REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH`) and `eth_chainId` return the pinned
values. A vault of revision 3 has no `LEAF_BOUND_EXIT_VERSION()`: the call
reverts and the check fails. A mismatch refuses deposits with
`deployment_mismatch`; exits stay available.

`config --exit-rpc-url URL` saves your own Ethereum RPC (HTTPS, or plain HTTP
to a node on this machine; no credentials, query or fragment). Deployment
checks use it as well. An escape then reads the chain and sends its
transactions only through it (a gasless escape's operations excepted, see
below): the balance, nonce, fee and simulation reads,
the receipts, the raise and finalization logs, and the wallet companion's
exit state (the note's status and stored leaf). The pinned
RPC, which the operator may run, is never asked in its place: a call your
exit RPC does not answer (a timeout, a 429 rate limit, a 5xx) is retried
twice, then the escape stops with an error naming the exit RPC, and you
retry later or configure another one. So a pinned RPC that is down or
answers falsely can neither block an escape nor end one, nor choose the
nonce or gas limit an escape is signed with. `config
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

- **Deposit activation.** After a successful receipt, the vault's
  `noteRecord(noteId)` is read at the receipt's own block hash (EIP-1898,
  canonical only). A vault of revision 4 stores only each note's leaf and
  status; the client recomputes this deposit's leaf with zkAPI Poseidon from
  the commitment, the receipt's note ID, the amount and the receipt's expiry,
  and the note must be Active with exactly that leaf. When the indexer's
  whole-tree snapshot (the same response for every client, so it does not
  reveal which note is yours) has applied that block, it must hold the same
  leaf there. The RPC served both the receipt and that read, so it never
  activates a note alone: when the indexer has no view of the receipt block
  (behind, unavailable, forked, malformed, or an older version without
  snapshot block metadata), your exit RPC (`--exit-rpc-url`), if one is set,
  must serve the receipt's block hash as canonical and the same Active leaf
  at it; without one the deposit waits for the indexer. The note secret is
  handed to the wallet only after this. While the vault, the indexer or the
  exit RPC does not show the note yet, or cannot be read, the deposit stays
  in phase `confirming` with stage `verifying` and polling continues. Disagreement sets phase
  `verification_conflict`. The conflict is not final: running
  `zkapi-clientd config` again checks the saved transaction against the vault,
  the indexer and the exit RPC once more, and activates the deposit if they
  now agree.
  Otherwise it stops and points to the repair below.
- **Deposit gas limit and minimum.** A deposit's gas grows with the number of
  trailing ones `t` of the note ID it lands at (about 16,100 gas per level,
  plus a fresh storage slot the first time a level is written, at note ID
  `2^t − 1`), and another deposit landing first can move it to a costlier ID.
  So the client never signs a bare estimate: with `m` the vault's
  `nextNoteId()` and `E` the estimate, both at the latest block, `t_now` the
  trailing ones of `m` and `t_max` the most over `[m, m + 64)`, it adds
  `16,500 · (t_max − t_now)`, plus 7,500 when `t_now` is 0 and `t_max` is not,
  plus `fresh_slot_gas − 5,000` when some `2^j − 1` (`j ≥ 1`) lies in
  `(m, m + 64)`, and signs with the larger of its usual padded estimate and
  `min(⌈1.2 · (E + extra)⌉, 1,500,000)`. Unused gas is refunded; the larger
  limit only raises the fee reserve. When `nextNoteId()` cannot be read,
  nothing is signed. A deposit below the vault's `minDeposit()`
  (`min_deposit_units`, which the deployment checks pin) is refused before
  the wallet companion prepares it (`deposit_too_small`). A third party
  depositing without this policy should send at least 650,000 gas under
  mainnet pricing, or 850,000 where a fresh slot costs about 110,000.
- **Reverted deposits.** Before a finalized failed deposit is retired or
  requoted, the indexer must show that this note did not land at the empty
  slot the signed transaction was built for. The slot is checked against the
  indexer's tree and saved with the note just before signing, together with
  the run of empty slots right below it in that tree. A reported revert can
  also be a deposit the RPC withheld and relays later, so the slot of every
  deposit signed for the note is kept. Another deposit of the same note is
  signed only when a search of the indexer tree it is built from, starting
  at each of those slots, does not find the note. An earlier deposit missing
  from that tree cannot land beside the new one. Quotes run the same search
  to refuse early. While the indexer is unavailable, a quote is still given,
  but approval signs nothing. A saved `verification_conflict` without a
  pending transaction is the exception: there the quote's search decides
  whether the conflict clears, so it must complete, and while the indexer is
  unavailable the quote is refused and the conflict stays. The search is
  bounded: it compares the first 64 occupied slots from each kept slot on,
  and the first 64 in the empty run below it, for expiry days back to about
  63 days before the search. A deposit lands after its slot only when every
  slot in between is empty, and before it only inside that run, when the
  indexer's view it was built from was a short fork that was then orphaned.
  The expiry days come from chain time, not from this device's clock. The
  vault derives a deposit's expiry from its block's time, so the search runs
  from the block time of the indexer view each slot was built from to the
  block time of the view it searches, with one day of tolerance on each side.
  Each of those times comes from the payment RPC's header for the indexer
  view's block, and is accepted only when that header hashes to the block
  hash the indexer names. While the RPC does not serve that header
  (`eth_getBlockByHash`), or serves one this release cannot hash (a header
  format introduced by a later network upgrade), nothing is signed and a
  reported revert waits. A slot saved before this release, or rewritten by
  one, has only the device clock's preparation time, and its search starts
  7 days before it. Nothing is signed, and no reported revert is retired,
  while this device's clock is more than a day from that chain time: correct
  the system clock and retry.
  So a landed deposit is missed only in two cases. It landed behind 64 or
  more occupied slots after the slot it was built for (or the start of the
  run), which needs 64 other deposits to land first. Or it landed about 63 or
  more days earlier, past its note's 30-day term on the packaged deployments unless
  vault pauses extended it by more than 33 days. (A slot saved by a
  pre-release build of this version records no run and is never searched
  below, so a deposit signed for such a slot from a view that was then
  orphaned is also missed when it landed below the slot. A slot saved by an
  earlier release on a device clock more than 6 days fast is also missed
  when its deposit landed within that much of its preparation.) If the note is
  found, the deposit is reported as a `verification_conflict` and no
  replacement is signed. Running
  `zkapi-clientd config` again checks once more; **repair** (below) binds
  the note that landed. Deposits that reuse your public commitment with a
  different amount are ignored, so they cannot block a genuine retry. A
  deposit signed by 0.1.6 or earlier, or whose `pending-deposit.json` such
  a release rewrote (dropping `slot`, `signed_slots` and each slot's
  `empty_before`), has no recorded slot: its reported revert is retired, and
  a retry signed, without this search.
- **Withdrawals.** Before the wallet companion deletes its note state, the
  vault (`noteRecord` at the payout receipt's block) must show the note
  Closed, through the pinned RPC and, when you configured one, your exit RPC
  as well; until then the withdrawal keeps waiting. A close leaves the
  note's leaf in the tree (only `retireClosedLeaf` zeroes it), so the indexer
  is not asked. Without an exit RPC the pinned RPC that served the receipt
  also serves this read: set one so that a single RPC never decides the
  close. A finalized escape of the same reservation (same note, nullifier,
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
finalized vault state itself (and the indexer, when it answers). It succeeds
when the private balance is active again.

Rebind never changes the note secret, commitment or amount; it accepts a note
only when the finalized vault state holds exactly this deposit there: an
Active note whose stored leaf is this deposit's for one expiry. A vault of
revision 4 does not store the expiry, so rebind takes it from a saved
receipt's `NoteDeposited` that names the note, or else tries every day bucket
`⌈(t + noteTtl) / 1 day⌉ · 1 day` for a deposit mined at `t` from one day
before this note's earliest prepared deposit (the last 64 days without one)
to the finalized block's time, normally one or two days, and accepts the one
whose leaf the vault stores. No match means another deposit holds that note,
and nothing changes. When the indexer's snapshot covers the finalized block
it must show the same leaf; an unavailable indexer is skipped. Left blank,
the note ID comes from a saved deposit's receipt or, failing that, from this
deposit's leaf among the vault's own leaves (`noteLeaves`, read at the
finalized block), searched with the bound above from every slot any of its
deposits was signed for, earliest first. It refuses while a withdrawal, public return or unconfirmed
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
companion must report bridge version 5 with `exit_concession: 1` and the
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
once and shows its full private payout. On a deployment that publishes a
gasless withdrawal paymaster the fee is paid from the payout (next section)
and nothing below about fee QRs applies; the wallet-paid flow described here
serves deployments without one and withdrawals saved wallet-paid before
sponsorship. The vault's own contract address is
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
and its account factory), a new withdrawal pays its network fee from the
payout: sending to an address this way is the only new withdrawal offered,
as in the web app, the local signing address needs no ETH and no fee QR
appears. A wallet-paid fee is neither offered nor taken as a fallback
(`--fees wallet` on a new withdrawal is refused with `wallet_fees_unavailable`
before anything is reserved), also when the bundler or paymaster is
unavailable: the withdrawal waits and is retried.

```sh
zkapi-clientd withdraw --to 0xDESTINATION                                     # quote: estimate, maximum, floor
zkapi-clientd withdraw --approve QUOTE_ID                                     # approve once; signed and sent within the maximum
zkapi-clientd withdraw --resume                                               # follow it, or retry it within the approval
zkapi-clientd withdraw --to 0xDESTINATION --fee-cap-gwei 2000000 \
    --bundler-url https://bundler.example/rpc --allow-expensive-gas          # a tighter maximum and your own bundler
zkapi-clientd withdraw --to 0xDESTINATION --collect                           # forward a payout waiting in the transit account (sponsored)
zkapi-clientd withdraw --to 0xDESTINATION --sweep                             # recovery: sweep it, paid by the local signing address
zkapi-clientd withdraw --to 0xDESTINATION --claim-credit                      # recovery: deliver a payout the paymaster credited
zkapi-clientd config --bundler-url https://bundler.example/rpc                # your own bundler by default
```

**Approve once.** The quote shows the estimated fee, says plainly that the
actual fee may change, and shows the most the fee may take from the payout
(`max_total_fee_wei`) and the least the destination receives
(`min_net_payout_wei` = payout − maximum − debt). The maximum is the
deployment's normal limit, as the web app uses it: the uneconomic fraction
(25%) of the payout, at most what the paymaster's policy lets one operation
cost plus its flat fee (and, for a destination with code, the credit
surcharge of a failed push); `--fee-cap-gwei` tightens it, nothing widens it,
and `--allow-expensive-gas` lifts the fraction. One approval (the guided
Enter, `--approve`, or `POST /admin/withdrawal/approve`) covers this
destination, note, transit account and bundler: it is journaled before
anything is signed, and the operation is built at the fees of the moment it
is signed. Fees that fell or rose since the quote, a bundler that drops or
refuses a copy for its price, a proof that expired, a lost answer or a
restart are all handled within the maximum without asking again: the copy
is rebuilt, re-signed with higher fees, or proved again from the kept
clearance, always at the nonce of the first copy signed under the approval,
so at most one copy is ever included and charged. When the fee needed now
exceeds the maximum (or the bundler or paymaster is unavailable) nothing is
signed and the status is `gasless_refused` with `gasless_retryable` true:
the running `withdraw` command, `--resume`, the guided flow or a restarted
daemon retries it later, at most eight rebuilds per approval. A new
destination or note, a higher maximum, a raised flat fee or debt, a reverted
operation (it used one of the key's attempts) or a nonce that moved need a
new quote and approval. The guided flow asks for Enter once; an approval
whose quote expired (quotes are approvable for 30 minutes) is re-quoted and
approved without asking only if the identity is unchanged, the maximum is not
higher and the floor not lower. A quote publishes nothing executable: no
valid owner signature and no exit proof reach the RPC or the bundler before
the approval (the gas estimate and the EntryPoint hash check use a copy whose
proof no verifier accepts, and nothing is simulated); the signed dry run runs
after the approval, once the copy is journaled.

A CLI from this build attached to a daemon an older build started (it reports
no `new_withdrawal_fees`) quotes and approves nothing through it, and names
the restart; a withdrawal that daemon already signed is still followed.

`--bundler-url` resolves from the flag, then `zkapi.bundler_url`, then the
deployment's published bundler; `zkapi.withdrawal_fees` applies only to
deployments without sponsorship. The bundler
URL follows the exit RPC's rules (HTTPS, or plain HTTP to this machine). It
is resolved once, when the quote is made (the quote shows it), and
`--approve` sends the operation to that bundler; an approval that would
resolve another one is refused before it is contacted.

**Compatibility exceptions** (recovery, not a normal option): a withdrawal
saved wallet-paid before sponsorship (no transit account) finishes
wallet-paid with its fee QR; a saved sponsored withdrawal whose sponsored path
stopped for good (refused with no retry, an operation that reverted, its
attempts used up, or a record the profile no longer pins) may be closed
wallet-paid with an explicit `--to ADDRESS --fees wallet` on the command line,
never from the guided flow and never automatically; `--sweep` and
`--claim-credit` deliver a payout waiting in the transit account or the
paymaster, paid by the local signing address; an escape keeps its own fee
choice (`--escape --fees wallet` is the operator-independent exit);
`withdraw --public` returns public ETH; deployments without a `gasless`
object, and the legacy protocol, stay wallet-paid.

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
what that bundler requires and is adopted when the approved operation is
built. The operation (`S.withdraw(mutualClose(...))`, packed per EntryPoint
v0.7.0, hashed locally and cross-checked with `getUserOpHash`, signed EIP-191
with the owner key after the approval, journaled, then dry-run through
`eth_call handleOps`) is journaled before any RPC or bundler sees it (`user_op` with its hash, nonce, bundler and every hash of a
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
re-signed with both fees raised an eighth (journaled, then dry-run), within the paymaster's ceilings and within the approval's maximum, the payout's floor and the paymaster's
policy and deposit, at the payout address's current state. A raise beyond
the maximum is not signed: the record waits as `gasless_refused`
(`fee_above_authorization`, retried under the approval), after looking once
more for an inclusion of any journaled copy, which is adopted. A withdrawal
saved by an older build without an approval keeps its old rule: a raise
beyond its approved maximum stops it with `fee_bump_needs_quote`, and
rerunning `--to` quotes again. The operation is abandoned 60 seconds before
the proof's `valid_until` (`op_expired`); under an approval it is proved
again, at the same nonce, once the expired copy can no longer be included. An operation found on chain is
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

An escape needs no Merkle path, root, indexer or log scan: its proof binds
the note's leaf, deposit amount and expiry (words 3 and 8 of the vault's
tuple: `noteLeaf` and `noteFields = n·2^192 + D·2^64 + e`), which the vault
compares with the leaf it stored at deposit. Before it proves, the companion
asks the server whether another device already spent the
note's state, and refuses with `device_not_newest` when the server shows a
valid request proof of the next state. The escape proof is valid for 3 hours;
the transaction is checked word by word against the decision you confirmed
(kind 0, destination, concession, `B − c` and `valid_until`, a nonzero note
leaf and note fields of this note below `2^224` whose deposit, at most
`2^53 − 1` units, covers the balance) before it is signed, and is sent through your exit RPC when one is configured. Its
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
state and the state's bound. An escape from it needs no Merkle path; a kit
that still carries one (`merkle_path`, from an earlier release) is accepted
and the path ignored. `exit-kit escape`
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

In the default metered billing mode, requests are serialized, including
concurrent chat/title requests (see [Ticket billing](#ticket-billing) for
concurrent requests). By default,
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

### Ticket billing

`zkapi-clientd config --billing-mode ticket` (with `serve` stopped) switches
the local API from metered leases to fixed-price tickets;
`--billing-mode metered` switches back. Each completion buys one ticket of the
tier its model's OA ticket count (`/chat/model-tickets`) selects from the
protocol server's catalog (`GET /v2/tickets`). The ticket's price is charged,
and the signed successor installed, when it is bought, before the request is
sent, so the next request can buy its ticket and run while earlier responses
are still streaming: up to `concurrency` requests at once. A ticket serves
one request and is consumed afterwards, whatever its outcome; its unused
allowance is not refunded. The key-reuse window does not apply to tickets.

The companion keeps paid tickets in its private inventory until they are
handed out, so a crash or lost reply neither loses a paid key nor buys a
second one, and `serve` returns its earlier run's unused claims at startup,
before the first request. Errors: `model_ticket_tier_unavailable` (no tier
for the model's ticket count), `ticket_terms_changed` (the tier was repriced
twice in a row), `tickets_unavailable` (the server sells no tickets). See
[fixed-price tickets](../../docs/tickets.md) for pricing, lifetime and
failure semantics.

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
