# Client configuration and use

The public commands are `zkapi-clientd config`, `serve`, `fund` and `withdraw`.
The client only supports zkAPI private ETH balances. Ticket issuance, import,
redemption and ticket-based inference are not included.

## Configuration

A new `config` creates the private configuration directory and defaults to
Ethereum Mainnet, direct HTTPS and a loopback listener at `127.0.0.1:8787`.
It asks for the deposit amount in USD, defaulting to $20 on Enter, and shows the
ETH amount, receiving address and locally generated QR. It waits automatically
for ETH and updates the receiving balance. Once funded, Enter approves the
fixed deposit with network fees that adjust automatically while the receiving
balance covers the principal and required fees. It checks a fresh quote before
signing, deposits and activates the private balance once its successful mined
receipt is validated against the canonical block and saved deposit. There is
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
```

To fund from a script instead, see
[scripted funding and withdrawal](#scripted-funding-and-withdrawal).

Use the arrow keys (or `j`/`k`) and Enter to select wallet actions and networks.
Esc or `q` cancels a selection. Text prompts remain available when output is
redirected. Ctrl+C stops safely and preserves saved progress; run
`zkapi-clientd config` again to continue.

`serve` does not prompt or authorize funding. Missing prerequisites point back
to `config`. Configuration stops temporary services it starts; an existing
compatible service it reused remains running. Stop a running service before
editing its configuration.

By default `serve` exits when the wallet cannot spend: before the first
deposit, with an empty private balance, or while a withdrawal is reserved.
`serve --allow-unfunded` logs a warning instead and keeps running, without
reporting itself ready for inference. Inference returns `402 funding_required`
(or `409 withdrawal_pending`) until the wallet can spend, and a deposit made
through the running daemon takes effect without a restart. Companion and wallet
status errors still stop `serve`.

## Scripted funding and withdrawal

On a host without a terminal, `zkapi-clientd config --network mainnet` creates
the profile, then stops with an error at the first wallet question without
spending anything. Start `serve --allow-unfunded` (for example as a service,
see [background services](CLI_PACKAGING.md#platform-packages-and-background-services))
and fund the wallet with `fund`.

`fund` and `withdraw` never read the terminal. They act through the running
daemon (`serve`, a background service, or a temporary `config` daemon) and its
authenticated local admin API, using the API key in `config.json` and the
owner-only `management-token` file. Run them as the service user with the same
`--config-dir`. Anyone who can read that directory can authorize payments, as
with the admin API; keep it private.

Every payment takes two steps:

1. A quote (`fund --usd N`, `fund --amount ETH`, `withdraw --to ADDRESS` or
   `fund return --to ADDRESS`)
   shows the fixed amount, destination, local signing address and maximum
   network fee. It signs nothing.
2. `--approve QUOTE_ID` signs and broadcasts only that exact quote, if it is
   still the saved quote and has not expired. Quotes expire after 30 seconds,
   and a new quote replaces the previous one.

Approval waits until the deposit is active, or until the withdrawal is final
(about 15 minutes). If it is interrupted, `--resume` recovers the saved signed
transaction and never authorizes another. Without options, each command shows
the address, balances and saved progress. Commands exit with a nonzero status
on failure.

Add `--json` to a quote to print it as one JSON object on standard output,
with status text on standard error. If no new quote is prepared, for example
because a signed withdrawal is already saved, the command exits nonzero and
prints nothing on standard output. Amounts are decimal strings in wei.

| Key | Value |
| --- | --- |
| `id` | Quote ID to pass to `--approve` |
| `kind` | `fund`, `withdraw` or `return` |
| `network` | `mainnet` or `sepolia` |
| `address` | Local signing address that pays fees (and the deposit) |
| `destination` | Recipient; `withdraw` and `return` only |
| `amount_wei` | Fixed deposit principal, withdrawn private balance, or returned amount |
| `max_fee_wei` | Maximum network fee approved with the quote |
| `required_total_wei` | Public ETH the signing address needs for this quote: the deposit or returned amount (none for `withdraw`) plus the required network fee, which can be lower than `max_fee_wei` |
| `shortfall_wei` | ETH still missing on the signing address; `"0"` when funded |
| `expires_at` | Expiry as a Unix time in milliseconds |

The wallet holds one note, and a note cannot be topped up. To add funds after
a deposit, withdraw the note (for example to an address you control), then fund
a new one. A withdrawal cannot be quoted while an inference key is still
settling. Settlement starts when the key reuse window ends (60 seconds by
default), so retry `withdraw --to` after that. `fund return --to ADDRESS`
sends public ETH left on the local signing address, with the same quote and
`--approve` steps.

```sh
# Show the local signing address. Send it ETH for the deposit plus network fees.
zkapi-clientd fund

# Quote a $20 deposit and approve that exact quote once the address is funded.
quote=$(zkapi-clientd fund --usd 20 --json)
if [ "$(printf '%s' "$quote" | jq -r .shortfall_wei)" = 0 ]; then
  zkapi-clientd fund --approve "$(printf '%s' "$quote" | jq -r .id)"
fi

# Withdraw the full private balance, closing the note.
quote=$(zkapi-clientd withdraw --to 0xYourAddress --json)
zkapi-clientd withdraw --approve "$(printf '%s' "$quote" | jq -r .id)"
```

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

Start Tor with a local SOCKS listener, then select its numeric loopback address:

```sh
zkapi-clientd config --relay-url socks5://127.0.0.1:9050
zkapi-clientd serve
```

The client passes destination names to SOCKS5 for remote DNS and keeps HTTPS
certificate verification. The Go frontend and the wallet companion use the
same route. If Tor is unavailable, requests fail instead of connecting directly.
Keep the local OpenAI-compatible API at its loopback URL. Stop a running
`serve` before changing its saved transport. `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` do not change this client's route.
On macOS, `torify zkapi-clientd serve` alone does not route the Go client; set
the SOCKS5 relay URL above even when launching it through `torify`.

## Deployment origins

The client defaults use these deployment manifests and vaults:

| Network | Manifest | Vault |
| --- | --- | --- |
| Mainnet | `https://zkapi-mainnet.openanonymity.ai/config.json` | `0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe` |
| Sepolia | `https://zkapi-sepolia.openanonymity.ai/config.json` | `0x49fA19f9bdECe7A48Ebc7749fD69aD40F577590F` |

The embedded manifests pin the deployment IDs, contracts, signing keys, oracle
and proof setup. Wallet funding and recovery records are bound to the configured
network and deployment. Unknown origins or unapproved manifest differences fail
closed. Do not delete recovery data to bypass a configuration mismatch.

Stop `serve` before installing an update. The installer preserves private files;
updating the repository alone does not update an installed binary.

## Withdrawals

Choose `withdraw` in `config --menu`. A new withdrawal asks for the destination
once and shows its full private payout. If gas is insufficient, it shows the
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
matching payout submitted independently. Public ETH return remains a separate
wallet menu action with its own approval. Return quotes expire after 30 seconds;
if one expires before signing, run the same wallet menu again and review a
fresh quote. A saved signed return resumes its original transaction instead.

Returning `all` requires an ordinary Ethereum account with no deployed code.
For a delegated or contract recipient, choose an exact ETH amount and leave
room for the displayed maximum fee. The exact-amount path still simulates the
transfer and requires destination, amount and fee approval.

`zkapi-clientd withdraw` and `zkapi-clientd fund return` do the same from a
script; see [scripted funding and withdrawal](#scripted-funding-and-withdrawal).

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
