# zkapi-clientd

A local OpenAI-compatible API, paid from your private ETH balance. No OA account or OpenRouter API key needed.

> **Local migration build:** this worktree targets the new concession protocol.
> Sepolia ships its leaf-bound staging deployment, shown as **zkAPI v0.2**
> (`zkapi-native-eth-sepolia-leaf-v4-20261020`, development proving setup; see
> the [Sepolia staging bundle](docs/DEVELOPMENT.md#sepolia-staging-bundle)).
> Mainnet is not deployed in its shipping manifests and production proving keys
> are not available. Do not use the older installer below to obtain this build.
> See [local migration status](docs/LOCAL_PROTOCOL_MIGRATION.md) for binary
> paths, preserved Tor features, withdrawal options, earlier deployments and
> deployment blockers.

## Configuration

`zkapi-clientd config` prints only pretty-printed saved JSON, with credentials
and secret-bearing URL components redacted. It never starts wallet setup.
All saved settings now live under `config`; the top-level `set-*` commands are
removed. See [configuration reference](docs/CONFIGURATION.md).

## Vault protocol selection

`config --vault-protocol legacy|concession` saves this profile's protocol stack;
`config` prints all saved settings as JSON; `config --vault-protocol default`
restores the concession default. Subsequent
commands use the saved choice without exports or repeated flags. Optional
`--vault-protocol` overrides it for one command. Legacy requires a compatible
existing profile and uses a pinned legacy protocol engine/companion. Both stacks
use the same native rewriting, target-transcript and cover-traffic source code;
selecting a vault preserves those settings. No address swap,
state conversion, deposit-closure bypass, or fallback from undeployed concession
networks. See [protocol selection and limitations](docs/VAULT_PROTOCOL.md).

## Optional Tor cover traffic

`config --cover-urls 'https://your-domain.example/cover.txt' --cover-rate 5`
configures bounded background HTTPS noise during native `serve`. Use a small
resource you control or have permission to poll. Requires authenticated `tor://`
routing; no wallet credit, prompt content or inference identities are used.
Disabled by default. See [limits, setup and privacy caveats](docs/COVER_TRAFFIC.md).

## Optional prompt rewriter

`config --rewriter-url http://localhost:8012 --rewriter-model qwen3.8-flash-next`
configures direct normalization with an immediate streamed preview. Saved
rewrites form a separate target-side history; normal continuations send only
new user text to the rewriter. Cache misses rewrite unknown historical user
turns rather than passing them raw. This discloses original text to the rewriter. See [configuration, privacy limits and client display](docs/REWRITER.md).

## Delegation for other AI programs (MCP)

`zkapi-clientd --config-dir PROFILE mcp` is a stdio MCP server for AI hosts.
It attaches to the running `serve` daemon (never starts, funds or configures
it) and offers `zkapi_delegate`, one paid, independent frontier-model
completion per call, plus free `zkapi_list_models`. Delegation requires
`tor://` routing with `IsolateSOCKSAuth`; each call gets a fresh key and Tor
identity, never web search. The provider (and any configured rewriter) still
reads the task, and network anonymity is not guaranteed. Development
builds only. See [MCP delegation](docs/MCP_DELEGATION.md) and the portable
agent skill in [skills/zkapi-delegate](skills/zkapi-delegate/SKILL.md).

## Build this branch

Follow [development builds and validation](docs/DEVELOPMENT.md). Published
`clientd-v0.1.6` packages do **not** contain this branch's privacy features or
protocol selector; do not use their installer to update this build.

The examples below assume `zkapi-clientd` refers to the newly built
`bin/zkapi-clientd-concession-tor` entry point. Global `--config-dir DIR` belongs
**before** the command. Select the correct existing profile/protocol before any
wallet operation; concession funding refuses Mainnet, which is not deployed yet.

## Usage

Configure your wallet:

```sh
zkapi-clientd config --setup
```

Setup updates payment details and progress in place while you wait. Menus use
the arrow keys and Enter; Ctrl+C stops safely and preserves your progress.

Then start the API:

```sh
zkapi-clientd serve
```

Choose a saved default model (stop the daemon before changing it):

```sh
zkapi-clientd list-models
zkapi-clientd config --model provider/model
zkapi-clientd config                 # display all settings
zkapi-clientd config --clear-model   # remove default
```

The default is used for requests that omit `model` and for funding recommendations.
Explicit request models take precedence. Listing/selection does not spend funds.

`serve` automatically opens a missing private note once funded: it prints the
ETH receiving address, network, and required top-up, then waits for funds.
Use `serve --model MODEL` for a model-aware recommendation:
`max(3 × per-query cap converted to ETH, 10 × estimated deposit gas)`, plus
network fees/buffer. Without a model or saved default, it uses the highest reviewed cap ($6).
Starting `serve` authorizes this deposit; Ctrl+C stops waiting. The recommendation
is a minimum: once funded, the unsigned deposit grows to use the available ETH
minus the quoted maximum fee allowance, rounded down to whole gwei. Unused fee
allowance/dust remain public. Signed transactions retain their amount and are
recovered rather than replaced; explicit manual deposits are not resized.

```sh
zkapi-clientd withdraw          # private withdrawal, then public remainder return
zkapi-clientd withdraw --public # return leftover funding-address ETH separately
```

After private withdrawal, the same command returns public funds to the same
destination with a separate fee approval. Interrupted returns resume; completed
returns are not repeated for dust. Withdrawals can start a temporary daemon
if none is running. See [lifecycle details](docs/CLI_ZKAPI.md#one-command-funding-and-withdrawal).

Leave that terminal running. In Open WebUI or another OpenAI-compatible client, set the base URL to **`http://127.0.0.1:8787/v1`** and leave the API key empty (use `local` if the app requires a value). Select a model and chat. The endpoint accepts local connections only.

Web search is on by default for all chat completions through OpenRouter's web
plugin. Search charges apply, including for background title and follow-up
requests from your UI. To turn the default off, stop `serve`, run
`zkapi-clientd config --web-search=false`, then restart `serve`.
Use `zkapi-clientd config --web-search=true` or `config --edit` to turn it back on.
See [web search](docs/CLI_ZKAPI.md#web-search) for configuration details.

The default reuses an OpenRouter key for a fixed window of up to 60 seconds.
Without Tor mode or rewriting enabled, compatible requests from different chats,
local clients, and Open WebUI's title/follow-up requests can share a key and its
spending cap. With Tor or rewriting enabled, unrelated message histories rotate
the key; eligible prefix-continuing histories can reuse it. The provider can
link requests using the same key. Your saved key-reuse setting is preserved across updates.
Settlement starts automatically when the window ends, even without another
request. An active response finishes first.
For conversation-aware Tor routing, configure Tor's SOCKS port with
`IsolateSOCKSAuth`, then select `zkapi-clientd config --relay-url tor://127.0.0.1:9050`
while the daemon is stopped. The ordinary OpenAI endpoint now retains a Tor
isolation identity for prefix-continuing message histories and rotates both
identity and provider key for unrelated histories. No wrapper CLI is required.
See [Tor mode and its limits](docs/CLI_ZKAPI.md#tor).

For fixed-price tickets that run requests concurrently, stop `serve`, run
`zkapi-clientd config --billing-mode ticket`, then restart `serve`; see
[ticket billing](docs/CLI_ZKAPI.md#ticket-billing).

For a fresh key per inference request, stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve`.
With reuse disabled, settlement starts after each response. Fresh keys may wait
for the previous key's settlement.

To update this branch, stop `serve`, rebuild both engines as documented, and
restart using the same profile. Do not replace a live wallet or proving setup.
See [wallet storage and updates](docs/CLI_PACKAGING.md#wallet-storage-and-updates).

To withdraw, run `zkapi-clientd config --menu` and choose `withdraw`, or
`zkapi-clientd withdraw --to ADDRESS` then `--approve QUOTE_ID`.

Where the deployment publishes a gasless withdrawal paymaster (Sepolia today),
sending to an address with the network fee paid from the payout is the only
new withdrawal, as in the web app: the local signing address needs no ETH, no
fee QR appears and no wallet-paid fee is offered. The withdrawal is carried by
an ERC-4337 user operation from a transit account bound to your destination,
signed with a fresh key per withdrawal and sponsored by the paymaster, which
keeps a measured gas charge and pushes the rest to the destination. The quote
shows the estimated fee (the actual fee may change), the most the fee may take
and the least the destination receives; you approve once, and fee changes
within that maximum are handled without asking again. See
[gasless withdrawals](docs/CLI_ZKAPI.md#paying-the-fee-from-the-payout-gasless-withdrawals).

For chain and protocol access the client uses only the RPC, zkAPI indexer and
protocol server packaged with the release. A deposit activates only after the
vault, read at the deposit's block, and a second source show it at the same
note: the indexer's whole-tree snapshot, or, while the indexer has no view of
that block, your exit RPC (without one the deposit waits for the indexer); a
withdrawal finishes only after the vault shows the note closed at the payout
block, through your exit RPC as well when one is set. A withdrawal first proves note ownership to the protocol server, which
then clears the cooperative close. When the operator cannot or will not
clear it, `zkapi-clientd withdraw --escape --to ADDRESS` exits through the
vault alone, after its challenge period. See
[chain verification and recovery](docs/CLI_ZKAPI.md#chain-verification-and-recovery)
and [escape withdrawals](docs/CLI_ZKAPI.md#escape-withdrawals).

[More options, including Tor, Sepolia and Docker clients](docs/CLI_ZKAPI.md) · [Installation details](docs/CLI_PACKAGING.md) · [Privacy](docs/PRIVACY.md)

[NixOS, AUR, and Homebrew packages with background services](docs/CLI_PACKAGING.md#platform-packages-and-background-services) are also available in this repository.
