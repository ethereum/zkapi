# zkapi-clientd

A local OpenAI-compatible API, paid from your private ETH balance. No OA account or OpenRouter API key needed.

> **Sepolia development build:** this worktree pins the deployed revision-4
> Sepolia vault. Its proving keys are for testnet development. Mainnet's new
> protocol remains unavailable. Build this branch as described below; older
> published installers do not contain these changes. See
> [deployment and recovery status](docs/LOCAL_PROTOCOL_MIGRATION.md).

## Configuration

`zkapi-clientd config` prints only pretty-printed saved JSON, with credentials
and secret-bearing URL components redacted. It never starts wallet setup.
All saved settings now live under `config`; the top-level `set-*` commands are
removed. See [configuration reference](docs/CONFIGURATION.md).

## Vault protocol selection

`config --vault-protocol legacy|concession-v1|concession` saves this profile's protocol stack;
`config` prints all saved settings as JSON; `config --vault-protocol default`
restores the concession default. Subsequent
commands use the saved choice without exports or repeated flags. Optional
`--vault-protocol` overrides it for one command. Legacy requires a compatible
existing profile and uses a pinned legacy protocol engine/companion.
`concession-v1` selects the original revision-3 Sepolia engine for existing
balances. The default `concession` selects revision 4. All stacks
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

## Build this branch

Follow [development builds and validation](docs/DEVELOPMENT.md). Published
`clientd-v0.1.6` packages do **not** contain this branch's privacy features or
protocol selector; do not use their installer to update this build.

The examples below assume `zkapi-clientd` refers to the newly built
`bin/zkapi-clientd-concession-tor` entry point. The [local Sepolia bundle setup](docs/DEVELOPMENT.md#sepolia-acceptance)
adds workspace-only `bin/zkapi-clientd` and `bin/zkapi-walletd` aliases, the proving
asset link, and the required current-shell PATH; it leaves global installations
and existing profiles intact. Global `--config-dir DIR` belongs
**before** the command. Select the correct existing profile/protocol before any
wallet operation; revision-4 funding is available on Sepolia; its Mainnet profile remains unavailable.

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

For a fresh key per inference request, stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve`.
With reuse disabled, settlement starts after each response. Fresh keys may wait
for the previous key's settlement.

To update this branch, stop `serve`, rebuild both engines as documented, and
restart using the same profile. Do not replace a live wallet or proving setup.
See [wallet storage and updates](docs/CLI_PACKAGING.md#wallet-storage-and-updates).

To withdraw, run `zkapi-clientd config --menu` and choose `withdraw`. It asks for the destination and waits for extra ETH for fees only if needed.

Where the deployment publishes a gasless withdrawal paymaster, the menu also
offers to pay the network fee from the payout itself ("no ETH needed"): the
withdrawal is then carried by an ERC-4337 user operation from a transit
account bound to your destination, signed with a fresh key per withdrawal and
sponsored by the paymaster, which keeps a measured gas charge and pushes the
rest to the destination. On the command line this is `zkapi-clientd withdraw
--to ADDRESS --fees payout` (defaults: `config --withdrawal-fees payout
--bundler-url URL`); `--collect`, `--sweep` and `--claim-credit` deliver a
payout that is waiting in the transit account or the paymaster. See
[gasless withdrawals](docs/CLI_ZKAPI.md#paying-the-fee-from-the-payout-gasless-withdrawals).

For chain and protocol access the client uses only the RPC, zkAPI indexer and
protocol server packaged with the release. A deposit's note is saved only
after the vault, read at the deposit's block, and the indexer's snapshot both
record it at the same note; with your own exit RPC set (`config
--exit-rpc-url URL`), once the deposit is final there, it stands in for an
indexer that does not. The operator's batch then activates the note for
requests, while withdrawals are available at once. A withdrawal finishes only
after the vault shows the note closed, through your exit RPC too when one is
set. A withdrawal first proves note ownership to the protocol server, which
then clears the cooperative close. When the operator cannot or will not
clear it, `zkapi-clientd withdraw --escape --to ADDRESS` exits through the
vault alone, after its challenge period. See
[chain verification and recovery](docs/CLI_ZKAPI.md#chain-verification-and-recovery)
and [escape withdrawals](docs/CLI_ZKAPI.md#escape-withdrawals).

[More options, including Tor, Sepolia and Docker clients](docs/CLI_ZKAPI.md) · [Installation details](docs/CLI_PACKAGING.md) · [Privacy](docs/PRIVACY.md)

[NixOS, AUR, and Homebrew packages with background services](docs/CLI_PACKAGING.md#platform-packages-and-background-services) are also available in this repository.
