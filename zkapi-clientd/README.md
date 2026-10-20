# zkapi-clientd

A local OpenAI-compatible API, paid from your private ETH balance. No OA account or OpenRouter API key needed.

## Quick start

Install or update:

```sh
curl -fsSL https://github.com/ethereum/zkapi/releases/download/clientd-v0.1.6/install.sh | bash
```

Configure your wallet:

```sh
zkapi-clientd config
```

Setup updates payment details and progress in place while you wait. Menus use
the arrow keys and Enter; Ctrl+C stops safely and preserves your progress.

Then start the API:

```sh
zkapi-clientd serve
```

Leave that terminal running. In Open WebUI or another OpenAI-compatible client, set the base URL to **`http://127.0.0.1:8787/v1`** and leave the API key empty (use `local` if the app requires a value). Select a model and chat. The endpoint accepts local connections only.

Web search is on by default for all chat completions through OpenRouter's web
plugin. Search charges apply, including for background title and follow-up
requests from your UI. To turn the default off, stop `serve`, run
`zkapi-clientd config --web-search=false`, then restart `serve`.
Use `zkapi-clientd config --web-search=true` or `config --edit` to turn it back on.
See [web search](docs/CLI_ZKAPI.md#web-search) for configuration details.

The default reuses an OpenRouter key for a fixed window of up to 60 seconds.
Compatible requests from different chats, local clients, and Open WebUI's title
and follow-up requests can share a key and its spending cap; the provider can
link those requests. Your saved key-reuse setting is preserved across updates.
Settlement starts automatically when the window ends, even without another
request. An active response finishes first.
For a fresh key per inference request, stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve`.
With reuse disabled, settlement starts after each response. Fresh keys may wait
for the previous key's settlement.

To update, stop `serve`, rerun the install command, then start `serve` again. Your wallet is preserved. See [wallet storage and updates](docs/CLI_PACKAGING.md#wallet-storage-and-updates).

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
protocol server packaged with the release. A deposit activates only after the
vault, read at the deposit's block, and the indexer's whole-tree snapshot both
show it at the same note; a withdrawal finishes only after both show the note
closed. A withdrawal first proves note ownership to the protocol server, which
then clears the cooperative close. When the operator cannot or will not
clear it, `zkapi-clientd withdraw --escape --to ADDRESS` exits through the
vault alone, after its challenge period. See
[chain verification and recovery](docs/CLI_ZKAPI.md#chain-verification-and-recovery)
and [escape withdrawals](docs/CLI_ZKAPI.md#escape-withdrawals).

[More options, including Tor, Sepolia and Docker clients](docs/CLI_ZKAPI.md) · [Installation details](docs/CLI_PACKAGING.md) · [Privacy](docs/PRIVACY.md)

[NixOS, AUR, and Homebrew packages with background services](docs/CLI_PACKAGING.md#platform-packages-and-background-services) are also available in this repository.
