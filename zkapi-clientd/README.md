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

For unattended use (a background service, container, CI job or script), `serve --allow-unfunded` starts before the wallet is funded, and `zkapi-clientd fund` and `zkapi-clientd withdraw` manage the wallet through the running daemon without prompts. Every payment is a quote followed by `--approve` with that exact quote ID. See [scripted funding and withdrawal](docs/CLI_ZKAPI.md#scripted-funding-and-withdrawal).

[More options, including Tor, Sepolia and Docker clients](docs/CLI_ZKAPI.md) · [Installation details](docs/CLI_PACKAGING.md) · [Privacy](docs/PRIVACY.md)

[NixOS, AUR, and Homebrew packages with background services](docs/CLI_PACKAGING.md#platform-packages-and-background-services) are also available in this repository.
