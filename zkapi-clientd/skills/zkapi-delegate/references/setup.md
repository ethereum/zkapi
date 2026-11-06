# Setting up zkAPI delegation

These steps are for the human operator. An agent should only point the user
here; it must not start, fund or reconfigure the daemon.

## Status

This is development source, not a shipped release. The Mainnet concession
deployment is not deployed and has no production proving keys; Sepolia runs
the leaf-bound staging deployment (zkAPI v0.2) with a development setup and
test ETH only. Published `clientd-v0.1.6` packages and older builds do not
contain `zkapi-clientd mcp` or the delegation route; build from source. A
legacy-vault profile can run the adapter, but its engine refuses delegation.

## Requirements

1. A configured, funded `zkapi-clientd` profile whose daemon (`zkapi-clientd
   serve`) is running. The adapter only attaches to it.
2. Tor with a numeric loopback SOCKS port and authentication isolation, for
   example `SocksPort 127.0.0.1:9050 IsolateSOCKSAuth` in `torrc`.
3. The daemon in Tor mode. With serve stopped:
   `zkapi-clientd --config-dir PROFILE config --relay-url tor://127.0.0.1:9050`,
   then start serve again. Without it every delegation is refused before any
   payment. Direct, Wisp and plain `socks5://` routes are not accepted for
   delegation; ordinary chat keeps working on them.

Delegation never enables web search, whatever the chat default.

If the profile configures the optional prompt rewriter, every delegated task
and context is sent in original form directly to that endpoint, outside Tor and
zkAPI, and it can read and link calls. Point it only at a rewriter you trust
(local or a TEE you chose); the adapter does not attest where it runs.

## MCP host configuration

The server is `zkapi-clientd [--config-dir PROFILE] mcp` over stdio. Use
absolute paths and the same profile as the running daemon. From the saved
config it uses only the connection settings and default model; it never loads
or creates the separate wallet management credential, and writes nothing.

Generic JSON (Claude Desktop, Cursor and similar hosts):

```json
{
  "mcpServers": {
    "zkapi": {
      "command": "/absolute/path/to/zkapi-clientd",
      "args": ["--config-dir", "/absolute/path/to/profile", "mcp"]
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.zkapi]
command = "/absolute/path/to/zkapi-clientd"
args = ["--config-dir", "/absolute/path/to/profile", "mcp"]
tool_timeout_sec = 660
```

Claude Code:

```sh
claude mcp add zkapi -- /absolute/path/to/zkapi-clientd --config-dir /absolute/path/to/profile mcp
```

Timeouts: the daemon may take up to 10 minutes for one delegation (waiting for
the previous key's settlement, then inference) and the adapter gives up after
11 minutes. Raise the host's MCP tool timeout to about 11 minutes where it is
configurable (Codex `tool_timeout_sec`; Claude Code `MCP_TOOL_TIMEOUT`, in
milliseconds). A host that cancels earlier stops waiting, but cancellation is
not a refund: a request that already reached the provider may be charged.

Payments: zkAPI caps each call at the model's per-call limit, but the adapter
has no session budget. Limit paid calls with your host's tool approval
settings if you want per-call confirmation.

## Install the skill

Copy this `zkapi-delegate` folder into the host's skills directory, for
example `~/.codex/skills/zkapi-delegate` or `~/.claude/skills/zkapi-delegate`.
It needs only the MCP server above.

## Without MCP

The same daemon route accepts the same fields directly on loopback:

```sh
curl -sS http://127.0.0.1:8787/v1/zkapi/delegate \
  -H 'Content-Type: application/json' \
  -d '{"task":"Explain why this loop never terminates: for i := 0; i < 10; i-- {}"}'
```

Add `-H "Authorization: Bearer $KEY"` when the profile sets
`require_api_key`. Use the profile's listen address. Each request is paid.
