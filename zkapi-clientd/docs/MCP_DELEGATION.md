# MCP delegation

`zkapi-clientd mcp` lets another AI program (a smaller local model, or a model
in a trusted execution environment) hand one hard task at a time to a frontier
model, paid through zkAPI. It is a stdio [Model Context Protocol] server that
attaches to the daemon you already run with `zkapi-clientd serve`.

The portable agent skill is [`skills/zkapi-delegate`](../skills/zkapi-delegate/SKILL.md);
operator setup and MCP host examples are in its
[`references/setup.md`](../skills/zkapi-delegate/references/setup.md).

[Model Context Protocol]: https://modelcontextprotocol.io/

## Status

Development source only. The Mainnet concession deployment is `not_deployed`
and production proving keys are missing; Sepolia ships the staging deployment
(zkAPI v0.2, development setup, test ETH). Published `clientd-v0.1.6` packages
and earlier builds have neither the `mcp` command nor the delegation route;
the adapter reports such a daemon as an older build. Build and run as in
[development builds](DEVELOPMENT.md). The legacy vault engine compiles the
shared route but lacks the capability, so it answers `delegation_unsupported`.

## Tools

| tool | cost | effect |
|---|---|---|
| `zkapi_delegate` | paid per call | One non-streaming text completion. Arguments: `task` (required, ≤ 32 KiB), `context` (≤ 192 KiB), `model`, `max_output_tokens` (1–32768, default 4096), `reasoning_effort` (`low`/`medium`/`high`). Unknown arguments are rejected. |
| `zkapi_list_models` | free | Public model IDs and per-call caps from the daemon's `/v1/models` (optional `search`). No key is acquired. |

`zkapi_delegate` is annotated as not read-only, not idempotent, destructive
(it spends balance) and open-world. The answer is returned as text plus
structured `finish_reason`, `truncated`, coarse token `usage` and
`credential_verification`; `truncated` means the answer is incomplete because
it hit the token limit or the daemon's answer-size bound. Provider generation IDs, routed provider names,
reasoning text and credentials are dropped. A model omitted by the caller uses
the running daemon's default model.

## What each delegation guarantees

The adapter posts to the daemon's loopback route `POST /v1/zkapi/delegate`.
That route accepts only the five fields above and builds the provider request
itself: one user message (task, then `Context:` and the context), `stream:
false`, the token limit and optional reasoning effort. There are no caller
messages, system prompts, tools, plugins, metadata, user IDs or headers, and no
web search even when the chat default enables it; `:online` models are refused.

In the daemon, each delegation:

- requires explicit Tor mode (`relay_url` `tor://IP:PORT`); otherwise it fails
  with `delegation_requires_tor` before queueing, model policy or any lease;
- creates a fresh random SOCKS authentication identity and opens the isolated
  route before acquiring a lease (`tor_preparation_failed` spends nothing);
- never uses the cached chat key and never caches its own key, whatever the key
  reuse window; its lease group retires as soon as the response ends, so later
  chat or delegation cannot reuse it;
- does not read or update the chat conversation matcher, so identical repeated
  delegations, and delegations interleaved with chat, never share keys or Tor
  identities;
- rewrites with a transcript scoped to the call when the rewriter is enabled
  (nothing is replayed from, or kept for, other requests);
- keeps the existing request slot, model budget, lease verification, settlement,
  TLS, response-size and error-redaction paths; the wallet companion still
  receives only the spending cap, never prompts, responses or model IDs;
- never retries inference, and is bounded to 10 minutes (adapter: 11).

The route requires a loopback peer and a loopback `Host` even when an API key
is configured, rejects browser origins, and refuses a backend without the
delegation capability. No delegation content is logged; logs show the route,
status, timing and local key reference only (verbose modes are unchanged).

## Adapter boundaries

- Attaches only: it never starts, funds, configures or withdraws. It loads
  and validates the saved config but uses only the connection settings and
  default model; it never loads or creates the separate management credential
  and writes no files.
- Connects only to the profile's numeric loopback address, ignores proxy
  environment variables, refuses redirects, uses no cookies or keep-alives,
  and sends only the local inference API key.
- Writes only MCP frames to stdout; failures go to stderr.
- Error texts are fixed messages. Wallet and protocol identifiers, such as the
  note nullifier of `receipt_journal_missing`, are withheld from delegation and
  from MCP output; the owner sees them through `zkapi-clientd config` and chat.
- MCP versions 2024-11-05 through 2025-11-25 are negotiated through the
  official Go SDK (v1.8.0), which also supports 2026-07-28 clients.

## Privacy limits

Each call uses zkAPI's unlinkable credential and payment protocol and a fresh
authenticated Tor SOCKS identity. Network anonymity is not guaranteed: timing,
shared exits, traffic correlation, the content itself, or a Tor service without
`IsolateSOCKSAuth` (which the daemon cannot verify) can link calls. There is no
content anonymity: the provider reads every task in plain text.

If the operator configured the optional prompt rewriter, the original task and
context go directly to that rewriter endpoint, outside Tor and zkAPI, and it
can read and link calls. Use only a rewriter you trust (local or a TEE of your
choice); the adapter does not attest where it runs.

The host running the agent and daemon is trusted with everything; nothing here
proves that a model runs locally or in a TEE. Model answers are untrusted text.

## Timeouts, cancellation and cost

A call can wait for the previous key's settlement before inference. Set the MCP
host's tool timeout to about 11 minutes where configurable. Cancelling a call
(or a host timeout) cancels the daemon request, but is not a refund: once the
request reached the provider it may be charged, and nothing is retried. The
same holds when the adapter loses its connection to the daemon or gets an
incomplete reply: the tool reports the outcome as unknown and possibly charged. Each
call is capped by the selected model's per-call limit; the adapter has no
session budget, so use the host's tool-approval settings to limit spending.

## Verification

Regression tests cover fresh keys and identities for identical and interleaved
delegations, the per-call rewriter transcript, refusal without Tor before any
lease, request shaping without web search or caller fields, redaction, the
legacy fail-closed path, loopback/redirect/proxy handling, cancellation without
retry, version negotiation and a real stdio session. They use local fakes; they
do not show Tor circuit behavior, live provider acceptance or anonymity.

### Live Sepolia check (2026-10-29)

One end-to-end run on the Sepolia staging deployment (zkAPI v0.2, development
proving setup, test ETH) used a built `zkapi-clientd` with a `dev-setup`
companion from the same source, a fresh profile and a local Tor with
`IsolateSOCKSAuth`. `TestLiveSepoliaDeployment` passed first. Two identical
`zkapi_delegate` calls through the real `mcp` binary to
`anthropic/claude-sonnet-5.5` (256 output tokens, no reasoning override, no
rewriter, web search off) each returned a plausible answer in about 35 s:
`finish_reason` stop, not truncated, `credential_verification` verified. The
daemon log showed a separate fresh key for each call (key references 1 and 2),
each retired after its response, and automatic settlement ready for both
(777 and 746 gwei). The private balance fell by exactly their sum.

Scope: the two calls ran one after another, each after the previous
settlement, so they do not exercise reuse within a key window (the regression
tests cover that). Inference went over Tor; the profile's deposit setup was
completed over direct HTTPS before Tor mode was restored. The run shows the
path works with real proofs, keys, provider and settlement; it measures no Tor
exit or correlation properties and is not evidence of anonymity. The reusable
harness is `scripts/live-mcp-sepolia.py` (opt-in, paid, never retries; it
refuses unless the running daemon reports the pinned Sepolia deployment).
