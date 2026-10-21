# Direct prompt rewriter and target-side transcript (opt-in)

The daemon maintains a separate target-side history. Pi/client history stays
unchanged; every user text part in a target request must have passed through
the rewriter. Cached rewrites are replayed verbatim, never replaced by the
original text when the caller resends its history.

## Configure

Stop the daemon before changing its configuration:

```sh
# From the repository root:
CLIENT="$PWD/zkapi-clientd/bin/zkapi-clientd-concession-tor"
$CLIENT config --rewriter-url http://localhost:8012 --rewriter-model qwen3.8-flash-next
$CLIENT config                      # status, never prints the key
$CLIENT config --clear-rewriter              # disable and remove the saved key
```

On first configuration, no API key is sent unless supplied. Partial edits preserve
an existing key; `--rewriter-clear-api-key` explicitly removes it. For a keyed service, populate an environment
variable using your secret-management method and pass `--rewriter-api-key-env VARIABLE`.
The value is saved in owner-only `config.json` through the locked atomic update;
wallet/inference/management credentials remain unchanged. Omitted options retain
their saved values. Do not put keys in URLs or shell arguments.

A URL can be an API base or a complete `/chat/completions` endpoint; an origin
alone adds `/v1/chat/completions`. Remote endpoints require verified HTTPS;
loopback HTTP is allowed. Requests go **directly**, outside Tor/Wisp, ignoring
environment proxies. No cookies, redirects or automatic HTTP retries.
Configuration sends no request/payment. The feature is disabled by default.
Older binaries may reject its config field; clear it before rollback.

## Separate histories and efficient rewriting

Under the serialized inference slot the daemon:

1. Classifies the incoming original history using canonical message digests.
2. For an exact retry or prefix continuation, substitutes saved rewritten user
   messages. Assistant/tool/system messages remain as supplied by the caller.
3. Sends only each **new user turn's text** to the rewriter, with a short fixed
   normalization instruction. No earlier conversation, images, tool definitions,
   target model settings or target credentials accompany that rewrite.
4. Sends the reconstructed target-side transcript to the target.

Ordinary continuation costs one rewrite of the new user turn; retries and
agent tool-result continuations read no old user text at the rewriter. Multiple
text parts of a user message are handled together in one call. The target API
still receives full history, as required by its stateless interface.

The cache contains only original-message hashes and normalized user messages,
not raw originals. It is memory-only, scoped to the immediately previous history,
not a cross-user content cache. Max 4,096 messages and 8 MiB cached rewritten
messages/preview text; overflow fails closed. No wallet recovery file is changed.

On restart, interleaving, an edited/truncated history or a resumed chat without
matching cache state, **all unknown user turns are normalized before inference**.
Each is processed independently without conversation context; this costs extra
reads once but never falls back to sending old user prompts raw. No prefix search
across unrelated sessions, disk persistence, or unbounded cache. The new cache
is committed only after all turns succeed. Failures never return a partial
transcript to inference. A subsequent retry can reuse a completed rewrite even
if later routing/payment/inference failed.

OR key reuse is based on the original conversation, not nondeterministic rewrite
text. A continuation keeps its eligible key within the existing fixed reuse
window, provider expiry, same budget and successful-response rules. A new or
non-prefix conversation clears the key even in non-Tor rewriter mode. No key
expiry extension or weakening of settlement/payment checks.

## Privacy and semantic limits

The editor extracts the task, necessary context and constraints, then rebuilds
the request in that order using concise task-first prose—not sentence-by-sentence
proofreading. It changes structure and removes nonessential conversational or
personal framing, with no headings for simple requests. It must not answer, add
facts, resolve missing context, or change requirements, conditions, negation,
uncertainty or meaningful personal context. Code, quotes,
identifiers, paths, URLs, numbers and exact-output constraints are preserved.
Unknown content-part types fail rather than bypassing rewriting. Known images,
audio and file attachments are retained and are **not anonymized**.

"No raw user prompt" means no bypass of this processing for text in `user`
messages, including historical ones. It is not a guarantee that every character
changes: normalized wording may match the original, especially code/quotes.
Nor can the daemon recognize user prose copied into system/developer instructions,
assistant messages, tool results, attachments, schemas or other request fields.
Those remain unchanged; clients must not place raw prompts there if they require
that broader guarantee. Compacted text in a new user message is rewritten; a
compaction placed in a system message is not. Meaning preservation and reduced
stylometric identifiability are model instructions, not proven properties.

The rewriter sees original text and your direct connection. HTTPS encrypts the
wire but does not anonymize you from that service or any upstream it uses.
Identifying facts, quotes, code, attachments and traffic timing remain risks.
Parallel rewriter/Tor activity can help an observer correlate connections.

## Style instruction

The default instruction reconstructs meaning with neutral task-first syntax,
collapses redundant wording and audits constraints. It contains no worked task
examples. See the [local candidate evaluation](REWRITER_EVALUATION.md), including
observed failures and limits—not a guarantee of anonymity or fidelity.

Override it with `config --rewriter-instruction-file PATH`, or reset with
`config --rewriter-default-instruction`. Bare `config` shows the effective text.
The JSON response contract and fail-closed parser remain fixed. See
[instruction configuration](CONFIGURATION.md#rewriter-instruction) for storage,
limits, disclosure and restart behavior.

## Immediate preview

Default `--rewriter-notice reasoning` flushes a local SSE prelude as soon as the latest
user rewrite is available, before lease acquisition and target inference:

- `choices[0].delta.reasoning_content`, labelled
  `zkapi prompt rewrite — NOT target-model thinking`;
- `zkapi_rewrite: {source, message_index, texts}` for custom UI adapters.

This is UI metadata, not added to target input. Cached retries show the same
preview; tool continuations do not repeat it. Backfilled older turns are protected
but only a trailing user turn gets a preview. Text is quoted for unambiguous
display. The prelude does not pause for approval: cancel to stop inference.

`--rewriter-notice metadata` omits the thinking delta; `--rewriter-notice off` omits both.
Nonstreaming responses cannot show an immediate body preview: metadata is added
to final JSON without changing answer/tool content (16 MiB response limit).

Compatibility checked against source, not live UI sessions:

- **pi:** its [OpenAI completions adapter](https://github.com/badlogic/pi-mono/blob/main/packages/ai/src/api/openai-completions.ts)
  consumes `reasoning_content` as `thinking_delta`; Ctrl+T controls collapsed
  thinking. Use `openai-completions` for this daemon.
- **Hermes:** [CLI display](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/cli_stream_mixin.py)
  selects live reasoning when `show_reasoning` and streaming are enabled.
  See also [reasoning tests](https://github.com/NousResearch/hermes-agent/blob/main/tests/agent/test_streamed_reasoning_details.py).
- There is no universally displayed warning field. Clients can group this with
  target reasoning, hide it, persist it or replay it. For strict signed reasoning
  or clean-history requirements, use metadata/off plus a custom UI adapter.
  No extension is installed by this feature.

After preview commits HTTP 200, later errors are SSE error frames followed by
`[DONE]`; clients must handle streamed errors. Verification headers may no longer
be available after early flush, but lease verification still occurs normally.
Preview does not imply that inference succeeded.

## Parallel Tor preparation and failure behavior

Rewriting/transcript reconstruction runs alongside a SOCKS CONNECT to the
configured target host using the selected conversation isolation identity. It
sends no HTTP request, prompt or provider key, and closes after preparation.
Inference opens verified TLS using the same identity. No global NEWNYM or
unauthenticated/direct fallback. Tor requires `IsolateSOCKSAuth`; SOCKS cannot
prove circuit construction/reuse or exit rotation. Preparation also runs on
cached/tool-continuation paths. Payment/key acquisition begins only after both
preparation and transcript reconstruction succeed.

Rewriting limits: 128 KiB input/output text per user turn, 1 MiB HTTP response,
90 seconds per call within the inference request deadline. Structured output
must have exactly the expected string count and successful `stop` finish reason.
Invalid output, truncation, refusals, tool calls, HTTP errors and cancellation
stop before inference; no original-text fallback. Cancellation joins the Tor
preparation task. Unprocessed queued requests disclose nothing to the rewriter.

## Validation and deployment

Tests cover target-side transcript replay, cold/edited/truncated histories,
cache atomicity, tool continuations, OR key reuse, text-only disclosure,
credentials/redirects, cancellation, parallel SOCKS preparation, previews and
config preservation. The opt-in live test uses only a synthetic prompt:

```sh
cd zkapi-clientd
ZKAPI_TEST_REWRITER=1 go test -v ./internal/rewriter -run TestLiveLocalRewriter
```

Live tests use `http://localhost:8012`, model `qwen3.8-flash-next`, with no key.
`TestLiveCanonicalReconstruction` checks sample reconstruction and retention of
selected exact details; it does not prove semantic equivalence or anonymity.
For the privacy/AGENTS.md sample, the updated instruction returned:
“Determine whether any components other than skills, such as AGENTS.md or other
relevant items, are included in the structured prompt and should be disabled for
privacy preservation.” A separate conditional/cache sample retained the no-command,
no-file-change, ask-before-restart and 100-word constraints. No wallet, zkAPI
payment or live target inference was involved.

Both protocol builds use this instruction. Restart to load a rebuilt binary;
existing in-memory rewrites are never silently replaced during a running session.

Upstream production proving keys and reviewed deployed network manifests are
still missing. Rewriting does not bypass those gates or activate a live vault.
