# Building the privacy-enabled client branch

## Scope and status

This branch adds daemon-native conversation-aware Tor isolation, canonical
prompt reconstruction, target-side transcript replay, bounded cover traffic,
model defaults, funding/withdrawal UI and saved vault-stack selection.

It is **development source, not a production wallet release**:

- The Mainnet concession manifest is `not_deployed`; production ceremony keys
  are missing. Never use development keys or legacy addresses to bypass this.
  Sepolia ships the leaf-bound staging deployment (zkAPI v0.2), which uses the
  development setup; see [Sepolia staging bundle](#sepolia-staging-bundle).
- Legacy uses historical protocol source plus current shared privacy code.
  Live legacy deposit/admission availability has not been established.
- Wallets, journals, installed proving assets and local binaries are not tracked.
  A clone contains source, not an existing wallet or complete working bundle.
- Protocol selection does not migrate notes, translate signed transactions or
  authorize spending. Starting `serve` retains its documented autofunding behavior.

## Prerequisites

Use the Go version required by `go.mod` (currently Go 1.26), Git, and standard
POSIX build utilities (`bash`, `tar`, `install`, `sha256sum`). Rust companion
builds also need the repository's pinned Rust toolchain, pkg-config and OpenSSL
development libraries. Dependency downloads may require network access.

Use a full clone: the legacy build reconstructs checkpoint
`be04d85dac5b27c4f54fa296f0735f02319c98a5`, an ancestor of this branch. A shallow
clone must fetch that history before building. No separate worktree is required.

## Build both Go engines

From the repository root, with the daemon stopped:

```sh
bash zkapi-clientd/scripts/build-legacy-privacy.sh

cd zkapi-clientd
go test -race ./...
go vet ./...
go build -trimpath -ldflags="-X main.version=privacy-$(git rev-parse --short HEAD)-dev" \
  -o bin/zkapi-clientd-concession-tor ./cmd/zkapi-clientd
```

The first script reconstructs the old protocol source in a temporary directory,
applies the adapter patch, and overlays the current shared privacy implementation.
It runs race tests and vet, builds `bin/zkapi-clientd-legacy-privacy`, and updates
`cmd/zkapi-clientd/legacy_client.sha256`. The primary build embeds that pin and
refuses a different legacy engine. Different toolchains may produce a different
hash: review and commit pin changes together with the source/build changes.
Never replace the pin merely to accept an unknown executable.

Outputs are deliberately ignored by Git. Shared feature changes must be tested
and rebuilt in **both** engines; see `packaging/legacy/shared-files.txt` and
[protocol selection](VAULT_PROTOCOL.md). The original historical recovery binary
is not overwritten.

## Companion and proving assets

The concession Rust companion can be compiled from the repository root:

```sh
cargo build --release --locked -p zkapi-companion --bin zkapi-walletd
install -m 755 target/release/zkapi-walletd zkapi-clientd/bin/zkapi-walletd-concession
```

Do not enable `dev-setup` for a production companion (Mainnet, or any
deployment pinned to ceremony keys). Compiling it does not supply reviewed
deployed manifests or production proving keys. The Sepolia staging deployment
is the only exception, with a separately named companion; see
[Sepolia staging bundle](#sepolia-staging-bundle).

The local legacy selector separately pins the historical `zkapi-walletd`
companion hash in `cmd/zkapi-clientd/vault_protocol.go`. A new clone does not
include that artifact or its original verifying/proving assets. Recover them
from your reviewed legacy installation; they must match the existing wallet's
protocol. The checkpoint retains historical companion source-preparation scripts,
but obtaining/rebuilding that bundle is not an automated production release
process here. A mismatched or absent companion is an explicit blocker, not a
reason to substitute the concession companion or disable verification.

## Sepolia staging bundle

Sepolia ships the leaf-bound staging deployment
`zkapi-native-eth-sepolia-leaf-v4-20261020`, shown as **zkAPI v0.2**: vault
`0x67eb750d9c0d63a99684ac3f3e65f0c610276993`, protocol server and indexer
`https://zkapi-sepolia.openanonymity.ai/v0.4`, bundler at its `/bundler`, pinned
RPC `https://ethereum-sepolia-rpc.publicnode.com`. Its proofs use the committed
development setup `protocol/setup/v2-concession-dev`, which only a companion
built with `dev-setup` loads. Use test ETH only, and keep this companion apart
from any production one. From the repository root:

```sh
cargo build --release --locked -p zkapi-companion --bin zkapi-walletd \
  --features zkapi-proof/dev-setup
install -m 755 target/release/zkapi-walletd zkapi-clientd/bin/zkapi-walletd-sepolia-dev
(cd zkapi-clientd && go build -trimpath -o bin/zkapi-clientd-concession-tor ./cmd/zkapi-clientd)

CLIENT="$PWD/zkapi-clientd/bin/zkapi-clientd-concession-tor"
PROFILE=/tmp/zkapi-sepolia-staging    # an isolated test profile
$CLIENT --config-dir "$PROFILE" config --setup --network sepolia \
  --zkapi-binary "$PWD/zkapi-clientd/bin/zkapi-walletd-sepolia-dev" \
  --proof-setup-dir "$PWD/protocol/setup/v2-concession-dev"
$CLIENT --config-dir "$PROFILE" serve
```

- Name the companion and setup with explicit absolute paths: the companion
  checks the setup's four key files against the manifest's SHA-256 pins before
  it opens a wallet, and the default installed setup is not this one.
- Keep a throwaway profile such as the `/tmp` one above (and repeat the same
  `--config-dir` on every command). Never point a staging build at your real
  profile to try it out.
- The deployment asks for the shared Sepolia access password. Setup prompts
  for it with input hidden and saves it owner-only in the profile; for scripted
  runs, set `OA_ZKAPI_TESTNET_PASSWORD_FILE` to an owner-only (`chmod 600`)
  file instead. Never pass it on the command line.
- The pinned public RPC rejects some multi-block `eth_getLogs` queries. If an
  exit, a withdrawal's recovery or a receipt check reports that the RPC is
  unavailable, configure your own RPC with `config --exit-rpc-url URL` (HTTPS,
  or `http://` to this machine). The client uses exactly the endpoint you save
  and never rewrites or substitutes a provider on its own; `--exit-rpc-url
  none` clears it.
- A profile that already holds a wallet of an earlier Sepolia deployment keeps
  it: this build opens new sibling directories for the leaf-v4 deployment and
  warns about the earlier one (see
  [deployment origins](CLI_ZKAPI.md#deployment-origins)).

Read-only acceptance of the live deployment is opt-in and sends no
transaction:

```sh
cd zkapi-clientd
ZKAPI_TEST_SEPOLIA=1 go test -v ./internal/zkapi -run '^TestLiveSepoliaDeployment$'
# Optional: your own RPC for the chain reads, and the dev-setup companion.
ZKAPI_TEST_SEPOLIA=1 ZKAPI_TEST_EXIT_RPC=https://rpc.example \
  ZKAPI_TEST_COMPANION="$PWD/bin/zkapi-walletd-sepolia-dev" \
  ZKAPI_TEST_PASSWORD_FILE=/path/to/owner-only-password \
  go test -v ./internal/zkapi -run '^TestLiveSepolia'
```

The first checks the pinned code hashes, vault and adapter getters, gasless
contracts, the bundler's EntryPoint and the server's `config.json` and
`/v1/attestation` against the manifest; the second starts the companion on an
empty temporary wallet and reads its status only.

The live ticket test **spends Sepolia test funds** (two fixed-price tickets).
It builds only with the `zkapi_live` tag and runs only with an explicit
opt-in. It puts the real `internal/server` API around a real
`Client` in ticket mode against a running companion, given by its loopback
URL. Everything it calls is real: proofs, successor checks, OA key
verification, model policy, provider streams and chain reads. It checks
chain 11155111 and an idle, affordable note before buying, and writes only
statuses, timings, process-local key references, prices and balances:

```sh
cd zkapi-clientd
ZKAPI_LIVE_TICKETS=spend-sepolia-test-funds \
  ZKAPI_LIVE_COMPANION_URL=http://127.0.0.1:19595 \
  ZKAPI_LIVE_PROFILE=/path/to/test-profile \
  ZKAPI_LIVE_OUT=/path/to/evidence.json \
  go test -tags zkapi_live -v -count=1 -timeout 20m ./internal/zkapi \
  -run '^TestLiveSepoliaTicketAPIConcurrency$'
```

The profile's `config.json` supplies the bridge token. The companion must
serve a funded Sepolia note at a protocol server that sells tickets. The test
streams two completions, starting the second one while the first is still
producing output, and checks each charge, the balance delta and that the two
streams overlapped.

## Run and configure

```sh
# From repository root; use an absolute binary path for service definitions.
CLIENT="$PWD/zkapi-clientd/bin/zkapi-clientd-concession-tor"
$CLIENT --help
$CLIENT --config-dir /path/to/existing-profile config
$CLIENT --config-dir /path/to/existing-profile config --help
```

Default Linux profile: `${XDG_CONFIG_HOME:-$HOME/.config}/zkapi-clientd`.
`--config-dir` overrides `ZKAPI_CLIENTD_CONFIG_DIR`, which overrides the legacy
`OA_CHAT_CONFIG_DIR` variable and OS default. Preserve the original profile for
wallet recovery. Never solve a lock conflict by removing wallet or lock files.

Rewriting/cover remain opt-in. Cover defaults to 5 arrivals/sec when configured,
uses explicit permitted HTTPS destinations, and can exceed 1 GiB/hour in response
payload at its cap. Rewriting discloses original user text directly to the editor.
Neither feature establishes anonymity; read [privacy](PRIVACY.md),
[rewriter](REWRITER.md) and [cover traffic](COVER_TRAFFIC.md) limitations.

## Validation

Both Go engines run the shared regression tests: original-history matching,
rewritten transcript replay, OR-key reuse, rewrite-before-payment, streamed
previews, SOCKS downgrade rejection, remote DNS, TLS checks, bounded cover workers
and cancellation. The optional synthetic rewriter test contacts only the local
service at port 8012, not zkAPI or a wallet:

```sh
cd zkapi-clientd
ZKAPI_TEST_REWRITER=1 go test -v ./internal/rewriter -run '^TestLive'
```

Unit/local-fixture tests do not demonstrate Tor circuit construction, anonymity,
live provider acceptance, on-chain proof verification or deployment readiness.
Foundry/Anvil tests and a separately approved live end-to-end exercise are still
needed for those applicable checks. No transaction is sent by the build scripts.

## Repository hygiene

Keep local configs, wallet recovery records, signed journals, prompt/response
captures, binaries and installed proving assets out of commits. Root-level ad hoc
shell/Python chat wrappers and scratch research/output files are no longer part
of this branch's source tree. Supported CLI code lives in `cmd/zkapi-clientd`;
necessary build, test and packaging scripts remain under `scripts`/`packaging`.
