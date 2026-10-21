# Building the privacy-enabled client branch

## Scope and status

This branch adds daemon-native conversation-aware Tor isolation, canonical
prompt reconstruction, target-side transcript replay, bounded cover traffic,
model defaults, funding/withdrawal UI and saved vault-stack selection.

It is **development source, not a production wallet release**:

- Shipping concession manifests are `not_deployed`; production ceremony keys
  are missing. Never use development keys or legacy addresses to bypass this.
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

Do not enable `dev-setup` for a production companion. Compiling it does not supply
reviewed deployed manifests or production proving keys.

The local legacy selector separately pins the historical `zkapi-walletd`
companion hash in `cmd/zkapi-clientd/vault_protocol.go`. A new clone does not
include that artifact or its original verifying/proving assets. Recover them
from your reviewed legacy installation; they must match the existing wallet's
protocol. The checkpoint retains historical companion source-preparation scripts,
but obtaining/rebuilding that bundle is not an automated production release
process here. A mismatched or absent companion is an explicit blocker, not a
reason to substitute the concession companion or disable verification.

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
