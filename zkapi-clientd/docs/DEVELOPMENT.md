# Building the privacy-enabled client branch

## Scope and status

This branch adds daemon-native conversation-aware Tor isolation, canonical
prompt reconstruction, target-side transcript replay, bounded cover traffic,
model defaults, funding/withdrawal UI and saved vault-stack selection.

It is **development source, not a production wallet release**:

- Sepolia pins the deployed revision-4 vault and its development setup.
  Mainnet remains `not_deployed`; production ceremony keys are missing.
- Legacy uses historical protocol source plus current shared privacy code.
  Isolated Sepolia tests cover both historical deployments; this does not
  establish current Mainnet admission or production deployment readiness.
- Wallets, journals, installed proving assets and local binaries are not tracked.
  A clone contains source, not an existing wallet or complete working bundle.
- Protocol selection does not migrate notes, translate signed transactions or
  authorize spending. Starting `serve` retains its documented autofunding behavior.

## Prerequisites

Use the Go version required by `go.mod` (Go 1.25 or newer), Git, and standard
POSIX build utilities (`bash`, `tar`, `install`, `sha256sum`). Rust companion
builds also need the repository's pinned Rust toolchain, pkg-config and OpenSSL
development libraries. Dependency downloads may require network access.

Use a full clone: the legacy build reconstructs checkpoint
`be04d85dac5b27c4f54fa296f0735f02319c98a5`, an ancestor of this branch. A shallow
clone must fetch that history before building. No separate worktree is required.

## Build the protocol engines

From the repository root, with the daemon stopped:

```sh
bash zkapi-clientd/scripts/build-legacy-privacy.sh
bash zkapi-clientd/scripts/build-legacy-companion.sh
bash zkapi-clientd/scripts/build-concession-v1.sh

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

For a runnable local Sepolia bundle, use [Sepolia acceptance](#sepolia-acceptance)
below, including the local aliases and PATH. The generic companion build
without development keys can be compiled from the repository root:

```sh
cargo build --release --locked -p zkapi-companion --bin zkapi-walletd
install -m 755 target/release/zkapi-walletd zkapi-clientd/bin/zkapi-walletd-concession
```

Do not enable `dev-setup` for a production companion. Compiling it does not supply
reviewed deployed manifests or production proving keys.

The legacy selector accepts its original companion hash and the reviewed
rebuild pin in `cmd/zkapi-clientd/legacy_companion_rebuilt.sha256`.
`build-legacy-companion.sh` fetches the exact original companion/protocol commits,
applies the original bridge patches, verifies both complete source diffs, and
installs `bin/zkapi-walletd-legacy` with `share/legacy` proving assets. Review
generated binary-pin changes before rebuilding the primary dispatcher.
Revision 3 similarly has an isolated engine, companion and proving setup built
by `build-concession-v1.sh`. Neither build converts existing wallets or changes
the original accepted legacy companion pin.

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
Foundry/Anvil and live checks establish different properties. An isolated
Sepolia exercise on 2026-10-17 verified revision-4 deposit, activation, real
inference and settlement, plus revision-3 and legacy deposit, inference,
settlement and wallet-paid withdrawal. No production wallet was used. No
transaction is sent by the build scripts or read-only opt-in live tests.

## Repository hygiene

Keep local configs, wallet recovery records, signed journals, prompt/response
captures, binaries and installed proving assets out of commits. Root-level ad hoc
shell/Python chat wrappers and scratch research/output files are no longer part
of this branch's source tree. Supported CLI code lives in `cmd/zkapi-clientd`;
necessary build, test and packaging scripts remain under `scripts`/`packaging`.

## Sepolia acceptance

Build a separate Sepolia companion; keep Mainnet and historical executables intact:

```sh
cargo build --release --locked -p zkapi-companion --bin zkapi-walletd --features zkapi-proof/dev-setup
install -m 755 target/release/zkapi-walletd zkapi-clientd/bin/zkapi-walletd-sepolia-r4
cd zkapi-clientd
# In a fresh local bundle; these links stay inside this workspace.
ln -s zkapi-clientd-concession-tor bin/zkapi-clientd
ln -s zkapi-walletd-sepolia-r4 bin/zkapi-walletd
mkdir -p share/zkapi-clientd
ln -s ../../../protocol/setup/v2-concession-dev share/zkapi-clientd/proof-setup
export PATH="$PWD/bin:$PATH"
zkapi-clientd version
ZKAPI_TEST_SEPOLIA=1 go test -v ./internal/zkapi -run '^TestLiveSepoliaDeployment$'
ZKAPI_TEST_SEPOLIA=1 ZKAPI_TEST_COMPANION="$PWD/bin/zkapi-walletd-sepolia-r4" \
  go test -v ./internal/zkapi -run '^TestLiveSepoliaCompanion$'
```

Default companion discovery uses `zkapi-walletd` from PATH. With no
`--proof-setup-dir`, it resolves `../share/zkapi-clientd/proof-setup` relative
to the companion's real executable and checks all four proving-key hashes.
The local links above therefore support an ordinary Sepolia profile without
binary/setup overrides. The primary executable's absolute path alone does
not add its directory to PATH. Keep this PATH change in the current shell;
do not replace a globally installed Mainnet daemon or its profile. If a link
already exists, inspect its target rather than replacing another protocol's
bundle. Historical profiles keep their explicitly pinned companion/setup paths.

These checks read the live contract and server pins, verify installed proving
keys, and optionally start the real Go/Rust bridge with an empty temporary
wallet. They do not submit a proof, inference request or transaction. For a
funded exercise, use an isolated Sepolia profile and retain all recovery files.
The historical revision-3 build and selection are documented in
[protocol selection](VAULT_PROTOCOL.md).
