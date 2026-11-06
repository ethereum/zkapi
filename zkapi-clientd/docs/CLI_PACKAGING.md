# Installation, updates and development

## One-command installation

Install or update the `0.1.6` prerelease:

```sh
curl -fsSL https://github.com/ethereum/zkapi/releases/download/clientd-v0.1.6/install.sh | bash
```

Then configure and serve:

```sh
zkapi-clientd config
zkapi-clientd serve
```

The command downloads a prebuilt native bundle and checks its SHA-256 before
activation. No compiler, Git or Python is needed. It assumes the installation's
`bin` directory is already on PATH. The default prefix is `~/.local`; use
`--prefix` for another writable absolute prefix. Configuration is separate from
installation unless `--setup` is supplied. A new profile defaults to Ethereum
Mainnet and direct HTTPS; `config --network sepolia` explicitly selects test ETH.

For updates, stop `serve`, rerun the same install command, then restart `serve`.
The previous bundle is retained, and configuration, signing keys and recovery
state remain in their private directory. The installer does not start services,
modify shell startup files or terminate running processes.

This exact-tag command works for prereleases. GitHub's repository-wide
`latest/download` URL excludes prereleases and may select unrelated operator
releases, so it is not used. The generated installer is pinned to its release.

Runtime requirements: macOS 13+ or Linux with glibc 2.39+, on amd64 or arm64;
Bash, curl, tar and SHA-256 tooling (`sha256sum` or `shasum`). Linux also needs
OpenSSL 3, libgcc and CA certificates.

## Platform packages and background services

Each client release includes generated platform package metadata pinned to its
native bundles. Each bundle contains the client, wallet companion, and
deployment-pinned proof assets, with SHA-256 checks for every supported archive.
The checked-in manifests are a snapshot for source-checkout installs; public
package repositories are updated independently by the publication workflow.

| Platform | Package | Background service |
| --- | --- | --- |
| Nix / NixOS | [Flake and modules](../packaging/nix/README.md) | NixOS or Home Manager systemd user service |
| Arch Linux / AUR | [PKGBUILD and .SRCINFO](../packaging/arch/README.md) | `systemctl --user enable --now zkapi-clientd` |
| Homebrew | [Formula and tap setup](../packaging/homebrew/README.md) | `brew services start zkapi-clientd` |

Run `zkapi-clientd config` as the user who will run the service before starting
it. For Nix, follow the module's explicit configuration-directory instructions.
Services run `zkapi-clientd serve`, keep wallet state outside the package, and
can be stopped with the corresponding service manager. Stop a foreground daemon
before starting its service so they do not compete for the same wallet or port.
Package installation does not fund or initialize a wallet. An unconfigured
service either remains stopped (Nix modules) or exits with configuration guidance.

The [publication workflow](../../.github/workflows/zkapi-clientd-publish.yml)
updates AUR, a configured Homebrew tap, and the `clientd-packages` Nix branch
when a client release is published. Initial credentials and the tap repository
must be configured as described under [Publishing packages](#publishing-packages).
The standalone Nix flake is also published as a release asset and can be used
without a package-registry submission.

Publishing makes an upgrade available; it does not change installations or
restart users' wallets. Stop the daemon, upgrade with the package manager,
then start it again. On NixOS, update the flake input and rebuild the system.

## Wallet storage and updates

`--config-dir` or `ZKAPI_CLIENTD_CONFIG_DIR` explicitly selects the wallet's
private directory. Use the same directory when updating the client or resuming
configuration so signing keys, notes, signed transactions and recovery journals
remain together. The client uses the directory in place without copying,
deleting or re-keying wallet state.

Stop the running daemon before updating or changing configuration, and never
run two clients against one wallet. Malformed profiles, orphaned recovery files
and unsupported profiles require explicit attention; the client never silently
converts them. Preserve recovery data when resolving configuration errors.

## Native bundle

The managed layout is:

```text
PREFIX/bin/zkapi-clientd -> PREFIX/lib/zkapi-clientd/current/bin/zkapi-clientd
PREFIX/bin/zkapi-walletd -> PREFIX/lib/zkapi-clientd/current/bin/zkapi-walletd
PREFIX/lib/zkapi-clientd/current -> releases/RELEASE_DIRECTORY
PREFIX/lib/zkapi-clientd/releases/RELEASE_DIRECTORY/
  bin/zkapi-clientd
  bin/zkapi-walletd
  share/zkapi-clientd/proof-setup/
  share/zkapi-clientd/build-info.json
  share/zkapi-clientd/third-party/
```

The default prefix is `~/.local`. Keep the two binaries and `share` directory
together. The installer checks both binaries and switches `current` atomically;
previous bundles remain available. It does not terminate a running daemon.
The helper is private implementation machinery; use the frontend's `config`
and `serve` commands.

## Maintainer builds and releases

Source builds are optional developer tooling; the end-user command above uses
prebuilt binaries. For local development, `./scripts/install-source.sh` builds
and installs this checkout. It requires Git, Go 1.25+, Rust 1.93+, Python 3,
C/C++ tools, CMake, pkg-config and OpenSSL 3 development headers/libraries.
On macOS install Xcode command-line tools and the corresponding Homebrew tools.

```sh
./scripts/prepare-zkapi.sh /tmp/clientd-wallet-source
./scripts/test-companion.sh /tmp/clientd-wallet-source
./scripts/build-native.sh 0.1.6 /tmp/clientd-artifacts /tmp/clientd-wallet-source
```

`prepare-zkapi.sh` checks out this repository at the commit pinned as
`ZKAPI_SOURCE_COMMIT` in `packaging/zkapi-source.env`, from this checkout when
it holds that commit and otherwise from `https://github.com/ethereum/zkapi`
(`ZKAPI_SOURCE_REPOSITORY` overrides it). `verify-zkapi-source.py` requires
exactly that commit with a clean tree, before and after the build.
`test-companion.sh` runs `cargo test -p zkapi-companion -p zkapi-auth` in the
prepared root workspace and `cargo test -p zkapi-client` in `protocol/rust`,
because the root workspace excludes that directory. When `forge` and `anvil`
are on `PATH` it also requires the companion's Anvil test
(`ZKAPI_REQUIRE_ANVIL=1`), which verifies the companion's escape, close and
ownership proofs in the generated proof adapter; without Foundry that test
reports a skip. `build-native.sh` builds
`cargo build --release --locked -p zkapi-companion --bin zkapi-walletd` and
bundles `protocol/setup/v2-concession`; a release build loads only the pinned
ceremony keys, so it stops while that directory holds none.

Run on the native target. Supported release targets are macOS 13+ and Linux
with glibc 2.39+, on amd64 or arm64. Linux runtime dependencies are OpenSSL 3,
libgcc and CA certificates. Local source builds use the host platform's ABI.

The client release namespace is `clientd-vMAJOR.MINOR.PATCH`, separate from
operator/SDK releases. The client release workflow assembles checksum-pinned
installers and native archives, Homebrew/AUR/Nix metadata, and Linux packages,
then creates a draft release for publication. Publishing that draft triggers
the separate package-publication workflow. Publish a client prerelease only after the
native, installer and package validation jobs succeed.

This release line serves the concession-exit vault. Its warnings send owners
of an earlier vault's note to that vault's point release, `zkapi-clientd
0.1.7` from the `release/v2-note-bound` line (deposits closed, mutual close
and escape kept). Release assembly (`scripts/assemble-release.py`) refuses
any other version until that release is published and its checksum record,
`zkapi-clientd/packaging/releases/clientd-0.1.7.json`, is checked in here;
`--fixture` skips the check for test fixtures only.

To refresh the source-checkout snapshot after a release, add its tag and four native archive hashes to
`zkapi-clientd/packaging/releases/clientd-VERSION.json`, then refresh the
installable manifests from the templates and pinned hashes:

```sh
python3 zkapi-clientd/scripts/sync-packages.py 0.1.6
python3 zkapi-clientd/scripts/sync-packages.py 0.1.6 --check
```

The publication helper's verified `release.json` already contains this record
and can be copied to that path. Refreshing the source snapshot is optional for
live AUR, Homebrew, and Nix distribution-branch updates.

Run these commands from the repository root. The package check workflow reads
the version from the checked-in PKGBUILD. Release assembly independently
hashes the native archives; the checked-in Nix package never overrides the new
release's generated package.

`install.sh --version MAJOR.MINOR.PATCH` selects a published native bundle from
`ethereum/zkapi`. Its release-generated form is pinned to its own version.
It supports install/update with the same prefix and optional `--setup`.
`--setup` runs configuration after activation; no configuration is performed
by default. Update the pinned README URL when publishing another client release.

The wallet companion (`zkapi-walletd`) is this repository's
`crates/zkapi-companion`, built with the protocol crates of the same commit, so
the circuit, the operator's server and the companion never come from two
sources. Releases build it from the pinned `ZKAPI_SOURCE_COMMIT` in a separate
build directory; move the pin to a commit holding every companion, protocol and
`Cargo.lock` change a release must ship. A release must pin a commit that is
pushed to the public repository: the release workflow's shallow checkout
fetches the pinned commit from there, and rebuilds and reviews of a release
must be able to fetch exactly it. A local, unpushed pin serves development and
CI from a checkout that holds it, never a release. Proving assets remain
deployment-pinned; never regenerate them for installation.

## Publishing packages

The tag workflow builds and validates all four native bundles and the platform
packages before creating a draft. Publish the draft in GitHub Releases to
promote those exact artifacts. `zkapi-clientd-publish.yml` listens for the
`release: published` event, including numeric client tags marked prerelease.
Other release namespaces are ignored. It downloads the exact tag's native
archives, packaging tarball, standalone Nix flake, and checksums; verifies their
hashes, payloads, versions, and package metadata; then publishes each platform
independently. It neither rebuilds a published binary nor edits a release asset.

The workflow and scripts must first be merged into the default branch. Add the
following GitHub Actions configuration in `ethereum/zkapi`:

| Name | Kind | Purpose |
| --- | --- | --- |
| `CLIENTD_AUR_SSH_KEY` | Secret | Unencrypted dedicated Ed25519 private key registered with the AUR maintainer account |
| `CLIENTD_HOMEBREW_TAP` | Variable | Initialized public repository such as `ethereum/homebrew-zkapi` |
| `CLIENTD_HOMEBREW_TOKEN` | Secret | Fine-grained token with Contents read/write on that tap repository only |

The Nix publisher uses the workflow's repository-scoped `GITHUB_TOKEN` with
Contents write permission to maintain `clientd-packages`. Allow that branch to
receive automation commits; rules requiring pull requests or signed commits on
it need an appropriate exception. No default-branch commits are required.
The AUR host key is pinned in `packaging/arch/aur_known_hosts`; verify a host-key
rotation with Arch Linux before updating that file.

For initial publication or a retry after configuring credentials:

```sh
gh workflow run zkapi-clientd-publish.yml --repo ethereum/zkapi \
  -f release_tag=clientd-v0.1.6
```

Successful publishers are safe to retry. Each refuses to replace a newer
package with an older release or overwrite different content at the same
version. To repair packaging for an existing version, first review and publish
an explicit packaging revision; do not use this release promoter to replace it.
Different releases are serialized. Missing AUR or Homebrew configuration makes
that platform fail visibly while the independent platforms can still publish.

The same operations are available locally:

```sh
python3 zkapi-clientd/scripts/publish-packages.py prepare clientd-v0.1.6 /tmp/clientd-release
git -c init.defaultBranch=master clone \
  ssh://aur@aur.archlinux.org/zkapi-clientd-bin.git /tmp/clientd-aur
python3 zkapi-clientd/scripts/publish-packages.py publish aur /tmp/clientd-release /tmp/clientd-aur
```

`publish homebrew` expects a checkout of the tap's default branch; `publish nix`
expects a checkout of `clientd-packages` (an initially empty orphan branch).
`publish ... --dry-run` stages the concrete files for inspection without
committing or pushing. Use a clean, disposable checkout for this operation.

### Arch Linux / AUR

Register the dedicated public SSH key in the AUR account settings. Browser
sign-in alone does not authorize Git pushes. Test it with
`ssh -i /path/to/key -o IdentitiesOnly=yes aur@aur.archlinux.org list-repos`.
Then store the private key without printing it:

```sh
gh secret set CLIENTD_AUR_SSH_KEY --repo ethereum/zkapi < /path/to/key
```

The first push of `PKGBUILD`, `.SRCINFO`, and the packaging license to
`ssh://aur@aur.archlinux.org/zkapi-clientd-bin.git` on `master` creates the AUR
entry. The account must own the package or be a co-maintainer if it exists.
Subsequent release pushes update its version and hashes. The `-bin` suffix
identifies installation from upstream native binaries. Users can then install
with an AUR helper such as `yay -S zkapi-clientd-bin` and use the included
systemd user unit. AUR contains build recipes; users' helpers build the Arch
package locally. See the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines).

### Homebrew

Create an initialized public tap repository in the chosen owner namespace:

```sh
gh repo create OWNER/homebrew-zkapi --public --add-readme
gh variable set CLIENTD_HOMEBREW_TAP --repo ethereum/zkapi --body OWNER/homebrew-zkapi
# Read the tap-scoped token from a private file or the interactive prompt.
gh secret set CLIENTD_HOMEBREW_TOKEN --repo ethereum/zkapi
```

The organization may require an owner to create the repository or approve the
token. Run the publication workflow once, then users can install and start it:

```sh
brew install OWNER/zkapi/zkapi-clientd
zkapi-clientd config
brew services start OWNER/zkapi/zkapi-clientd
```

`brew update` fetches new formula versions; `brew upgrade zkapi-clientd` installs
them. The formula uses the native bundles built in the release pipeline, so a
separate Homebrew bottle build is unnecessary. This is a third-party tap; a
`homebrew/core` listing is a separate reviewed submission, and this binary
formula needs a source-build implementation for core's acceptance rules.
See [tap publication](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)
and [acceptable formulae](https://docs.brew.sh/Acceptable-Formulae).

### Nix and NixOS

No account or registry submission is required for the public flake. After the
first publication run, install from the maintained distribution branch:

```sh
nix profile install github:ethereum/zkapi/clientd-packages#zkapi-clientd
```

For NixOS or Home Manager, set
`inputs.zkapi-clientd.url = "github:ethereum/zkapi/clientd-packages";` and import
the appropriate service module as described in [the Nix guide](../packaging/nix/README.md).
Run `nix flake update zkapi-clientd`, then `nixos-rebuild switch --flake .` or
`home-manager switch --flake .` to adopt a new release. For a profile install,
use the entry's name from `nix profile list` with `nix profile upgrade NAME`.
An exact release asset remains available for reproducible version pinning:

```sh
nix profile install 'https://github.com/ethereum/zkapi/releases/download/clientd-v0.1.6/zkapi-clientd-nix.tar.gz#zkapi-clientd'
```

Adding the package and service to Nixpkgs/NixOS's built-in catalog requires a
separate upstream pull request, a maintainer entry, package and module review,
and NixOS service tests. The flake supports installation and release updates
without waiting for that review. See [contributing to Nixpkgs](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md)
and [Nix profile upgrades](https://nix.dev/manual/nix/stable/command-ref/new-cli/nix3-profile-upgrade).

## Checks

```sh
go test -race ./...
go vet ./...
python3 scripts/test-install.py
python3 scripts/test-prepare-zkapi.py
python3 scripts/test-packages.py
```

The Go tests check deployment-manifest integrity, exact approved digest
matching, and persistence of wallet state. Fixture tests do not read an installed
profile or contact deployment endpoints.

The model-budget fixture is generated by executing the OA web client's real
pricing modules against synthetic public policy. When changing either client's
model policy, check it against a reviewed OA Chat checkout (no network or
wallet access):

```sh
node scripts/check-web-model-budgets.mjs /path/to/oa-chat
# After reviewing an intentional web policy change:
node scripts/check-web-model-budgets.mjs /path/to/oa-chat --write
```

The fixture stores the two source hashes and exercises live assignments,
unknown tiers, variants, fallback names and both reasoning settings. Go tests
compare the CLI's resulting helper allowance with those web-produced results.
Companion recovery tests use local mock servers and real signed wallet updates;
they never need production keys, funds or an installed wallet.

Native packaging and service-manager checks have extra platform dependencies;
see the client workflows. Fixture tests never need live funds.

Run all three platform checks in disposable Docker containers on an SSH host
(from the repository root):

```sh
python3 zkapi-clientd/scripts/test-platforms-ssh.py user@docker-host.example
```

Replace `user@docker-host.example` with your Docker host; the host argument is
required. The runner copies the source into a new remote temporary directory,
downloads the four pinned archives, verifies them against the checksum metadata, assembles
the current package definitions, and runs the Nix, Arch, and Linux Homebrew
checks. `--platform nix`, `--platform arch`, or `--platform homebrew` selects one.
Use `--artifacts /path/to/release` to reuse downloaded archives. Local logs are
written to `zkapi-clientd/build/platform-tests/`; `--logs` selects another directory.

The Docker host needs Python 3, curl, Bash, and permission to run Docker. Service
tests use disposable privileged containers with private cgroup namespaces so
systemd can run inside the container. They do not mount a host wallet or the
Docker socket. Each runner removes its own containers; the SSH runner removes
its temporary source and archives unless `--keep` is supplied.

These checks install real release binaries and test service configuration,
missing-profile behavior, and stopping. They do not configure or fund a wallet,
perform paid inference, or claim macOS `launchd` coverage. Homebrew's macOS
service checks remain part of the native release workflow.
