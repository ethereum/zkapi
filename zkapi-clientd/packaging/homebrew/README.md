# Homebrew package and service

`zkapi-clientd.rb` installs the published `clientd-v0.1.6` binaries for macOS
(Intel/Apple Silicon) and Linux (x86_64/ARM64), including `zkapi-walletd` and its
proof setup. The release archive checksums come from
`packaging/releases/clientd-0.1.6.json`. `zkapi-clientd.rb.in` is the release template.

The publication workflow updates a configured tap's `Formula/zkapi-clientd.rb`
on every published client release. See [tap creation and release credentials](../../docs/CLI_PACKAGING.md#homebrew).
Once configured, install with `brew install OWNER/zkapi/zkapi-clientd` and start
it with `brew services start OWNER/zkapi/zkapi-clientd` after wallet setup.
Stop the service before `brew update && brew upgrade zkapi-clientd`, then start
it again to run the upgraded executable.

To install from this
checkout without publishing a tap, run from the repository root:

```sh
brew tap-new local/zkapi
cp zkapi-clientd/packaging/homebrew/zkapi-clientd.rb \
  "$(brew --repository local/zkapi)/Formula/zkapi-clientd.rb"
brew install local/zkapi/zkapi-clientd
zkapi-clientd config
brew services start local/zkapi/zkapi-clientd
```

Run these as your normal user so the service uses your private configuration and
wallet. Homebrew generates a launchd agent on macOS and a systemd user unit on
Linux. Linux needs a running systemd user manager; optional lingering keeps that
manager alive after logout. `brew services start` registers the service at login;
`brew services run` starts it for the current session without registering it.

```sh
brew services info local/zkapi/zkapi-clientd
brew services restart local/zkapi/zkapi-clientd
brew services stop local/zkapi/zkapi-clientd
```

The default API address is `http://127.0.0.1:8787/v1`. Both output streams go to
`$(brew --prefix)/var/log/zkapi-clientd.log`. Configuration is required before
the daemon can serve; installing the formula does not initialize or fund a wallet.
If Homebrew 7.0.7 reports an unconfigured Linux service as "not started" while
systemd is waiting to restart it, stop the failed unit with
`systemctl --user stop sh.brew.zkapi-clientd.service` before
`brew services stop local/zkapi/zkapi-clientd`.

## Docker validation

`test-docker.sh RELEASE_DIRECTORY` runs on a Linux Docker host. It builds the
official Homebrew Ubuntu 24.04 image with systemd, installs the formula through a
temporary local tap, runs `brew test` and `brew linkage --test`, then starts,
verifies, and stops the generated systemd user service with `systemctl` and
unregisters it with Homebrew. Only the archive URL is
redirected to the supplied local release archive; the formula's SHA-256 is kept.

The script uses a disposable privileged container with a private cgroup
namespace so systemd can run. It does not mount host files, the Docker socket, or
the host cgroup tree. Its container is removed on exit; the reusable test image
is retained. To run it over SSH, for example:

```sh
ssh docker-host 'bash /path/to/zkapi/zkapi-clientd/packaging/homebrew/test-docker.sh /path/to/release'
```

The empty-profile test confirms that the real installed daemon exits with
configuration guidance and creates no wallet configuration. It does not exercise
funded inference. Linux containers cannot execute macOS binaries or launchd;
those service checks require a separate macOS host.

To update the checked-in formula after publishing a release, run
`python3 zkapi-clientd/scripts/sync-packages.py VERSION` from the repository root.
