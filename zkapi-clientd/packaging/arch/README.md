# Arch Linux / AUR

This directory is ready to copy to an AUR repository for `zkapi-clientd-bin`.
It installs the checksum-pinned `0.1.6` release for x86_64 or aarch64, the native
wallet companion and proving assets, and a systemd user service.
The release publication workflow maintains the AUR repository after its SSH
key has been registered. See [initial publication and credentials](../../docs/CLI_PACKAGING.md#publishing-packages).

Once the first push has created the public entry, install with an AUR helper:

```sh
yay -S zkapi-clientd-bin
zkapi-clientd config
systemctl --user enable --now zkapi-clientd.service
```

For updates, stop the service, upgrade with your AUR helper, and start it again.
The package preserves the wallet and configuration.

To build and install this checkout on Arch Linux as a regular user:

```sh
cd zkapi-clientd/packaging/arch
makepkg -si
zkapi-clientd config
systemctl --user enable --now zkapi-clientd.service
```

Configure the wallet before starting its service. The service runs as your
user, uses the same default profile as the CLI, and keeps newly created files
private with `UMask=0077`. It does not perform interactive setup or funding.
Never run another client against the same wallet while the service is active.

```sh
systemctl --user status zkapi-clientd.service
journalctl --user -u zkapi-clientd.service
systemctl --user stop zkapi-clientd.service
```

To keep it running after logout, optionally enable lingering for your user:

```sh
loginctl enable-linger "$USER"
```

For a separate existing profile, use `systemctl --user edit zkapi-clientd` and
set an absolute directory before starting the service:

```ini
[Service]
Environment=ZKAPI_CLIENTD_CONFIG_DIR=/absolute/path/to/private-profile
```

The concrete `PKGBUILD` and `.SRCINFO` are generated from the `.in` templates
and the pinned release checksums. From the repository root, refresh both with:

```sh
python3 zkapi-clientd/scripts/sync-packages.py 0.1.6
```

## Docker validation

To use Docker on an explicitly selected SSH host from your local checkout, run this from the
repository root:

```sh
python3 zkapi-clientd/scripts/test-platforms-ssh.py user@docker-host.example --platform arch
```

On a Linux Docker host, run:

```sh
./zkapi-clientd/packaging/arch/test-docker.sh
# Optionally reuse already downloaded release archives:
./zkapi-clientd/packaging/arch/test-docker.sh /path/to/release-archives
```

The runner builds the package as a regular user, installs it with `pacman`,
checks both binaries and every proof asset, and exercises the installed service
with a real systemd user manager. It checks enable/start/stop and the expected
configuration guidance for a fresh profile, without creating a wallet. It uses
a disposable privileged Arch container to run systemd and removes that
container afterward. Only this package directory and optional release cache
are mounted, both read-only. Set `ARCH_IMAGE` to select another Arch image.

The startup check covers an unconfigured installation. Serving funded inference
requires the user's configured wallet; this test neither funds a wallet nor
submits live transactions.
