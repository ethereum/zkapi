# Nix package and services

This directory is an installable flake. Its checked-in `package.nix` pins the
published client release and all four archive SHA-256 digests. The flake lock
also pins Nixpkgs and Home Manager. From a checkout of this repository:

```sh
nix profile install path:./zkapi-clientd/packaging/nix#zkapi-clientd
zkapi-clientd config
```

Release automation renders `package.nix.in` from the exact release archives and
publishes `zkapi-clientd-nix.tar.gz` as a standalone flake. It also includes the
flake in the combined packaging archive.

After extracting `zkapi-clientd-packaging.tar.gz`, install without root privileges:

```sh
nix profile install ./nix#zkapi-clientd
zkapi-clientd config
zkapi-clientd serve
```

You can also run `nix run ./nix -- --version` or build with `nix build ./nix`.
Nix flakes require the `nix-command` and `flakes` experimental features.
The package supports x86_64/aarch64 on Linux and macOS. Linux ELF dependencies
are patched into the Nix store and the matching companion/proof data are bundled.
The companion is selected from the package's own `bin` directory. No user state
is created by a build, installation, or activation.

## NixOS user service

Add the package directory as a flake input. Copy it into your configuration
repository or point to an immutable repository revision:

```nix
inputs.zkapi-clientd.url = "path:./zkapi-clientd-release/nix";
# Or: github:ethereum/zkapi/<revision>?dir=zkapi-clientd/packaging/nix
```

Then include the module and explicitly choose the login users:

```nix
imports = [ inputs.zkapi-clientd.nixosModules.default ];
services.zkapi-clientd = {
  enable = true;
  users = [ "alice" ];
  # Optional; defaults to manual start.
  startAtLogin = true;
};
```

Log in as that user and run `ZKAPI_CLIENTD_CONFIG_DIR="$HOME/.config/zkapi-clientd" zkapi-clientd config`, then
`systemctl --user start zkapi-clientd`. The default private directory is
`~/.config/zkapi-clientd`. A custom runtime directory can be selected with
`services.zkapi-clientd.configDir`; initialize the same directory with
`ZKAPI_CLIENTD_CONFIG_DIR=/absolute/private/directory zkapi-clientd config`.

## Home Manager user service (Linux)

```nix
imports = [ inputs.zkapi-clientd.homeManagerModules.default ];
services.zkapi-clientd = {
  enable = true;
  startAtLogin = true;
};
```

Run `zkapi-clientd config` as the login user, then `systemctl --user start zkapi-clientd`.
The module respects Home Manager's `xdg.configHome`; initialize that same
directory with `ZKAPI_CLIENTD_CONFIG_DIR` if it differs from your shell's default.
The service stays stopped until the initialized `config.json` exists.
Use `journalctl --user -u zkapi-clientd` for metadata-only operational logs.
Neither module creates a root daemon, initializes/funds a wallet, or places
configuration, keys, or private recovery state in the Nix store.
Retain and back up the runtime directory separately; package removal and Nix
garbage collection do not remove it.

## Release validation

`zkapi-clientd/scripts/test-nix.py RELEASE_ARTIFACTS` evaluates all four packages,
validates the standalone flake archive, and builds/executes the current host's
package from its checksummed local release archive. It also evaluates the NixOS
and Home Manager service declarations and private-state assertions. Run this
check on each native release host.

On a Linux Docker host, test the package and actual user service units with:

```sh
bash zkapi-clientd/packaging/nix/test-docker.sh "$PWD" /path/to/assembled-release
```

The runner uses `nixos/nix:2.24.14`, the locked package set, and a disposable
non-root user. It checks both rendered NixOS and Home Manager units with
`systemd-analyze`, starts each with a real systemd user manager, confirms that a
missing profile prevents startup, then confirms that the real packaged daemon
rejects an invalid profile with configuration guidance and can be stopped.
It verifies that the profile remains unchanged and no wallet is created.
Docker runs with `--privileged --cgroupns=private` for the isolated manager's
writable cgroups; no host cgroup tree or Docker socket is mounted. The container
is removed on exit. Run the script on the remote host when using SSH, since its
two path arguments name files on the Docker host.

This is Nix package and systemd user-service validation in Docker, not a full
NixOS boot test. It does not initialize or fund a wallet, run paid inference, or
test macOS service management.
