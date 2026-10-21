#!/usr/bin/env bash
# Build this checkout and the pinned wallet companion, then activate one bundle.
set -euo pipefail
umask 022

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
client_dir=$(cd -- "$script_dir/.." && pwd)
version=0.0.0
install_args=()
setup=0
network=''
fail() { printf 'zkapi-clientd source installer: %s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || fail '--version requires MAJOR.MINOR.PATCH.'
            version=$2; shift 2 ;;
        --prefix)
            [[ $# -ge 2 ]] || fail '--prefix requires an absolute directory.'
            [[ "$2" = /* && "$2" != / && "$2" != *:* && "$2" != *$'\n'* && "$2" != *$'\r'* ]] ||
                fail '--prefix must be an absolute directory without colons or newlines, other than /.'
            install_args+=("$1" "$2"); shift 2 ;;
        --network)
            [[ $# -ge 2 ]] || fail '--network requires mainnet or sepolia.'
            [[ "$2" = mainnet || "$2" = sepolia ]] || fail '--network requires mainnet or sepolia.'
            network=$2
            install_args+=("$1" "$2"); shift 2 ;;
        --setup)
            setup=1; install_args+=("$1"); shift ;;
        --help|-h)
            cat <<'HELP'
Build and install zkapi-clientd from this checkout; rerun to update it.

Usage: ./scripts/install-source.sh [--prefix ABSOLUTE_DIR]
          [--version MAJOR.MINOR.PATCH] [--setup [--network mainnet|sepolia]]

The source build uses version 0.0.0 by default and records the exact checkout,
source state, the pinned wallet companion commit and build toolchains.
It prepares and builds the pinned Rust companion (crates/zkapi-companion at
ZKAPI_SOURCE_COMMIT) in a temporary directory; the build does not modify
operator services or wallet data.
Installation defaults to ~/.local. Stop an existing daemon before updating,
then restart it after installation. Prior installation bundles are retained.

Prerequisites: Git, Go 1.25+, Rust/Cargo 1.93+, Python 3, a C/C++ compiler,
CMake, pkg-config, OpenSSL 3 headers/libraries, tar, and SHA-256 tooling.
On macOS install Xcode command-line tools and `brew install go rust cmake
pkg-config openssl@3`. On Linux install the corresponding development packages.
Builds download pinned source and locked dependencies. No published release is
required. No wallet is initialized or funded unless --setup is supplied.
HELP
            exit 0 ;;
        *) fail "Unknown argument: $1 (see --help)." ;;
    esac
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail '--version requires MAJOR.MINOR.PATCH.'
[[ -z "$network" || "$setup" = 1 ]] || fail '--network requires --setup.'
[[ "$(id -u)" != 0 ]] || fail 'Run as your normal user, without sudo.'
for executable in git go cargo rustc python3 cmake pkg-config tar; do
    command -v "$executable" >/dev/null 2>&1 || fail "Required command is missing: $executable."
done
if [[ "$(uname -s)" = Darwin && -z "${OPENSSL_DIR:-}" ]] && command -v brew >/dev/null 2>&1; then
    openssl_prefix=$(brew --prefix openssl@3 2>/dev/null || true)
    if [[ -d "$openssl_prefix" ]]; then
        export OPENSSL_DIR="$openssl_prefix"
    fi
fi

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/zkapi-clientd-source.XXXXXX")
cleanup() { rm -rf "$build_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

printf 'Building zkapi-clientd and its pinned wallet companion. This can take several minutes.\n'
bash "$script_dir/prepare-zkapi.sh" "$build_dir/wallet-source"
bash "$script_dir/build-native.sh" "$version" "$build_dir/artifacts" "$build_dir/wallet-source" --archive-only
archive="$build_dir/artifacts/zkapi-clientd_${version}_$(go env GOOS)_$(go env GOARCH).tar.gz"
digest=$(python3 - "$archive" <<'PY'
import hashlib
from pathlib import Path
import sys
with Path(sys.argv[1]).open('rb') as source:
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(1 << 20), b''):
        digest.update(block)
print(digest.hexdigest())
PY
)
# Bash 3.2 on macOS treats an empty array as unset with nounset. Construct
# the argument list before expanding optional arguments so no-options works.
set -- --version "$version" --archive "$archive" --sha256 "$digest"
if [[ ${#install_args[@]} -gt 0 ]]; then
    set -- "$@" "${install_args[@]}"
fi
bash "$client_dir/install.sh" "$@"
