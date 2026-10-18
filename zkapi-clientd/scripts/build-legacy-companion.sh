#!/usr/bin/env bash
# Rebuild the preserved note-bound companion from its exact reviewed source
# commits and patches. The original deployed binary pin remains accepted.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
base=be04d85dac5b27c4f54fa296f0735f02319c98a5
companion=20aa542ae98e767c0507133fd34b12a56f5ccd3d
protocol=8b2d4e3da921f956e1eb6b93afbf722a877c060c
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$root" archive "$base" zkapi-clientd | tar -x -C "$work"
git -c init.defaultBranch=prepared init --quiet "$work/source"
git -C "$work/source" fetch --quiet --depth=1 "$root" "$companion"
git -C "$work/source" -c advice.detachedHead=false checkout --quiet --detach "$companion"
git -C "$work/source" submodule update --init --recursive --depth=1
test "$(git -C "$work/source/protocol" rev-parse HEAD)" = "$protocol"
git -C "$work/source" apply --index "$work/zkapi-clientd/internal/zkapi/companion.patch"
git -C "$work/source/protocol" apply --index "$work/zkapi-clientd/internal/zkapi/protocol-transport.patch"
verify=(python3 "$work/zkapi-clientd/scripts/verify-zkapi-source.py" "$work/source" "$companion" "$protocol")
"${verify[@]}"
(cd "$work/source" && CARGO_TARGET_DIR="$root/target/legacy" cargo build --release --locked --bin zkapi)
"${verify[@]}"
mkdir -p "$here/bin" "$here/share/legacy"
install -m 755 "$root/target/legacy/release/zkapi" "$here/bin/zkapi-walletd-legacy"
cp "$work/source/protocol/setup/v2/"{manifest.json,request.pk,request.vk,withdrawal.pk,withdrawal.vk} "$here/share/legacy/"
sha256sum "$here/bin/zkapi-walletd-legacy" | cut -d ' ' -f 1 > "$here/cmd/zkapi-clientd/legacy_companion_rebuilt.sha256"
echo 'Built the preserved legacy companion; rebuild the primary client to embed its additional pin.'
