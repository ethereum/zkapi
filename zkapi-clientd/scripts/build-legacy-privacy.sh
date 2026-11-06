#!/usr/bin/env bash
# Build the old protocol engine with CURRENT shared privacy/UI implementation.
# No live profile, wallet, service, or network endpoint is used by these tests.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
base=be04d85dac5b27c4f54fa296f0735f02319c98a5
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The shared packages live in the pinned OA module (go.mod) under pkg/; the old
# tree keeps them under internal/, so their files and imports are mapped back.
oa_module=github.com/OpenAnonymity/oa-chat/oa-clientd
legacy_internal=github.com/ethereum/zkapi/zkapi-clientd/internal
(cd "$here" && go mod download "$oa_module")
oa_dir=$(cd "$here" && go list -m -f '{{.Dir}}' "$oa_module")
test -d "$oa_dir/pkg"

git -C "$root" archive "$base" zkapi-clientd | tar -x -C "$work"
(cd "$work" && git apply --unsafe-paths "$here/packaging/legacy/privacy.patch")
copied=()
while IFS= read -r path; do
  case "$path" in
    internal/activity/* | internal/cover/* | internal/delegatemcp/* | internal/relay/* | internal/rewriter/* | internal/server/*)
      source="$oa_dir/pkg/${path#internal/}" ;;
    *) source="$here/$path" ;;
  esac
  mkdir -p "$work/zkapi-clientd/$(dirname "$path")"
  sed "s#\"$oa_module/pkg/#\"$legacy_internal/#g" "$source" > "$work/zkapi-clientd/$path"
  copied+=("$work/zkapi-clientd/$path")
done < "$here/packaging/legacy/shared-files.txt"
# Import order follows the path, so restore gofmt's order after the mapping.
gofmt -w "${copied[@]}"
cd "$work/zkapi-clientd"
# Shared opt-in live tests stay OFF for release builds.
unset ZKAPI_TEST_REWRITER ZKAPI_EVAL_REWRITER ZKAPI_EVAL_DEFAULT ZKAPI_VAULT_PROTOCOL
# No dev keys or companion/protocol changes: only Go privacy/client wiring.
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-X main.version=legacy-be04d85-privacy-v1' -o "$work/legacy" ./cmd/zkapi-clientd
mkdir -p "$here/bin"
install -m 755 "$work/legacy" "$here/bin/zkapi-clientd-legacy-privacy"
sha256sum "$work/legacy" | cut -d ' ' -f 1 > "$work/hash"
# Compile this pin into the dispatcher, then rebuild that binary separately.
install -m 644 "$work/hash" "$here/cmd/zkapi-clientd/legacy_client.sha256"
echo 'Built bin/zkapi-clientd-legacy-privacy; rebuild the primary client to embed its pin.'
