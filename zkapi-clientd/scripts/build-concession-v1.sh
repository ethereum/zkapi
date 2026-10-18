#!/usr/bin/env bash
# Preserve access to the deployed Sepolia revision-3 vault. Reconstruct its
# reviewed protocol, retain current shared privacy code, and build an isolated
# client/companion pair. No live wallet or transaction is touched.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
base=0fb263b0da04986cfe5c63b12340c1581018ae9b
live_sepolia=${ZKAPI_TEST_SEPOLIA:-0}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git -C "$root" archive "$base" | tar -x -C "$work"
git -C "$work" apply "$here/packaging/concession-v1/compatibility.patch"
while IFS= read -r path; do
  mkdir -p "$work/zkapi-clientd/$(dirname "$path")"
  cp "$here/$path" "$work/zkapi-clientd/$path"
done < "$here/packaging/legacy/shared-files.txt"
# The dispatcher passes the saved name unchanged. Within this isolated
# executable, concession-v1 means this revision-3 engine, never revision 4.
python3 - "$work" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]) / 'zkapi-clientd/cmd/zkapi-clientd/vault_protocol.go'
s = p.read_text()
old = 'case "", "concession":'
assert old in s
p.write_text(s.replace(old, 'case "", "concession", "concession-v1":', 1))
PY
unset ZKAPI_TEST_REWRITER ZKAPI_EVAL_REWRITER ZKAPI_EVAL_DEFAULT ZKAPI_VAULT_PROTOCOL ZKAPI_TEST_SEPOLIA
(cd "$work/zkapi-clientd" && go test -race ./... && go vet ./...)
# Testing above keeps historical test fixtures intact. Shipping pins below
# select the actual historical deployment instead of its old placeholder.
cp "$here/packaging/concession-v1/sepolia.json" "$work/zkapi-clientd/internal/zkapi/deployments/sepolia.json"
if [[ "$live_sepolia" == 1 ]]; then
  cp "$here/internal/zkapi/live_sepolia_test.go" "$work/zkapi-clientd/internal/zkapi/live_sepolia_test.go"
  (cd "$work/zkapi-clientd" && ZKAPI_TEST_SEPOLIA=1 go test -v ./internal/zkapi -run '^TestLiveSepoliaDeployment$' -count=1)
fi
mkdir -p "$here/bin" "$here/share/concession-v1"
(cd "$work/zkapi-clientd" && go build -trimpath -ldflags='-X main.version=concession-v1-0fb263b-sepolia' -o "$work/client" ./cmd/zkapi-clientd)
# Sepolia uses the reviewed single-party dev setup. These artifacts are named
# separately and must never replace a Mainnet installation or revision-4 keys.
(cd "$work" && CARGO_TARGET_DIR="$root/target/concession-v1" cargo build --release --locked -p zkapi-companion --bin zkapi-walletd --features zkapi-proof/dev-setup)
install -m 755 "$work/client" "$here/bin/zkapi-clientd-concession-v1"
install -m 755 "$root/target/concession-v1/release/zkapi-walletd" "$here/bin/zkapi-walletd-concession-v1"
cp "$work/protocol/setup/v2-concession-dev/"{manifest.json,request.pk,request.vk,withdrawal.pk,withdrawal.vk} "$here/share/concession-v1/"
sha256sum "$here/bin/zkapi-clientd-concession-v1" | cut -d ' ' -f 1 > "$here/cmd/zkapi-clientd/concession_v1_client.sha256"
sha256sum "$here/bin/zkapi-walletd-concession-v1" | cut -d ' ' -f 1 > "$here/cmd/zkapi-clientd/concession_v1_companion.sha256"
echo 'Built revision-3 Sepolia recovery pair; rebuild the primary client to embed its pins.'
