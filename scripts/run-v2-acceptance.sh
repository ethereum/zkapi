#!/usr/bin/env bash
# The local end-to-end acceptance of circuit zkapi-v2-concession-v1 (vault
# revision 3) and the §10.7 Phase B drill scenarios that run on Anvil
# (docs/v2-acceptance.md): builds the drill binaries and the contracts, then
# runs scripts/v2-acceptance.mjs. Extra arguments go to the harness, for
# example --output-dir DIR.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for executable in node npm cargo forge anvil; do
    if ! command -v "$executable" >/dev/null 2>&1; then
        echo "Required executable is missing: $executable" >&2
        exit 1
    fi
done
node -e 'if (Number(process.versions.node.split(".")[0]) < 24) { console.error("Node 24 or newer is required"); process.exit(1); }'
node --test scripts/v2-acceptance.test.mjs

# Respect explicit toolchain settings. Prefer the installed standalone tools on
# macOS; SDK 15.4 also works with hosts whose newer SDK needs a newer linker.
if [[ "$(uname -s)" == Darwin ]]; then
    if [[ -z "${DEVELOPER_DIR:-}" && -d /Library/Developer/CommandLineTools ]]; then
        export DEVELOPER_DIR=/Library/Developer/CommandLineTools
    fi
    if [[ -z "${SDKROOT:-}" && -d /Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk ]]; then
        export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk
    fi
fi

# The challenge signer sidecar (and the ethers the harness encodes with).
npm ci --prefix docker/aws/signer --ignore-scripts --no-audit --no-fund
# Drill binaries, in their own target directory so that they never replace a
# release build: `zkapi` with the adversary modes (--features
# zkapi-cli/adversary), and every daemon, the companion and the wallet driver
# accepting the single-party dev setup (zkapi-proof/dev-setup) that the drill
# vault is deployed with. Release builds have neither.
cargo build --locked --release --target-dir target/acceptance \
    --features zkapi-cli/adversary,zkapi-proof/dev-setup \
    -p zkapi-cli --bin zkapi \
    -p zkapi-serverd --bin zkapi-challenged --example v2_acceptance_wallet \
    -p zkapi-indexerd --bin zkapi-indexerd \
    -p zkapi-companion --bin zkapi-walletd
# The contracts: the protocol artifacts (ABI, codehash audit) and the demo
# project whose Deploy.s.sol deploys them.
(cd protocol/contracts && forge build)
(cd demo/contracts && forge build)
exec node scripts/v2-acceptance.mjs --bin-dir target/acceptance/release "$@"
