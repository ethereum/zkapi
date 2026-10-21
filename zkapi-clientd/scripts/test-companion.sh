#!/usr/bin/env bash
set -euo pipefail

# Test the wallet companion in a tree from prepare-zkapi.sh: zkapi-companion
# and zkapi-auth in the root workspace, and zkapi-client in the protocol
# workspace, which the root workspace excludes.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
zkapi_dir=${1:?Usage: test-companion.sh PREPARED_ZKAPI_DIRECTORY}
zkapi_dir=$(cd -- "$zkapi_dir" && pwd)
# shellcheck source=zkapi-clientd/packaging/zkapi-source.env
source "$repo_dir/zkapi-clientd/packaging/zkapi-source.env"
python3 "$script_dir/verify-zkapi-source.py" "$zkapi_dir" "$ZKAPI_SOURCE_COMMIT"

# With Foundry installed, the companion's proofs must also verify in the
# generated adapter on Anvil (crates/zkapi-companion/tests/anvil_adapter.rs);
# without it that test reports a skip.
if command -v forge >/dev/null 2>&1 && command -v anvil >/dev/null 2>&1; then
    export ZKAPI_REQUIRE_ANVIL=1
    echo 'Foundry found: the Anvil adapter test is required'
else
    unset ZKAPI_REQUIRE_ANVIL
    echo 'Foundry (forge, anvil) not on PATH: the Anvil adapter test is skipped'
fi
echo 'Testing zkapi-companion and zkapi-auth in the root workspace'
(cd "$zkapi_dir" && cargo test --release --locked -p zkapi-companion -p zkapi-auth)
echo 'Testing zkapi-client in the protocol workspace'
(cd "$zkapi_dir/protocol/rust" && cargo test --release --locked -p zkapi-client)
echo 'Tested zkapi-companion, zkapi-auth and zkapi-client'
