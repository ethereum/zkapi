#!/usr/bin/env bash
set -euo pipefail

# Check out this repository at the pinned ZKAPI_SOURCE_COMMIT into a fresh
# directory, from which build-native.sh builds the wallet companion
# (zkapi-walletd) and test-companion.sh tests it.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
destination=${1:?Usage: prepare-zkapi.sh EMPTY_DESTINATION}
# shellcheck source=zkapi-clientd/packaging/zkapi-source.env
source "$repo_dir/zkapi-clientd/packaging/zkapi-source.env"

if [[ ! "${ZKAPI_SOURCE_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'ZKAPI_SOURCE_COMMIT must be a full 40-character lowercase commit hash.' >&2
    exit 1
fi
if [[ -e "$destination" ]]; then
    echo 'Destination already exists; use a fresh build directory.' >&2
    exit 1
fi
# The commit hash pins the content, so any repository holding the commit is
# an equally good source. Use this checkout when it has the commit (no
# network, and it works before the commit is pushed); otherwise fetch it from
# the public repository, or from ZKAPI_SOURCE_REPOSITORY when that is set.
if git -C "$repo_dir" cat-file -e "${ZKAPI_SOURCE_COMMIT}^{commit}" 2>/dev/null; then
    source_repository=$repo_dir
else
    source_repository=${ZKAPI_SOURCE_REPOSITORY:-https://github.com/ethereum/zkapi.git}
fi
git -c init.defaultBranch=prepared init --quiet "$destination"
git -C "$destination" fetch --quiet --depth=1 "$source_repository" "$ZKAPI_SOURCE_COMMIT"
git -C "$destination" -c advice.detachedHead=false checkout --quiet --detach "$ZKAPI_SOURCE_COMMIT"
python3 "$script_dir/verify-zkapi-source.py" "$destination" "$ZKAPI_SOURCE_COMMIT"
echo "Prepared the pinned zkAPI companion source $ZKAPI_SOURCE_COMMIT at $destination"
