#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v node >/dev/null 2>&1 || { echo 'Install Node.js 24 or newer, then rerun.' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo 'Install npm with Node.js, then rerun.' >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo 'Install Git, then rerun.' >&2; exit 1; }
node -e 'if (+process.versions.node.split(".")[0] < 24) { console.error("Node.js 24 or newer is required"); process.exit(1); }'
test -f assignment.json || { echo 'Use the participant package supplied for your turn.' >&2; exit 1; }
npm ci --ignore-scripts --no-audit --no-fund
exec node ceremony.mjs contribute --package . --out submission "$@"
