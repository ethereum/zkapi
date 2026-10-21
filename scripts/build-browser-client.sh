#!/usr/bin/env bash
# Build the browser WebAssembly of circuit zkapi-v2-concession-v1 reproducibly.
#
#   scripts/build-browser-client.sh --setup dev|mpc-1
#       Build into sdk/wasm/, copy the setup's keys into sdk/assets/proofs/ and
#       rewrite sdk/assets/manifest.json (scripts/sync-sdk-assets.mjs).
#   scripts/build-browser-client.sh --check [--setup dev|mpc-1]
#       Rebuild into a temporary directory and require every sdk/wasm/ file to
#       match the hashes in sdk/assets/manifest.json (by default for the setup
#       the manifest names). Changes nothing. `npm run verify:wasm` runs it.
#
# --setup selects the bundle's setup: `mpc-1` (the ceremony keys pinned in
# zkapi-proof, the production bundle) or `dev` (the development setup in
# protocol/setup/v2-concession-dev, for CI, tests, the drill vault and any
# vault deployed with Deploy.s.sol's ALLOW_DEV_SETUP=1; it enables
# zkapi-browser's dev-setup feature). The SDK build refuses to pair a bundle
# with a profile of another setup.
#
# Reproducibility: the toolchain is rust-toolchain.toml's (rustc 1.99.0) and
# wasm-bindgen-cli 0.2.117; Cargo.lock is used as is (--locked); the target
# directory is fixed; and every absolute build path (the checkout, CARGO_HOME,
# RUSTUP_HOME and HOME) is remapped, so the bytes do not depend on where or by
# whom they are built.
set -euo pipefail

readonly REQUIRED_RUSTC="1.99.0"
readonly REQUIRED_WASM_BINDGEN="0.2.117"
WASM_FILES=(zkapi_browser.js zkapi_browser_bg.wasm zkapi_browser.d.ts zkapi_browser_bg.wasm.d.ts)

usage() {
  echo "usage: $0 --setup dev|mpc-1 | $0 --check [--setup dev|mpc-1]" >&2
}

setup_id=""
check=0
while (($#)); do
  case "$1" in
    --setup) setup_id="${2:-}"; shift 2 ;;
    --setup=*) setup_id="${1#--setup=}"; shift ;;
    --check) check=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
if ((check)) && [[ -z "$setup_id" ]]; then
  setup_id="$(node -p "require('./sdk/assets/manifest.json').setupId")"
fi
case "$setup_id" in
  dev) features=(--features dev-setup) ;;
  mpc-1) features=() ;;
  *) usage; exit 2 ;;
esac
protocol_rust="$repo_root/protocol/rust"
export CARGO_TARGET_DIR="$protocol_rust/target"
wasm_target="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/zkapi_browser.wasm"

wasm_bindgen_bin="${WASM_BINDGEN_BIN:-$(command -v wasm-bindgen || true)}"
if [[ -z "$wasm_bindgen_bin" ]]; then
  echo "wasm-bindgen is required: cargo install wasm-bindgen-cli --version $REQUIRED_WASM_BINDGEN --locked" >&2
  exit 1
fi
if [[ "$("$wasm_bindgen_bin" --version)" != "wasm-bindgen $REQUIRED_WASM_BINDGEN" ]]; then
  echo "wasm-bindgen-cli $REQUIRED_WASM_BINDGEN is required, found: $("$wasm_bindgen_bin" --version)" >&2
  exit 1
fi
rustc_version="$(rustc -V)"
if [[ "$rustc_version" != "rustc $REQUIRED_RUSTC "* ]]; then
  echo "rustc $REQUIRED_RUSTC is required (rust-toolchain.toml), found: $rustc_version" >&2
  exit 1
fi

# The last matching prefix wins: the checkout is remapped after HOME, so a
# checkout below HOME still becomes /src.
remaps=("$HOME=/build" "${RUSTUP_HOME:-$HOME/.rustup}=/rustup" "${CARGO_HOME:-$HOME/.cargo}=/cargo" "$repo_root=/src")
encoded=""
for remap in "${remaps[@]}"; do
  encoded+="${encoded:+$'\x1f'}--remap-path-prefix=$remap"
done
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="$encoded"

cargo build \
  --locked \
  --manifest-path "$protocol_rust/Cargo.toml" \
  -p zkapi-browser \
  --target wasm32-unknown-unknown \
  --release \
  ${features[@]+"${features[@]}"}

if ((check)); then
  out_dir="$(mktemp -d)"
  trap 'rm -rf "$out_dir"' EXIT
else
  out_dir="$repo_root/sdk/wasm"
  mkdir -p "$out_dir"
fi
"$wasm_bindgen_bin" "$wasm_target" \
  --target web \
  --out-dir "$out_dir" \
  --out-name zkapi_browser \
  --omit-default-module-path

if ((check)); then
  node - "$out_dir" "$setup_id" "${WASM_FILES[@]}" <<'NODE'
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const [outDir, setupId, ...files] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(path.resolve('sdk/assets/manifest.json'), 'utf8'));
if (manifest.setupId !== setupId) {
  console.error(`sdk/assets/manifest.json is for setup ${manifest.setupId}, not ${setupId}.`);
  process.exit(1);
}
let failed = false;
for (const file of files) {
  const actual = createHash('sha256').update(fs.readFileSync(path.join(outDir, file))).digest('hex');
  const expected = manifest.files[`wasm/${file}`];
  const status = actual === expected ? 'ok' : 'MISMATCH';
  if (actual !== expected) failed = true;
  console.log(`${status} wasm/${file} ${actual}${actual === expected ? '' : ` (manifest ${expected})`}`);
}
if (failed) {
  console.error('The rebuilt WebAssembly differs from sdk/assets/manifest.json.');
  process.exit(1);
}
console.log(`The ${setupId} WebAssembly rebuilds byte for byte (sourceRevision ${manifest.sourceRevision}).`);
NODE
else
  node "$repo_root/scripts/sync-sdk-assets.mjs" --setup "$setup_id"
  echo "Browser WebAssembly built for setup $setup_id in sdk/wasm; review and commit sdk/."
fi
