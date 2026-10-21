#!/usr/bin/env bash
# Regenerate the golden vault calldata, getter selectors and layouts, and
# event layouts with Forge (VaultCalldataGolden.t.sol, which compiles the real
# protocol/contracts sources: abi.encodeCall against ZkApiVault, and the
# vault's own Events) and compare them with vault_calldata_golden.json, which
# zkapi-serverd (watcher, native_billing) and zkapi-indexerd (poller) pin
# their encoders, selectors and decoders against. With --update, rewrite the
# JSON instead. Needs forge and node; uses the vendored forge-std of
# protocol/contracts and its compiler settings.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$here/../../../.." && pwd -P)
golden="$here/vault_calldata_golden.json"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src" "$work/test"
cp "$here/VaultCalldataGolden.t.sol" "$work/test/"
# The protocol profile's settings (via_ir and the optimizer), so the vault
# compiles as it does in protocol/contracts.
cat >"$work/foundry.toml" <<EOF
[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["$repo/protocol/contracts/lib"]
allow_paths = ["$repo/protocol/contracts"]
remappings = ["forge-std/=$repo/protocol/contracts/lib/forge-std/src/", "@openzeppelin/=$repo/protocol/contracts/lib/openzeppelin-contracts/", "zkapi/=$repo/protocol/contracts/src/"]
solc = "0.8.28"
optimizer = true
optimizer_runs = 10000
via_ir = true
EOF

if ! (cd "$work" && forge test --match-contract GoldenTest -vv) >"$work/forge.log" 2>&1; then
  cat "$work/forge.log" >&2
  exit 1
fi

node - "$work/forge.log" "$golden" "${1:-}" <<'JS'
const fs = require("node:fs");
const assert = require("node:assert/strict");
const [log, goldenPath, mode] = process.argv.slice(2);
const lines = fs.readFileSync(log, "utf8").split("\n").map((line) => line.trim());
const start = lines.indexOf("Logs:");
if (start < 0) throw new Error("forge printed no logs");
const vectors = { selectors: {}, getter_words: {}, events: {} };
for (const line of lines.slice(start + 1)) {
  const match = /^([A-Za-z0-9_.]+)=(\S+)$/.exec(line);
  if (!match) break;
  const [, key, value] = match;
  const [kind, name, field] = key.split(".");
  if (kind === "calldata") vectors[name] = value;
  else if (kind === "selector") vectors.selectors[name] = value;
  else if (kind === "getter_words") vectors.getter_words[name] = Number(value);
  else if (kind === "event") {
    vectors.events[name] ??= {};
    vectors.events[name][field] = value;
  } else throw new Error(`unexpected forge line: ${line}`);
}
const names = ["defeat", "raise", "escape", "close", "retire"];
for (const name of names) {
  if (!vectors[name]) throw new Error(`forge did not print ${name}`);
}
const golden = JSON.parse(fs.readFileSync(goldenPath, "utf8"));
if (mode === "--update") {
  fs.writeFileSync(goldenPath, `${JSON.stringify({ generator: golden.generator, ...vectors }, null, 2)}\n`);
  console.log(`updated ${goldenPath}`);
  process.exit(0);
}
const { generator: _, ...pinned } = golden;
try {
  assert.deepStrictEqual(pinned, vectors);
} catch (error) {
  console.error("vault_calldata_golden.json differs from the real contracts (forge abi.encodeCall, selectors, getters and events):");
  console.error(error.message);
  process.exit(1);
}
console.log(`golden vectors match the real contracts: ${names.join(", ")}, ${Object.keys(vectors.selectors).length} selectors, ${Object.keys(vectors.getter_words).length} getters, ${Object.keys(vectors.events).length} events`);
JS
