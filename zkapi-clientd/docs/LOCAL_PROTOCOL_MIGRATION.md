# Local Tor client: concession-protocol migration

This branch merges upstream `df88556` into the custom Tor client, including
canonical prompt reconstruction, a separate target-side transcript and bounded
cover traffic. Both selectable protocol engines share the privacy implementation.
Legacy recovery executables and wallet profiles are preserved. This is a
development build, not a deployed production release. See
[building this branch](DEVELOPMENT.md) and [protocol selection](VAULT_PROTOCOL.md).

## Protocol and deployment gate

The client now uses vault revision 4 and circuit `zkapi-v2-concession-v2`,
including upstream concession exits with note-bound exit proofs (no Merkle
path), deposits that operator batches activate later, independent exit-RPC
support, and payout-funded withdrawals where a deployed manifest enables
them. The Rust
companion is `crates/zkapi-companion`, not the removed legacy companion patch.

**Sepolia is deployed:** `zkapi-native-eth-sepolia-concession-v2-r4-20261017`,
vault `0x7ff4ba0662a8218d0954c1a11ae61df6c3548ea4`, API path `/v0.3`.
The packaged profile pins its contract, signing keys, runtime code and proving
assets. It uses `protocol/setup/v2-concession-dev` and requires a Sepolia
companion built with `--features zkapi-proof/dev-setup`.

**Mainnet remains `not_deployed`** for the new protocol. The production ceremony
keys are not present. Neither selection nor Sepolia setup can bypass that gate.

Tor SOCKS authentication isolation, conversation key rotation, diagnostics,
saved default models, compact funding display, deposit-all-minus-fees and
private-plus-public guided withdrawal are retained. Actual circuit isolation
still requires Tor's `IsolateSOCKSAuth` configuration.

## Outputs

- `zkapi-clientd/bin/zkapi-clientd-concession-tor`: new Go daemon.
- `zkapi-clientd/bin/zkapi-clientd-legacy-privacy`: old protocol engine with
  current shared privacy features, selected automatically for legacy profiles.
- `zkapi-clientd/bin/zkapi-walletd-concession`: new Rust companion compiled
  in release mode without `dev-setup`.

A Sepolia bundle includes the Go executable, its matching Rust companion and
all four pinned request/withdrawal key files plus the setup manifest. The
historical `concession-v1` engine and setup are separate from the current ones;
`legacy` keeps the earlier note-bound-v1 engine. No live wallet is converted.

## Withdrawal interface

- Bare `withdraw`: guided private close followed by a separately approved
  public return. Credited-but-unclaimed private payouts block the public sweep
  so recovery fees remain available.
- `withdraw --public`: standalone public return.
- Explicit upstream options (`--to`, `--escape`, `--conceded`, `--fees payout`,
  `--approve`, `--resume`, `--claim`, `--collect`, `--sweep`, `--claim-credit`)
  run through a temporary runtime with **no automatic deposit**. They retain
  upstream quote/approval semantics and do not automatically sweep public ETH.
- Use `withdraw --help` for all explicit options. Configure an independent RPC
  with `config --exit-rpc-url URL`.

Revision-3 notes use `--vault-protocol concession-v1` and the original profile.
Earlier note-bound-v1 notes use `--vault-protocol legacy`. Both require their
matching pinned companions and original state directories.
This migration does not convert notes or send transactions.

## Validation

Go race tests and vet; Rust companion/auth and protocol-client release tests.
The upstream Anvil adapter test skips on hosts without Foundry; a passing Rust
test command alone is not evidence of on-chain verification. Isolated Sepolia
tests on 2026-10-17 exercised revision-4 deposit/activation/inference/settlement
and both historical deployments' deposit/inference/settlement/withdrawal flows.
These direct-HTTPS checks do not test live Tor circuit isolation or Mainnet.
