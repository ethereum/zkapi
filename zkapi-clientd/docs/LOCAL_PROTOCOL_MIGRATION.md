# Local Tor client: concession-protocol migration

This branch merges upstream `df88556` into the custom Tor client, including
canonical prompt reconstruction, a separate target-side transcript and bounded
cover traffic. Both selectable protocol engines share the privacy implementation.
Legacy recovery executables and wallet profiles are preserved. This is a
development build, not a deployed production release. See
[building this branch](DEVELOPMENT.md) and [protocol selection](VAULT_PROTOCOL.md).

## Protocol and deployment gate

The client now uses vault revision 4 and circuit `zkapi-v2-concession-v2`
(leaf-bound exits: an exit binds the note's stored leaf and needs no Merkle
path), including upstream concession exits, independent exit-RPC support, and
payout-funded withdrawals where a deployed manifest enables them. It refuses a
revision-3 profile (circuit `zkapi-v2-concession-v1`) and a vault whose
`LEAF_BOUND_EXIT_VERSION()` is not 1; deposits below the vault's minimum
(`min_deposit_units`) are refused, and each deposit is signed with the gas
limit of the deposit gas policy (`fresh_slot_gas` from the profile). The Rust
companion is `crates/zkapi-companion`, not the removed legacy companion patch.

**Sepolia ships the leaf-bound staging deployment**
`zkapi-native-eth-sepolia-leaf-v4-20261020`: vault
`0x67eb750d9c0d63a99684ac3f3e65f0c610276993`, protocol server and indexer
`https://zkapi-sepolia.openanonymity.ai/v0.4`, bundler at its `/bundler`,
displayed as **zkAPI v0.2** (vault revision 4, leaf-bound exits). It uses the
development proving setup `protocol/setup/v2-concession-dev`, so it runs with
a companion built with `dev-setup` (see the
[Sepolia staging bundle](DEVELOPMENT.md#sepolia-staging-bundle)).
**Mainnet remains `not_deployed`**: there is no configured vault, indexer or
protocol-server address, and the production setup directory
`protocol/setup/v2-concession` has no ceremony keys. The CLI checks its
embedded manifest before attaching to a daemon or starting funding. It must
not fall back to an old vault or test fixtures, nor use development proving
keys for Mainnet.

### Older deployments in the same profile

Wallet state is per deployment (`zkapi/<network>/<deployment_id>/` and
`funding/<network>/<deployment_id>/` in the configuration directory), so this
build opens new sibling directories for the leaf-v4 deployment and never
migrates, reads or changes an older deployment's. Already funded notes and
saved in-flight withdrawals of an older deployment stay where their build
left them; `serve`, `config --setup`, `config --menu`, `withdraw` and guided
funding print a warning naming such a deployment, its directories and its way
out, without asking anything or stopping. Existing leaf-v4 wallets keep
loading: the embedded Sepolia manifest is byte-for-byte what they saved, and a
test pins its SHA-256.

Compatibility exception: this build cannot load the exact manifests of the
earlier Sepolia concession deployments
`zkapi-native-eth-sepolia-concession-v1-r3` (revision 3, `/v0.2`) and
`zkapi-native-eth-sepolia-concession-v2-r4-20261017` (revision 4 without
leaf-bound exits, `/v0.3`). Their files are preserved and warned about; recover
them with the local CLI bundle built from git branch `origin/v0.2`, run with the
same `--config-dir` (adding `--vault-protocol concession-v1` for revision 3). A
profile whose saved vault protocol is `concession-v1` is refused with that
guidance and left unchanged. Note-bound wallets keep the legacy dispatcher.
See [deployment origins](CLI_ZKAPI.md#deployment-origins).

Tor SOCKS authentication isolation, conversation key rotation, diagnostics,
saved default models, compact funding display, deposit-all-minus-fees and
private-plus-public guided withdrawal are retained. Actual circuit isolation
still requires Tor's `IsolateSOCKSAuth` configuration.

## Outputs

- `zkapi-clientd/bin/zkapi-clientd-concession-tor`: new Go daemon.
- `zkapi-clientd/bin/zkapi-clientd-legacy-privacy`: old protocol engine with
  current shared privacy features, selected automatically for legacy profiles.
- `zkapi-clientd/bin/zkapi-walletd-concession`: new Rust companion compiled
  in release mode without `dev-setup` (the production companion; the Sepolia
  staging deployment needs a `dev-setup` build instead).

These binaries alone are **not an installable working wallet bundle**: Mainnet
still lacks pinned production proving assets and a deployed manifest, and the
Sepolia staging deployment needs the `dev-setup` companion and the development
setup directory named explicitly.
Do not point the new daemon at the old companion/proving setup. No home-profile
configuration, wallet record, or running service was changed for this migration.

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

Legacy notes require the legacy release and their original state directories.
This migration does not convert notes or send transactions.

## Validation

Go race tests and vet; Rust companion/auth and protocol-client release tests.
The upstream Anvil adapter test skips on hosts without Foundry; a passing Rust
test command alone is not evidence of on-chain verification. Automated tests
send no transactions and perform no live Tor/provider, deposit or withdrawal
acceptance; the opt-in read-only Sepolia checks (`ZKAPI_TEST_SEPOLIA=1`) are
described in [development builds](DEVELOPMENT.md#sepolia-staging-bundle).
