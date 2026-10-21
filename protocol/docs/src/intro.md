# Introduction

This book maps the active zkAPI v2 implementation to its source. The
[protocol model](../../PROTOCOL.md) describes sequential anonymous spending and
the concession exit; the [implementation specification](../../SPEC.md)
describes exact interfaces; the
[concession exit design](../../../docs/design/concession-exit.md) carries the
security argument.

The current implementation uses BN254 Groth16 proofs, BN254 Poseidon hashing,
and Baby-JubJub Schnorr signatures and note-bound balance commitments, for
circuit `zkapi-v2-concession-v1` and vault revision 3. The Solidity vault
settles native ETH in whole gwei. These are classical elliptic-curve
primitives. Review the [setup trust assumptions](../../setup/v2-concession/README.md)
and the [development setup](../../setup/v2-concession-dev/README.md) before
deploying.

```text
contracts/                Native ETH vault and Groth16 verification
setup/v2-concession/      Ceremony keys (mpc-1), once the ceremony has run
setup/v2-concession-dev/  Development keys for tests and the drill vault
setup/v2/                 Keys of the legacy circuit zkapi-v2-note-bound-v1
rust/                     Proof circuits, native/browser wallets, types, and Merkle helpers
../crates/                Runtime server, challenge service, indexer, companion, operator CLI
../sdk/                   Browser SDK and proof assets
```
