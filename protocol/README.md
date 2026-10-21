# zkAPI protocol

Anonymous prepaid API usage with native ETH settlement, BN254 Groth16 proofs,
and Baby-JubJub Schnorr signatures. A request consumes one private state and
returns a fresh server-signed state at an anchor derived from the spent
nullifier. The vault settles the remaining balance when the note closes, and
its concession exit lets an owner leave without the operator.

The current circuit binds signed balances to the private membership leaf and
the nullifier chain to the note. Its circuit ID is `zkapi-v2-concession-v1`
(vault revision 3). Read the [ceremony setup and trust assumptions](setup/v2-concession/README.md)
and the [development setup](setup/v2-concession-dev/README.md) before using
its keys.

## Implementation

```text
contracts/               Solidity vault, BN254 Poseidon, and Groth16 verifier
setup/v2-concession/     Ceremony keys (mpc-1), once G-SETUP has run
setup/v2-concession-dev/ Development keys for tests and the drill vault
setup/v2/                Keys of the legacy circuit zkapi-v2-note-bound-v1
rust/crates/
  zkapi-types   Canonical BN254 field encoding and v2 wire statements
  zkapi-core    BN254 Poseidon, note/nullifier helpers, and Merkle trees
  zkapi-proof   Groth16 circuits, proving, verification, and curve operations
  zkapi-browser Storage- and transport-independent WASM wallet core
  zkapi-client  Native wallet, note persistence, and request recovery
```

The runtime server, challenge service, indexer, and operator CLI live in the
[parent workspace](../crates). The browser integration is in the
[parent SDK](../sdk).

See [PROTOCOL.md](PROTOCOL.md) for the protocol model,
[SPEC.md](SPEC.md) for the active implementation interfaces,
[the concession exit design](../docs/design/concession-exit.md) for the exit's
security argument, and [the implementation book](docs/src/intro.md) for a
source map.

## Build and test

From this directory:

```bash
cargo test --release --manifest-path rust/Cargo.toml --workspace --locked
cd contracts
forge test
```

The proof system requires the circuit-specific Groth16 setup. The committed
keys are the single-party development setup; the production keys come from a
multi-party ceremony that has not run yet, and release builds load no other
keys. The proof tests run on the committed development setup, or on the
setup directory named by `ZKAPI_SETUP_DIR`. The setup READMEs describe the
trust assumptions and compatibility requirements.

## License

MIT OR Apache-2.0
