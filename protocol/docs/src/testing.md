# Testing and Verification

From the repository root:

```bash
cargo test --release --manifest-path protocol/rust/Cargo.toml --workspace --locked
cargo test --release --workspace --locked
```

Protocol tests cover canonical fields and serialization, Merkle trees, native
wallet persistence and the shared exit-rule vectors, browser wallet state,
compact proof encoding, commitment binding, signing-seed policy, setup ids and
key headers, the request/withdrawal circuit constraints (positive, negative and
mutate-each-public-input cases with the `CircomReduction` prover), the R1CS
export round trip and negative assignments, the zkey import gates, and the
cross-check of the reduction against `ark-circom`. `ZKAPI_SETUP_DIR` runs the
proof tests against any setup directory. `cargo run --release -p zkapi-proof
--bin release_policy_check` (from `protocol/rust`) checks that release builds
refuse development keys. Root tests cover the active runtime HTTP paths,
startup key and deployment binding, nullifier persistence and request
evidence, clearance ownership proofs, settlement terminality and the
settle-then-sign gate, defeat and raise decisions and status, the companion's
exit routes, and indexer reorganization and divergence handling.

From `protocol/contracts/`, run `forge test` for deposit, the concession exit
(initiation, defeat, raise, finalization), the bounded pause, the treasury
timelock, invariant fuzzing, the generated mutation test over real proofs, the
gas snapshot (`FORGE_SNAPSHOT_CHECK=true`), the shared withdrawal golden vector
and real Groth16 verifier regressions. `node scripts/check-withdrawal-golden.mjs`
submits the Rust, JS and Go encoders' calldata to an Anvil vault. The
challenge signer's tests run with `npm test` in `docker/aws/signer` (and
`npm run test:anvil` when `anvil` is installed).

The SDK asset check is `npm run verify:assets` from the repository root, and
`npm run verify:wasm` rebuilds the WebAssembly and compares it byte for byte.
Keep the committed WASM and key hashes synchronized with the setup manifest.
Key generation is a separate operation and is not required for ordinary
verification. The [setup trust assumptions](../../setup/v2-concession/README.md)
apply.

`npm run test:e2e:v2` runs the local lifecycle acceptance on Anvil with real
services, proofs and contracts and a mocked provider and oracle. See the
[acceptance process](../../../docs/v2-acceptance.md) for its scenario and
boundary.
