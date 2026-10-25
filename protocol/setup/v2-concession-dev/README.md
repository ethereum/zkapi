# Development setup for `zkapi-v2-concession-v2` (setup id `dev`)

These keys are for tests, CI, fixtures, the Sepolia drill vault, and a vault
deliberately deployed on a single-party setup with `ALLOW_DEV_SETUP=1`
([Single-party setup](../../../docs/deployment.md#single-party-setup)).
They are single-party Groth16 keys generated with OS randomness, so whoever
ran the generator could have kept the toxic waste and could forge every proof
of a vault that uses them. **Default release builds refuse them**: every key
file starts with the header `zkapi-v2-concession-v2/dev/<request|withdrawal>\0`,
and only builds of `zkapi-proof` with the `dev-setup` feature accept the `dev`
setup id, which a production build gets only when asked (`ALLOW_DEV_SETUP=1`,
or `--setup dev` for the browser bundle; `cargo run --release -p zkapi-proof
--bin release_policy_check` checks the release side). The production setup is
the multi-party ceremony in [`../v2-concession`](../v2-concession/README.md)
(setup id `mpc-1`).

## Contents

| File | What it is |
| --- | --- |
| `request.pk`, `request.vk` | Request circuit keys (12 public inputs, 13 IC points) |
| `withdrawal.pk`, `withdrawal.vk` | Withdrawal circuit keys (16 public inputs, 17 IC points; input 3 is the note leaf and input 8 its packed fields) |
| `manifest.json` | `setup_id`, `reduction: "circom"`, SHA-256 of the four key files, `vk_keccak256` per kind, `r1cs_sha256` (this build's `.r1cs` exports), circuit shapes, the verifying keys and the Poseidon parameters. `ptau_sha256`, `transcript_sha256` and `zkey_sha256` are `null`: there was no ceremony. |
| `Groth16ProofAdapter.sol` | The generated Solidity verifier, with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH`; deployed once per vault, folded for that vault's address, chain and signing keys |
| `Bn254PoseidonRuntime.sol` | The generated Poseidon contract the vault calls (identical in every setup: it depends on the Poseidon parameters only); `protocol/contracts/src/poseidon/` holds the same file |
| `poseidon-runtime.json` | Its pins: compiler settings, the source's SHA-256, the runtime codehash `Deploy.s.sol` requires, the selectors, the scaled constants and the lane bounds of every round |

The VK hashes are keccak256 of each `.vk` file without its header. They are
also the adapter constants, so a deployment's adapter identifies its setup.

## How it was made

```text
cd protocol/rust
cargo run --release -p zkapi-proof --example setup -- ../setup/v2-concession-dev
```

The generator is `Groth16::<Bn254, CircomReduction>::circuit_specific_setup`
(`zkapi_proof::compact::setup`). `ark-groth16` 0.5's generator calls the
reduction's `h_query_scalars`, so these keys have the snarkjs-style H query
and are used by the same `CircomReduction` prover as the ceremony keys
(checked by `tests/reduction_cross_check.rs` and `tests/proofs.rs`).

No powers of tau matches these keys (the generator discards `τ`), so they
cannot pass the import's binding check. `tests/zkey_import.rs` checks the
rest of the path on them: written as snarkjs `.zkey` files, they read back
exactly, pass the coefficient and shape gates, and the directory writer
reproduces every file here byte for byte. The binding and proving gates
are tested on a toy ceremony with known `τ, α, β, δ`.

A dry run of the full ceremony pipeline used snarkjs 0.7.5 with a throwaway
2^16 powers of tau, one contribution and a beacon, on the exported `.r1cs`
of the previous statement (`zkapi-v2-concession-v1`). It was imported with
`import_zkey --setup-id rehearsal`, passed every import gate including the
binding check, and passed `tests/proofs.rs` with `ZKAPI_SETUP_DIR` pointing
at it; snarkjs `groth16 verify` accepted the shipping prover's proofs under
those keys. **It has not been repeated on this statement's `.r1cs`** (the
SHA-256 in `manifest.json`): rerun it before the ceremony. The pipeline
itself (export, import, reduction) did not change.

These keys were generated once, for the leaf-bound statement of vault
revision 4 (request 23,507 and withdrawal 20,545 constraints; withdrawal
proving key 4.26 MB instead of 5.58 MB).

## Regenerating

Regenerate only when the circuits change. The new keys replace every pin:
the fixtures (`examples/solidity_fixture.rs`,
`examples/vault_challenge_fixture.rs`), the contracts' adapter and its tests,
the SDK proving keys and hashes, and the deployment profiles of the drill
vault. The setup example refuses to overwrite an existing directory.

A change to a generator alone (the adapter template or the Poseidon runtime)
leaves the keys and rewrites the generated files in place:

```text
cd protocol/rust
cargo run --release -p zkapi-proof --example refresh_setup_sources -- ../setup/v2-concession-dev
cp ../setup/v2-concession-dev/Bn254PoseidonRuntime.sol ../contracts/src/poseidon/
```

CI requires `protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol` to be
this directory's copy, `Bn254PoseidonRuntimeTest` requires the compiled
runtime to hash to `poseidon-runtime.json`'s `runtime_codehash` (a pin in
`zkapi-proof`'s `poseidon_runtime.rs`, to update with any change to the
runtime's source or compiler settings), and `protocol/formal`'s
`scripts/generate.py --check` re-renders the runtime's permutation and
requires the file to match it.
