# Development setup for `zkapi-v2-concession-v2` (setup id `dev`)

These keys are for tests, CI, fixtures, the Sepolia drill vault, and a vault
deliberately deployed on a single-party setup with `ALLOW_DEV_SETUP=1`
([Single-party setup](../../../docs/deployment.md#single-party-setup)).
They are single-party Groth16 keys generated with OS randomness, so whoever
ran the generator could have kept the toxic waste and could forge every proof
of a vault that uses them. **Default release builds refuse them**: every key
file starts with the header `zkapi-v2-concession-v2/dev/<kind>\0`, and only
builds of `zkapi-proof` with the `dev-setup` feature accept the `dev`
setup id, which a production build gets only when asked (`ALLOW_DEV_SETUP=1`,
or `--setup dev` for the browser bundle; `cargo run --release -p zkapi-proof
--bin release_policy_check` checks the release side). The production setup is
the multi-party ceremony in [`../v2-concession`](../v2-concession/README.md)
(setup id `mpc-1`).

## Contents

| File | What it is |
| --- | --- |
| `request.pk`, `request.vk` | Request circuit keys (12 public inputs, 13 IC points) |
| `withdrawal.pk`, `withdrawal.vk` | Withdrawal circuit keys (17 public inputs, 18 IC points): bound to the stored note by its registration commitment and packed amount and expiry, no Merkle path |
| `insertion1.pk`, `insertion1.vk` | 1-note insertion (activation) circuit keys (5 public inputs, 6 IC points) |
| `insertion4.pk`, `insertion4.vk` | 4-note insertion circuit keys (11 public inputs, 12 IC points) |
| `insertion16.pk`, `insertion16.vk` | 16-note insertion circuit keys (35 public inputs, 36 IC points) |
| `manifest.json` | `setup_id`, `reduction: "circom"`, SHA-256 of the ten key files, `vk_keccak256` per kind, `r1cs_sha256` (this build's `.r1cs` exports), circuit shapes, the verifying keys and the Poseidon parameters. `ptau_sha256`, `transcript_sha256` and `zkey_sha256` are `null`: there was no ceremony. |
| `Groth16ProofAdapter.sol` | The generated Solidity verifier of all five circuits, with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` and `INSERTION{1,4,16}_VK_HASH` |
| `Bn254Poseidon.sol` | The generated Poseidon library (with the path and subtree helpers the vault's activation and retirement use) |

The VK hashes are keccak256 of each `.vk` file without its header. They are
also the adapter constants, so a deployment's adapter identifies its setup.
Every circuit has a QAP domain of 2^15 points (request 23,990, withdrawal
21,029, insertion1 16,439, insertion4 18,941 and insertion16 31,847
constraints).

Only the operator's activation worker proves the insertion statements; the
clients and the browser bundle need the request and withdrawal keys alone.

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
of the previous circuit revision (`zkapi-v2-concession-v1`, request and
withdrawal only). It was imported with `import_zkey --setup-id rehearsal`,
passed every import gate including the binding check, and passed
`tests/proofs.rs` with `ZKAPI_SETUP_DIR` pointing at it. snarkjs `groth16
verify` accepted the shipping prover's proofs under those keys. The import
of all five circuits of this revision is exercised by the toy ceremony of
`tests/zkey_import.rs`; no snarkjs dry run of this revision has been
recorded yet.

## Regenerating

Regenerate only when the circuits change. The new keys replace every pin:
the fixtures (`examples/solidity_fixture.rs`,
`examples/vault_challenge_fixture.rs`), the contracts' adapter and its tests,
the SDK proving keys and hashes, the activation worker's insertion keys, and
the deployment profiles of the drill vault. The setup example refuses to
overwrite an existing directory.
