# Rust Libraries and Services

The protocol workspace contains five crates:

- [zkapi-types](../../rust/crates/zkapi-types): canonical BN254 field encoding,
  v2 public statements (`RequestPublicInputsV2`, `WithdrawalPublicInputsV2C`),
  HTTP messages, and Schnorr signatures.
- [zkapi-core](../../rust/crates/zkapi-core): BN254 Poseidon, registration,
  note, nullifier, successor-anchor and state helpers, and Merkle trees.
- [zkapi-proof](../../rust/crates/zkapi-proof): Groth16 circuits, the
  `CircomReduction` prover, commitments, signing, key headers and setup policy,
  R1CS export and ceremony import, proving, and verification.
- [zkapi-client](../../rust/crates/zkapi-client): native wallet state,
  prepared-request journal, response validation, the exit rules and exit lock,
  withdrawal proofs, and recovery. Its shared test vectors
  (`tests/vectors/exit-rules.json`) are reproduced by the browser SDK and
  `zkapi-clientd`.
- [zkapi-browser](../../rust/crates/zkapi-browser): wallet core for the browser,
  with storage and transport supplied by its caller.

The [root workspace](../../../crates) owns the runtime server and challenge
service, contract event indexer, operator CLI, and the desktop wallet
companion `zkapi-walletd`. It imports the protocol libraries directly. The
browser [SDK](../../../sdk) supplies the web-facing transport, storage
integration, and proof assets.
