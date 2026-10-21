# Note-bound Groth16 setup (legacy)

Circuit ID: `zkapi-v2-note-bound-v1`.

These keys serve the legacy vaults, whose stack runs from the release line
`release/v2-note-bound`. The code on `main` serves circuit
`zkapi-v2-concession-v1` and refuses these key files: their single-label
header names another circuit. The current setups are
[`../v2-concession`](../v2-concession/README.md) (ceremony) and
[`../v2-concession-dev`](../v2-concession-dev/README.md) (development).

These are single-party Groth16 keys generated with OS randomness by
`cargo run --release -p zkapi-proof --example setup -- NEW_OUTPUT_DIRECTORY`
at the legacy line's revision.
The `v2` directory name denotes the wire schema. Proving/verifying files carry
the `zkapi-v2-note-bound-v1` circuit header.
The matching generated Solidity verifier is committed alongside them.

No multi-party setup ceremony has been conducted. Matching hashes establish
artifact identity, not the absence of retained setup secrets. Independently
review the circuit, third Pedersen generator, setup provenance and trust
assumptions before deployment.
The vault's immutable verifier, client proving keys, and pinned hashes must
match this setup. Use the matching circuit for all signed states and keep wallet
data bound to its configured vault and signing keys.
