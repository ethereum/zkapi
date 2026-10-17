# Groth16 Proofs

[groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) defines the request
and withdrawal circuits, [insertion.rs](../../rust/crates/zkapi-proof/src/insertion.rs)
the insertion circuit for batches of 1, 4 and 16 notes.
[compact.rs](../../rust/crates/zkapi-proof/src/compact.rs) provides their
native proving and verification interface (`RequestProver`,
`InsertionProver` and the verifiers), canonical proof
serialization, Baby-JubJub operations, key headers and the setup policy. Every
prover uses `Groth16<Bn254, CircomReduction>`
([reduction.rs](../../rust/crates/zkapi-proof/src/reduction.rs)), the reduction
of the snarkjs ceremony pipeline; verification is standard Groth16.

The request circuit has 12 public field elements and 23,990 constraints. It
proves membership at the current root of the request tree, secret knowledge, a
genesis state (`τ = 1`, `B = D`) or a signed state whose anchor is the
successor of an earlier nullifier of the same note, `D ≥ B ≥ solvency_bound`,
expiry, rerandomization, and a request-context-bound nullifier authorization.
The withdrawal circuit has 17 public field elements and 21,029 constraints. It
proves no membership: its registration commitment (input 3) opens to the
state's secret and its packed amount and expiry (input 16) fix the leaf, both
of which the vault compares with the note it stores. It proves the note-bound
state, `final_balance + conceded = B ≤ D`, the kind (0 escape, 1 mutual close,
2 ownership proof), the successor nullifier of an escape, a 160-bit
destination (zero for kind 2), a 64-bit `valid_until`, and the clearance
signature of a mutual close.

The insertion circuit for `K` notes (`K` = 1, 4, 16; 16,439, 18,941 and
31,847 constraints, `3 + 2K` public field elements) proves that the empty
aligned subtree at the first note ID hashes to the old root with a private
path, and the subtree of the `K` leaves built from the public commitments and
packed amounts and expiries to the new root with the same path. Every circuit
fits a 2^15 domain.

The request and withdrawal circuits use `E(B,r,L) = B*G + r*H + L*J`. Reusing a signed state with a
different membership leaf fails the signature/balance relation. The exact
public input order is in [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs).

Keys use circuit ID `zkapi-v2-concession-v2` with a header naming the setup
and the key kind (`request`, `withdrawal`, `insertion1`, `insertion4`,
`insertion16`). Release builds accept only the ceremony setup `mpc-1` with
its five pinned verifying-key hashes; the committed development setup
([v2-concession-dev](../../setup/v2-concession-dev/README.md)) loads only in
builds with the `dev-setup` feature. The matching generated Solidity verifier
(one adapter for all five keys) and Poseidon implementation are committed, the
browser wallet consumes the same request and withdrawal proving-key bytes, and
the operator's activation worker the insertion proving keys. See the [ceremony setup](../../setup/v2-concession/README.md)
for the trust assumptions. Proving keys, signed states, and the verifier must
use this exact circuit and setup.
