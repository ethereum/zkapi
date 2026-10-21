# Groth16 Proofs

[groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) defines request and
withdrawal circuits. [compact.rs](../../rust/crates/zkapi-proof/src/compact.rs)
provides their native proving and verification interface, canonical proof
serialization, Baby-JubJub operations, key headers and the setup policy. Every
prover uses `Groth16<Bn254, CircomReduction>`
([reduction.rs](../../rust/crates/zkapi-proof/src/reduction.rs)), the reduction
of the snarkjs ceremony pipeline; verification is standard Groth16.

The request circuit has 12 public field elements and 31,670 constraints. It
proves membership, secret knowledge, a genesis state (`τ = 1`, `B = D`) or a
signed state whose anchor is the successor of an earlier nullifier of the same
note, `D ≥ B ≥ solvency_bound`, expiry, rerandomization, and a
request-context-bound nullifier authorization. The withdrawal circuit has 16
public field elements and 36,452 constraints. It proves the note-bound state,
`final_balance + conceded = B ≤ D`, the kind (0 escape, 1 mutual close, 2
ownership proof), the successor nullifier of an escape, a 160-bit destination
(zero for kind 2), a 64-bit `valid_until`, and the clearance signature of a
mutual close.

Both circuits use `E(B,r,L) = B*G + r*H + L*J`. Reusing a signed state with a
different membership leaf fails the signature/balance relation. The exact
public input order is in [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs).

Keys use circuit ID `zkapi-v2-concession-v1` with a header naming the setup
and the key kind. Release builds accept only the ceremony setup `mpc-1` with
its pinned verifying-key hashes; the committed development setup
([v2-concession-dev](../../setup/v2-concession-dev/README.md)) loads only in
builds with the `dev-setup` feature. The matching generated Solidity verifier
and Poseidon implementation are committed, and the browser wallet consumes the
same proving-key bytes. See the [ceremony setup](../../setup/v2-concession/README.md)
for the trust assumptions. Proving keys, signed states, and the verifier must
use this exact circuit and setup.
