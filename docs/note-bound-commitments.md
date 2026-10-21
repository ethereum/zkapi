# Note-bound commitments

A signed balance commitment binds to the same note used by the Merkle-membership
proof:

```text
L = Poseidon(leaf_domain, note_id, registration(secret), deposit, expiry)
C = balance * G + blinding * H + L * J
```

Both request and withdrawal circuits compute `L` from the exact private values
used by the Merkle-membership proof. They use that same `L` to open the signed
commitment. `J` is independently derived with Keccak try-and-increment from
`zkapi.v2.note-binding.generator.v1`, choosing even y and clearing the cofactor.
No known scalar relation to `G` or `H` is introduced. The full canonical BN254
field representation of `L` is multiplied by J, naturally reducing modulo the
Baby-JubJub subgroup order, in both native code and the circuit.

The server updates an anonymous commitment by subtracting `charge * G` and
adding `blind_delta * H`. The note component survives that update without
revealing the note leaf. A fresh uniformly random blinding masks the leaf in
public commitments. Changing the note while retaining the signature requires
breaking the commitment binding/signature or finding an appropriate hash
collision; balancing the deposit amounts alone cannot do it.

This construction relies on the discrete-log binding assumption for the
independent third generator, alongside the Poseidon, Schnorr and Groth16
assumptions. Groth16/BN254 and Baby-JubJub are not post-quantum.

## The nullifier chain is note-bound too

Circuit `zkapi-v2-concession-v1` also binds each state's nullifier and the
anchors of its successors to the note:

```text
N(τ)    = Poseidon(null_domain, secret, note_id, τ)       // zkapi.v2c.null
succ(N) = Poseidon(anchor_domain, N)                      // zkapi.v2c.anchor
τ_0 = 1,  τ_{i+1} = succ(N(τ_i))
```

Including `note_id` keeps the nullifier chains of two notes disjoint even when
they share a secret. The server signs a successor only at `succ(N)` of the
request it settles, and the request circuit refuses to spend a signed state
whose anchor is not `succ(N(τ_prev))` for an earlier anchor of the same note,
so a successor signed at any other anchor is unspendable. A signed state at
anchor 1 is unprovable, and the request circuit also requires the balance to
be at most the deposit. An escape publishes its state's nullifier and the
successor's, `N(succ(N))`, which only the holder of the secret can compute:
only a request proof at that successor nullifier, which only the owner can
make, defeats the escape. See the
[concession exit design](design/concession-exit.md).

## Compatibility and setup

The circuit identifier is `zkapi-v2-concession-v1`. Proving and verifying key
files carry the header `zkapi-v2-concession-v1/<setup_id>/<kind>\0`; loaders
reject a key of another circuit, of the other kind, or of a setup the build
does not accept, before decoding. Release builds accept only the ceremony
setup `mpc-1` with its pinned verifying-key hashes. Public deployment
manifests must advertise `proof_setup.circuit_id` and the setup ID, and
clients must pin the matching key hashes, the vault address and the runtime
code hashes of the vault, adapter and Poseidon library. The header guards
against accidental mismatches; it does not establish setup provenance or
replace independently pinned key hashes.

The checked-in `protocol/setup/v2-concession-dev` directory contains a
single-party development setup, which release builds refuse; the production
keys come from the multi-party ceremony of `protocol/setup/v2-concession`,
which has not run yet. The matching Solidity verifier and SDK WASM/proving
keys must travel together. Artifact hashes identify setup files but do not
establish that setup secrets were destroyed. See
[the ceremony setup](../protocol/setup/v2-concession/README.md) for the trust
assumptions. The legacy circuit `zkapi-v2-note-bound-v1` keeps its own setup
in [`protocol/setup/v2`](../protocol/setup/v2/README.md).

The vault has an immutable verifier and signing keys. Its circuit, proof
artifacts, denomination, and client pins must match exactly. Wallet state and
recovery journals are bound to that configuration. See
[native ETH billing](native-eth-billing.md) for asset and quote configuration.

## Challenge and settlement requirements

Operate `zkapi-challenged` alongside the server and indexer, with durable
retries and an explicit restricted signer. It defeats an escape with any
verified request proof at the escape's successor nullifier, from the server's
append-only request evidence, and otherwise raises the escape's concession to
what the request at the escaped state owes. Neither needs the live root: a
request proof keeps its historical root. Keep the API server available
through every challenge window. See [service operation](challenge-service.md).

Direct OpenRouter retirement persists disable, grace, usage capture and
revocation stages and does not settle before confirmed deletion while its
settlement deadline has not passed. At that write-once deadline the server
settles the captured usage, or the proof's solvency bound if none was
captured, and keeps deleting the key in the background. Its aggregate usage
API supplies no authoritative final receipt: the configured grace must cover
in-flight calls and accounting delay. OA-org finalized receipts provide a
separate settlement path.
