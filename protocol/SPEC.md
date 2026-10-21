# zkAPI v2 implementation specification

This document describes the active implementation. The protocol model is in
[PROTOCOL.md](PROTOCOL.md). Source definitions linked below fix the exact field
order, encodings, and constraints.

## Cryptographic parameters

- Proof system: circuit-specific Groth16 on BN254; every prover uses the
  `CircomReduction` QAP reduction, and verification is standard Groth16.
- Circuit: `zkapi-v2-concession-v1` (vault revision 3); `protocol_version`
  stays 2.
- Circuit field: BN254 scalar field, modulus
  `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
- Hash: domain-separated Poseidon, exponent 5, rate 2, capacity 1,
  8 full rounds and 57 partial rounds. Leaves, nullifiers, commitments and
  signatures are sponge hashes with the domain as the first absorbed element;
  a note-tree node is one permutation of `(domain "zkapi.v2.node", left,
  right)`, its first rate lane (the domain in the capacity lane), so a node
  costs one permutation and no sponge hash can collide with one.
- Balance commitment: `E(B, r, L) = B*G + r*H + L*J` on Baby-JubJub,
  where `L` is the private active-note leaf.
- Server authentication: separate Baby-JubJub Schnorr keys for state and
  clearance signatures, pinned by the deployment.
- Note tree: depth 32, zero leaf 0, note ID as the leaf index; append-only
  except for the retired leaves of closed notes. The vault keeps the tree's
  frontier and appends each deposit's leaf itself, without a Merkle proof;
  only `retireClosedLeaf` takes siblings.

[Native hash functions](rust/crates/zkapi-core/src/v2.rs) and
[circuit constraints](rust/crates/zkapi-proof/src/groth16.rs) use the
`zkapi.v2.*` domain labels, and `zkapi.v2c.null` (arity 4) and
`zkapi.v2c.anchor` (arity 2) for nullifiers and successor anchors. The
independent note-binding generator is derived
under `zkapi.v2.note-binding.generator.v1`. Native helpers, circuits, setup
manifest, and generated Solidity must agree. This is a classical elliptic-curve
proof and signature system.

## Notes and state

A registration commitment is `C = H_reg(secret, 0)`. The leaf is
`L = H_leaf(note_id, C, deposit_amount, expiry)`. The user keeps the secret,
private balance and blinding, current and previous anchors, server signature
and `bound_at_state` locally. Genesis has balance equal to the deposit and
anchor 1. A state's nullifier is `N(τ) = H_null(secret, note_id, τ)`, and the
state signed after a request at `N` has anchor `succ(N) = H_anchor(N)`. A later
spend proves a valid signature on the deployment-bound commitment and anchor,
and that the anchor is `succ(N(τ_prev))` for its previous anchor `τ_prev`; a
signed state at anchor 1 is unprovable.

Binding `L` into both request and withdrawal commitments prevents a signed
state from being moved to a different membership note. Rerandomization changes
only the blinding term. The server subtracts the bounded usage charge and adds
a fresh blinding delta before signing the next state.

## Proof statements

The public statement structs and exact verifier order are defined by
[inputs.rs](rust/crates/zkapi-types/src/inputs.rs) and
[Types.sol](contracts/src/libraries/Types.sol).

The request statement contains these 12 field elements:

1. protocol version
2. chain ID
3. vault address
4. active root
5. state signing key x
6. state signing key y
7. request time
8. solvency bound
9. request nullifier
10. authorization tag
11. anonymous commitment x
12. anonymous commitment y

The request proof establishes note membership, secret knowledge, genesis or
valid signed state on the derived anchor chain, `deposit ≥ balance ≥ solvency
bound`, expiry at least the request time, correct rerandomization, and the
nullifier/authorization tag. The authorization tag binds the nullifier to a
private context derived from the exact client request ID and payload hash.
Runtime validation binds the public deployment, keys, the exact current root,
time, and charge bound to the configured service.

The withdrawal statement contains these 16 field elements:

1. protocol version
2. chain ID
3. vault address
4. active root
5. state signing key x
6. state signing key y
7. clearance signing key x
8. clearance signing key y
9. note ID
10. final balance
11. destination address
12. withdrawal nullifier
13. kind
14. next nullifier
15. conceded amount
16. valid until

The withdrawal proof establishes membership and the note-bound state, and
`final_balance + conceded = balance ≤ deposit`. Its kind is 0 (escape), 1
(mutual close) or 2 (ownership proof). An escape's next nullifier is the
nullifier of the state's successor, `N(succ(N))`; it is 0 for the other kinds,
and only an escape may concede. A mutual close additionally proves the
clearance signature. An ownership proof has a zero destination. The
destination is bound by 160 Boolean constraints and `valid_until` by a 64-bit
range check. The vault checks the deployment, pinned keys, the kind, that the
block time is at most `valid_until`, a destination other than zero and the
vault itself, that it ever held the proof's root (`knownRoots`), note status,
nullifier use, and the balance before settlement. It refuses kind 2
everywhere; the server refuses an ownership proof whose `valid_until` has
passed or is more than an hour ahead.

## Wire format and persistence

[wire.rs](rust/crates/zkapi-types/src/wire.rs) defines the active HTTP schemas.
A clearance request (`ClearanceRequestV2C`) carries `ownership_proof`, a kind-2
withdrawal statement (`WithdrawalPublicInputsV2C`) and proof for the same
nullifier; both refuse unknown fields. Request types keep their v2 names
(`ApiRequestV2`, `RequestPublicInputsV2`, `RequestResponseV2`) and shapes.
`Groth16ProofWire` carries backend `groth16_bn254` and base64-encoded Arkworks
canonical compressed proof bytes. Public inputs are part of the enclosing
request and are verified directly. The Solidity adapter accepts the EVM proof
encoding produced by the proof library.

The internal `Felt252` name is retained for compatibility, but values are BN254
scalar-field elements. JSON fields use canonical `0x` hexadecimal strings and
reject values at or above the field modulus. Preserve the existing v2 JSON
shapes; numeric handling at browser boundaries is defined by the SDK.

The native wallet writes the state's `bound_at_state` and journals prepared
requests before transport, and holds an exit lock while an exit proof may
land. The runtime server persists nullifier reservations, an append-only
`request_evidence` copy of every request proof (written in the reservation's
transaction and kept until the deployment retires), and signed transcripts.
Every lease's charge is fixed by a write-once settlement deadline, at worst at
its solvency bound; its successor is signed afterwards, only while its
nullifier is unspent on chain. The challenger defeats an escape with any
verified request proof at the escape's next nullifier, and raises an escape's
concession with a request proof at its nullifier. The browser wallet receives
storage and transport from its caller.

## Native ETH settlement

[ZkApiVault](contracts/src/ZkApiVault.sol) accounts in whole gwei. A deposit
must attach exactly `amount * 1 gwei`, have positive amount, and stay within
`MAX_NATIVE_UNITS = 2^53 - 1`. The vault buckets expiry to daily boundaries.

No withdrawal changes the tree. Mutual close pays the user's final balance to
the chosen destination and the spent amount to the treasury; a destination
that rejects the payout reverts the close. Both withdrawal paths revert
`InvalidDestination()` for the zero address or the vault itself. Escape
initiation consumes the escaped nullifier and the next nullifier, records the
concession, and starts the configured challenge period. A valid request proof
at the next nullifier defeats the escape (`challengeEscapeWithdrawal`): the
note returns to active, both nullifiers are released, and the escaped one is
set in `challengedNullifiers`, so a later escape from that state reverts
`ChallengedNullifier()` and one from the state below it `SupersededState()`,
while a cleared mutual close remains possible. A valid request proof at the
escaped nullifier only raises the concession (`raiseEscapeConcession`), to at
most its solvency bound. An escape can be finalized after its deadline and
pays the state balance minus the concession. Active notes can be claimed for
the treasury after `effectiveExpiry`, which adds paused time and a
post-defeat grace and is never earlier than `unpauseClaimGrace` after an
unpause. `retireClosedLeaf` removes a closed note's leaf.

The owner can pause deposits and expiry claims until it unpauses, and escapes
and mutual closes for at most `maxPauseDuration` (at least twice the challenge
period); a new pause needs a day since the last unpause. Defeats, raises,
escape finalization, `claimEscapePayout` and `retireClosedLeaf` stay open. Treasury
changes are scheduled, then accepted after `treasuryChangeDelay` of unpaused
time, and failed treasury payments accrue `treasuryArrears` instead of
reverting payouts. An escape payout that its destination rejects, or that
needs more than 100,000 gas to receive, is credited to
`escapePayoutCredits(destination)` with an `EscapePayoutDeferred` event instead
of blocking the escape; anyone can deliver it with
`claimEscapePayout(destination)`. A mutual close to a destination that
rejects ETH reverts instead (it forwards all gas, so a destination that only
needs more gas is paid).

## Source ownership

- [zkapi-core](rust/crates/zkapi-core): native hashing and Merkle helpers.
- [zkapi-proof](rust/crates/zkapi-proof): circuits, proving and verification,
  signing, commitments, and setup serialization.
- [zkapi-browser](rust/crates/zkapi-browser): browser wallet core.
- [zkapi-client](rust/crates/zkapi-client): native wallet and persistence.
- [Root runtime crates](../crates): server, challenge service, indexer, and CLI.
- [SDK](../sdk): browser integration and public proof assets.

## Setup compatibility and verification

The wire version is v2 and the circuit ID is `zkapi-v2-concession-v1`. Key
files carry the header `zkapi-v2-concession-v1/<setup_id>/<kind>\0`. Release
builds accept only the ceremony setup `mpc-1` whose verifying-key hashes equal
the pins in `compact.rs`; the committed development setup `dev`
([v2-concession-dev](setup/v2-concession-dev/README.md)) loads only with the
`dev-setup` feature, which production builds enable only when built for a
single-party vault (`ALLOW_DEV_SETUP=1`). The adapter exposes
`CIRCUIT_ID_HASH`, `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH`. Setup files,
Solidity verification keys, WASM, and
SDK asset hashes must remain paired. See [the ceremony setup](setup/v2-concession/README.md)
for the ceremony, its trust assumptions and how to audit it. The keys of the
legacy circuit `zkapi-v2-note-bound-v1` stay in [setup/v2](setup/v2/README.md)
for the legacy release line.

Run protocol Rust tests with
`cargo test --release --manifest-path rust/Cargo.toml --workspace --locked` and contract
tests with `forge test` from `contracts/`. The parent workspace tests the active
HTTP and settlement integration. Regenerating setup keys is a separate change
that requires regenerating all dependent artifacts and deploying their matching
verifier and vault.
