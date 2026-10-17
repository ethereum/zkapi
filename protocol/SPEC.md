# zkAPI v2 implementation specification

This document describes the active implementation. The protocol model is in
[PROTOCOL.md](PROTOCOL.md). Source definitions linked below fix the exact field
order, encodings, and constraints.

## Cryptographic parameters

- Proof system: circuit-specific Groth16 on BN254; every prover uses the
  `CircomReduction` QAP reduction, and verification is standard Groth16.
- Circuit: `zkapi-v2-concession-v2` (vault revision 4); `protocol_version`
  stays 2. Five Groth16 keys: request, withdrawal, and the insertion
  statement for batches of 1, 4 and 16 notes.
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
- Request tree: depth 32, zero leaf 0, note ID as the leaf index; requests
  prove membership under its root. A deposit only records its note; recorded
  notes are appended in deposit order ("activated") as aligned subtrees of 1,
  4 or 16 leaves, and `activationCursor` counts the appended notes. Append-only
  except for the retired leaves of closed notes. The vault keeps only
  `currentRoot`: an activation with an insertion proof (`activateNotes`) does
  no hashing, the no-prover `activateNotesOnChain` and `retireClosedLeaf` take
  the 32 siblings of their slot in the current tree. No withdrawal reads the
  tree.

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
`L = H_leaf(note_id, C, deposit_amount, expiry)`, and a note's metadata is
`M = deposit_amount + expiry * 2^128` (`uint256(depositAmount) |
uint256(expiryTs) << 128` in the vault): the vault stores `C`, the amount and
the expiry of every recorded note in `notes(noteId)`, so `(note_id, C, M)`
names the note and fixes its leaf. The user keeps the secret,
private balance and blinding, current and previous anchors, server signature
and `bound_at_state` locally. Genesis has balance equal to the deposit and
anchor 1. A state's nullifier is `N(τ) = H_null(secret, note_id, τ)`, and the
state signed after a request at `N` has anchor `succ(N) = H_anchor(N)`. A later
spend proves a valid signature on the deployment-bound commitment and anchor,
and that the anchor is `succ(N(τ_prev))` for its previous anchor `τ_prev`; a
signed state at anchor 1 is unprovable.

Binding `L` into both request and withdrawal commitments prevents a signed
state from being moved to a different note. Rerandomization changes
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

The withdrawal statement contains these 17 field elements:

1. protocol version
2. chain ID
3. vault address
4. registration commitment `C`
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
17. note metadata `M`

The withdrawal proof establishes that `C` opens to the state's secret
(`H_reg(secret, 0) = C`), that the state commitment binds the leaf computed
from the note ID, `C` and `M`, the note-bound state, and
`final_balance + conceded = balance ≤ deposit`; it proves no tree
membership. Its kind is 0 (escape), 1 (mutual close) or 2 (ownership proof). An escape's next nullifier is the
nullifier of the state's successor, `N(succ(N))`; it is 0 for the other kinds,
and only an escape may concede. A mutual close additionally proves the
clearance signature. An ownership proof has a zero destination. The
destination is bound by 160 Boolean constraints and `valid_until` by a 64-bit
range check. The vault checks the deployment, pinned keys, the kind, that the
block time is at most `valid_until`, a destination other than zero and the
vault itself, that inputs 4 and 17 equal the stored note's `C` and `M`
(`NoteBindingMismatch()` otherwise, before the proof is verified; an
unrecorded note stores zeros, which no secret opens), note status, nullifier
use, and the balance before settlement. So a note exits as soon as it is
recorded, activated or not, and no exit needs a root, a path or an indexer.
The vault refuses kind 2 everywhere; the server refuses an ownership proof
whose `valid_until` has passed or is more than an hour ahead, or whose `C` and
`M` are not the stored note's (`note_binding_mismatch`), or whose note is not
`Active` (`note_not_active`), and answers a note it cannot read yet as
retriable (`note_not_recorded`).

The insertion statement for a batch of `K` notes (`K` = 1, 4 or 16, one
verifying key each) contains `3 + 2K` field elements:

1. old root
2. new root
3. first note ID
4. `C_0`, `M_0`, ..., `C_{K-1}`, `M_{K-1}`

It proves that the first note ID is a 32-bit index aligned to `K`, that each
`M_j` packs a 128-bit amount and a 64-bit expiry, that the `K` leaves
`H_leaf(first + j, C_j, amount_j, expiry_j)` hash to a subtree root, and that
with one private path the empty subtree of height `log2 K` at that position
hashes to the old root and the new subtree to the new root, so no occupied leaf
is overwritten and every other node, retired leaves included, is kept
([insertion.rs](rust/crates/zkapi-proof/src/insertion.rs)). It binds no
deployment: `activateNotes(firstNoteId, count, expectedRoot, newRoot, proof)`
builds the inputs from its own state (`expectedRoot` must be `currentRoot`,
`firstNoteId` must be `activationCursor`, and every `C_j`, `M_j` is read from
`notes`, whatever the note's status), so a proof can neither skip, reorder nor
alter a recorded note. A note that closed before its activation still has its
original leaf appended.

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
A deposit records the note as the next note ID (`NoteDeposited(noteId,
commitment, amount, expiryTs)`) and does no tree work.

Activation appends the recorded notes `activationCursor ..
activationCursor + count - 1` to the request tree, for `count` 1, 4 or 16 with
`activationCursor` a multiple of `count` and the notes recorded; it is
permissionless. `activateNotes` verifies an insertion proof against the
adapter's `INSERTION{count}_VK_HASH`; `activateNotesOnChain(firstNoteId,
count, siblings)` hashes the leaves, the subtree and both paths itself (about
1.7M gas for one note), so activation never depends on a prover. Both advance
`activationCursor`, set `currentRoot` and emit `NotesActivated(firstNoteId,
count, newRoot, proved)`. An activation prepared against an older cursor or
root reverts `StaleActivation()`, a malformed range `InvalidActivation()`.
Activation takes effect on inclusion; `isActivated(noteId)` is `noteId <
activationCursor`. The operator's activation worker proves batches, picking
the largest aligned size the recorded notes fill and waiting a bounded time
for a fuller batch.

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
unpause. `retireClosedLeaf` removes the leaf of a closed, activated note
(`NoteNotActivated()` before its activation; a note that closed before it is
retired once an activation appends its leaf).

The owner can pause deposits, activations and expiry claims until it
unpauses, and escapes and mutual closes for at most `maxPauseDuration` (at
least twice the challenge period); a new pause needs a day since the last
unpause. Defeats, raises,
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

The wire version is v2 and the circuit ID is `zkapi-v2-concession-v2`. Key
files carry the header `zkapi-v2-concession-v2/<setup_id>/<kind>\0`, for the
kinds `request`, `withdrawal`, `insertion1`, `insertion4` and `insertion16`.
Release builds accept only the ceremony setup `mpc-1` whose verifying-key
hashes equal the pins in `compact.rs`; the committed development setup `dev`
([v2-concession-dev](setup/v2-concession-dev/README.md)) loads only with the
`dev-setup` feature, which production builds enable only when built for a
single-party vault (`ALLOW_DEV_SETUP=1`). The adapter, one contract for all
five verifying keys, exposes `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`,
`WITHDRAWAL_VK_HASH` and `INSERTION{1,4,16}_VK_HASH`; whoever can forge an
insertion proof can set the request tree's root (requests without a deposit),
so the insertion keys need the ceremony like the others. Setup files,
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
