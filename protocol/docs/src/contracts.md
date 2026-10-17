# Solidity Contracts

[ZkApiVault](../../contracts/src/ZkApiVault.sol) (revision 4,
`CONCESSION_ESCAPE_VERSION` 1, `NOTE_BOUND_EXIT_VERSION` 1) accepts native ETH
deposits in whole gwei, records each note (`notes(noteId)`: commitment,
amount, expiry, status), keeps the root of the depth-32 request tree, and pins
the server's state and clearance signing keys, the proof adapter, the
challenge period, the note lifetime and the maximum pause. Amounts are bounded
by `2^53 - 1` gwei.

[NoteLeafLib](../../contracts/src/libraries/NoteLeafLib.sol) and
[MerkleUpdateLib](../../contracts/src/libraries/MerkleUpdateLib.sol) use the
[BN254 Poseidon implementation](../../contracts/src/libraries/Bn254Poseidon.sol)
shared with the circuit parameters (a leaf is the sponge over its five fields;
a node is one permutation with the domain in the capacity lane, `compress`).
The library is generated with the setup (`zkapi-proof`'s `refresh_setup_sources`
example rewrites it) in the optimized form of the Poseidon reference
implementation; CI requires `src/libraries/Bn254Poseidon.sol` to be the
setup's copy. A deposit only records its note. Only activations and
`retireClosedLeaf` change the tree, of which the vault stores only
`currentRoot`:

- `activateNotes(firstNoteId, count, expectedRoot, newRoot, proof)` appends
  the recorded notes `activationCursor .. activationCursor + count - 1`
  (`count` 1, 4 or 16, aligned) with an insertion proof whose inputs the vault
  builds from `currentRoot`, the cursor and the stored notes, whatever their
  status; it does no hashing.
- `activateNotesOnChain(firstNoteId, count, siblings)` is the permissionless
  no-prover fallback: it authenticates the batch's empty subtree at
  `currentRoot` with the slot's siblings (`compressPairPath`), hashes the
  leaves (`NoteLeafLib`) and the subtree (`compressSubtree`), and computes the
  new root (about 1.7M gas for one note).
- `retireClosedLeaf(noteId, siblings)` replaces the leaf of a closed,
  activated note by zero, after checking the siblings at `currentRoot`.

Both activations require `firstNoteId == activationCursor` (else
`StaleActivation()`, as for an `expectedRoot` other than `currentRoot`), an
aligned range of recorded notes (else `InvalidActivation()`), advance
`activationCursor` and emit `NotesActivated(firstNoteId, count, newRoot,
proved)`. An activation or retirement landing first invalidates a prepared
one (`StaleActivation()` or `StaleRoot()`); deposits never do.

[Groth16ProofAdapter](../../contracts/src/adapters/Groth16ProofAdapter.sol)
verifies the request, withdrawal and 1-, 4- and 16-note insertion statements
directly (`assertValidInsertion(count, inputs, proof)`), and exposes
`CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` and
`INSERTION{1,4,16}_VK_HASH`; CI requires it to be the setup's generated copy.
Public deployment fields and pinned signing keys are checked by the vault
before settlement. A withdrawal statement names the note by its registration
commitment (input 3) and packed amount and expiry (input 16), which the vault
compares with `notes(noteId)` before verifying the proof
(`NoteBindingMismatch()`), so a note exits as soon as it is recorded, with no
root and no path.

Mutual close (kind 1) pays the final balance to the destination and the spent
balance to the treasury. An escape (kind 0) consumes the escaped nullifier and
its successor's, records the concession in `pendingConcessions`, and pays the
state balance minus the concession after the challenge period. A request proof
at the successor nullifier defeats it (`challengeEscapeWithdrawal`), returns
the note to active and records the escaped nullifier in `challengedNullifiers`;
a request proof at the escaped nullifier only raises the concession
(`raiseEscapeConcession`), to at most that request's solvency bound. An
escape from a challenged state reverts `ChallengedNullifier()`, and one from
the state below it `SupersededState()`. Every withdrawal reverts after its
`validUntil` (`ProofExpired()`), and kind 2 is refused everywhere
(`WrongWithdrawalKind()`). Active notes can be claimed for the treasury after
`effectiveExpiry`, which adds paused time, a post-defeat grace, and a grace
after each unpause. `retireClosedLeaf` removes a closed note's leaf, once the
note is activated (`NoteNotActivated()` before).
[Types.sol](../../contracts/src/libraries/Types.sol) defines the note state,
the pending records and the proof statements.

The owner can pause deposits, activations, expiry claims and treasury changes until it
unpauses, but escapes and closes only for `maxPauseDuration` (at least twice
the challenge period), and a new pause needs a day since the last unpause.
Defeats, raises, escape finalization, `claimEscapePayout` and
`retireClosedLeaf` stay open while paused. Treasury changes are scheduled with
`setTreasury`, applied with `acceptTreasury` after `treasuryChangeDelay` of
unpaused time, and cancellable. A treasury that rejects a payment accrues
`treasuryArrears` instead of blocking payouts; anyone can pay them with
`withdrawTreasuryArrears`. An escape destination that rejects its payout, or
needs more than 100,000 gas (`ESCAPE_PAYOUT_GAS`), is credited in
`escapePayoutCredits` instead of blocking the escape; anyone can deliver the
credit with `claimEscapePayout(destination)`, which forwards all gas. A mutual
close to a destination that rejects ETH reverts, and a withdrawal to the zero
address or the vault itself reverts `InvalidDestination()`. The
[vault reference](../../../docs-site/content/docs/api-reference/vault.mdx) lists
every view, error and event.
