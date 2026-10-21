# Solidity Contracts

[ZkApiVault](../../contracts/src/ZkApiVault.sol) (revision 3,
`CONCESSION_ESCAPE_VERSION` 1) accepts native ETH deposits in whole gwei,
maintains the depth-32 note tree, and pins the server's state and clearance
signing keys, the proof adapter, the challenge period, the note lifetime and
the maximum pause. Amounts are bounded by `2^53 - 1` gwei.

[NoteLeafLib](../../contracts/src/libraries/NoteLeafLib.sol) and
[MerkleUpdateLib](../../contracts/src/libraries/MerkleUpdateLib.sol) use the
[BN254 Poseidon implementation](../../contracts/src/libraries/Bn254Poseidon.sol)
shared with the circuit parameters (a leaf is the sponge over its five fields;
a node is one permutation with the domain in the capacity lane, `compress`).
The library is generated with the setup (`zkapi-proof`'s `refresh_setup_sources`
example rewrites it) in the optimized form of the Poseidon reference
implementation. Only `deposit` and `retireClosedLeaf` update the tree:
`MerkleUpdateLib` keeps the tree's frontier, so a deposit appends its leaf
without a Merkle proof (32 compressions) and deposits never invalidate each
other, while a retirement proves the leaf's siblings at the live root and
refreshes the one frontier entry it can reach. Every root the vault sets is
recorded in `knownRoots`, and a withdrawal proof may use any of them.

[Groth16ProofAdapter](../../contracts/src/adapters/Groth16ProofAdapter.sol)
verifies the request and withdrawal statements directly and exposes
`CIRCUIT_ID_HASH`, `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH`. Public
deployment fields and pinned signing keys are checked by the vault before
settlement.

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
after each unpause. `retireClosedLeaf` removes a closed note's leaf.
[Types.sol](../../contracts/src/libraries/Types.sol) defines the note state,
the pending records and the proof statements.

The owner can pause deposits, expiry claims and treasury changes until it
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
