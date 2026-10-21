# End-to-End Flows

## Request

1. The wallet fixes the state's solvency bound (`bound_at_state`) with its
   journal, then proves membership and a note-bound state (genesis, or a
   signed state at the successor anchor of an earlier nullifier), solvency
   with the balance at most the deposit, rerandomization, and authorization
   for the exact request context.
2. The server verifies deployment, signing keys, time, the exact current
   root, bound and proof.
3. A durable nullifier reservation, written with an append-only copy of the
   request proof, prevents competing spends.
4. A short-lived OpenRouter lease determines usage.
5. The server settles the bounded charge, then, only while the request's
   nullifier is unspent on chain, signs the next state at
   `succ(N) = H("zkapi.v2c.anchor", N)` with fresh blinding, and persists the
   transcript. A lease whose key never reached the wallet settles at zero; a
   delivered lease whose usage is still unavailable at its write-once
   settlement deadline settles at the solvency bound.
6. The wallet checks the returned transition, including the derived anchor
   and the charge against its bound, and installs its next state.
   Prepared-request journals support retries and recovery.

## Mutual close

The client sends a kind-2 ownership proof of its current state (no
destination, no successor nullifier, valid for at most an hour) with its
clearance request. The server verifies it, reserves the nullifier and returns
a clearance signature. The client proves a kind-1 close with that signature,
and the vault consumes the nullifier and settles native ETH to the user and
treasury. No Merkle work is done, and any root the vault ever held is
accepted.

## Escape, defeat and raise

The client proves a kind-0 escape from its newest state `S_k`. It publishes
`N_k`, the successor's nullifier `N_{k+1}`, a conceded amount `c` up to the
state's `bound_at_state`, and a `valid_until`. Initiation consumes both
nullifiers and starts the challenge period; the leaf stays in the tree.

- A request proof at `N_{k+1}` shows the owner spent the successor, so the
  escape was stale. The challenge service submits it from the server's
  request evidence, whatever the request's settlement status; the vault
  returns the note to active and marks `N_k` as challenged for good.
- A request proof at `N_k` only raises `c`, to at most that request's
  solvency bound. The challenge service raises to the settled charge, or to
  the solvency bound of a request that may have been delivered and is still
  unsettled near the deadline.

Neither needs an indexer path or the live root. After an uncontested deadline,
anyone can finalize the escape, which pays `B_k − c` to its destination. If
the destination rejects the payout or needs more than 100,000 gas, the vault
still closes the note and pays the treasury share, and credits the payout to
that destination; anyone can deliver it later with
`claimEscapePayout(destination)`. After a missed defeat, the challenge service
retires the closed note's leaf (`retireClosedLeaf`).

If an active note is not withdrawn, its deposit can be claimed for the
treasury after its effective expiry, which paused time and a defeat extend.
Expiry claims are closed while the vault is paused.
