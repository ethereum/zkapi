# Native ETH architecture

```text
Host app -> browser SDK -> zkAPI server (proof-backed lease authorization)
                   |                  -> OA org/station or direct key management
                   |-> inference provider (prompts/responses)
                   |-> Ethereum native ETH vault
                   |-> indexer (current request-tree root and request paths)
                   |-> ERC-4337 bundler -> EntryPoint v0.7.0 -> transit account -> vault (withdrawals that pay their gas from the payout;
                                                                        the withdrawal paymaster sponsors and settles)

Challenger -> server request evidence + vault (+ indexer for retirements) -> restricted EIP-1559 signer -> vault
Activation worker -> vault (recorded notes) + indexer (cursor slot's siblings) -> insertion prover -> activateNotes -> vault
```

The browser keeps note secrets, blindings, signing evidence and recovery journals.
It creates Groth16 proofs locally with the packaged WASM and matching keys.
The server verifies each exact authorization, reserves its nullifier with an
append-only copy of its proof, issues a bounded key, settles the charge, and
signs the next balance at the anchor derived from the spent nullifier while
that nullifier is unspent on chain.

The authorization includes a pinned finalized ETH/USD quote. Notes and signed
balances are integer gwei; provider costs are micro-USD converted using that
saved quote. Exact retries preserve the original proof and quote. See
[native billing](native-eth-billing.md) for rounding and recovery rules.

A deposit only records its note on chain, and the note can exit at once. It
can make anonymous requests once it is activated: the operator's activation
worker appends the recorded notes to the request tree in deposit order, in
aligned batches of 1, 4 or 16 with an insertion proof (`activateNotes`,
which the vault takes only from its activator, the worker's sender), picking
the largest batch the recorded notes fill and waiting a bounded time for a
fuller one. Once an hour has passed since the latest proved activation,
anyone can activate without a prover (`activateNotesOnChain`). See
[the activation worker](activation-worker.md).

The indexer mirrors the recorded notes, activations and leaf retirements (the
tree is append-only otherwise) and every published nullifier, and serves only
a view it has verified against the vault's root, next note ID and activation
cursor. The
challenger defeats an escape with a verified request proof at its successor
nullifier, raises an under-conceded escape with the request at its nullifier,
retires a closed note's leaf after a missed defeat (once the note is
activated), and retries through
durable deployment-bound checkpoints. It reports each obligation on private
status endpoints. See [challenge operation](challenge-service.md).

Settlement always fixes a charge: a lease that never reached the wallet
settles at zero, and a delivered lease whose usage is still unavailable at its
write-once deadline settles at the proof's solvency bound. The exceptions are a lease
whose record is corrupt and a pending lease whose row cannot be decoded; the
operator repairs and reopens the first, and repairs the second, restoring an
unreadable saved request with the reopen command
([settlement terminality](native-eth-billing.md#settlement-terminality)). Owners
recover signed states from the API server; an exit never needs it. Mutual
close sends the server a kind-2 ownership proof of the note, which cannot
start an escape, and checks that it names the note the vault stores, before it
signs a clearance. An escape needs no operator and no path: every withdrawal
proof names its note by the registration commitment, amount and expiry the
vault stores, which the vault compares, and it concedes at most the state's
request budget. The vault owner can pause
exits for at most `maxPauseDuration` and schedule time-locked treasury
changes; a pause cannot move funds or expire notes. See
[owner and operator powers](../docs-site/content/docs/protocol.mdx#owner-and-operator-powers)
and the [concession-vault migration](migration-concession-vault.md).

A withdrawal can pay its network fee from the payout instead of a funded
account: its proof names a transit account derived from the owner and the
payout address, and a user operation from that account, sent through the
operator's ERC-4337 bundler, makes the vault call. The withdrawal paymaster
re-runs the vault's checks in validation, sponsors the gas from its EntryPoint
deposit, and in postOp keeps a measured charge and pushes the rest to the
payout address; the vault itself is unchanged
([operating it](deployment.md#operating-gasless-withdrawals)).

Only the v2 Groth16/Baby-JubJub proof path and native ETH payment path are active.
The operator CLI supplies server/indexer/setup/signing-key commands; the host
application integrates the browser SDK directly. The separate [zkapi-clientd](../zkapi-clientd/README.md) frontend provides a local
OpenAI-compatible API backed by private native ETH balances. Its Rust
wallet/prover companion, `zkapi-walletd`, is built from this repository's
`crates/zkapi-companion` at a pinned commit. It has no ticket mode or token
wallet. It checks deposits against the vault's `notes(noteId)` and
withdrawals against the vault and the operator's indexer before changing
private state, shows a note as activating until its activation, and escapes
without the operator, through the user's own exit RPC when one is configured.
