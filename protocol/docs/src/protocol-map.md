# Protocol Map

| Behavior | Implementation |
| --- | --- |
| Registration, leaf, nullifiers, successor anchors, signature messages | [v2.rs](../../rust/crates/zkapi-core/src/v2.rs) |
| Note tree and sibling paths | [merkle.rs](../../rust/crates/zkapi-core/src/merkle.rs) |
| Request and withdrawal constraints | [groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) |
| Native proving, verification, signing, key headers and setup policy | [compact.rs](../../rust/crates/zkapi-proof/src/compact.rs) |
| The `CircomReduction` QAP reduction every prover uses | [reduction.rs](../../rust/crates/zkapi-proof/src/reduction.rs) |
| R1CS export and ceremony import checks | [r1cs.rs](../../rust/crates/zkapi-proof/src/r1cs.rs), [ceremony.rs](../../rust/crates/zkapi-proof/src/ceremony.rs) |
| Public statements and field ordering | [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs) |
| Native wallet and recovery | [wallet.rs](../../rust/crates/zkapi-client/src/wallet.rs) |
| Exit rules (S1–S6, C1–C5, E0–E7) and the exit lock | [exit_policy.rs](../../rust/crates/zkapi-client/src/exit_policy.rs), [exit_lock.rs](../../rust/crates/zkapi-client/src/exit_lock.rs) |
| Browser wallet | [zkapi-browser](../../rust/crates/zkapi-browser/src/lib.rs) |
| Native ETH deposits, exits, defeats and raises | [ZkApiVault.sol](../../contracts/src/ZkApiVault.sol) |
| EVM verification | [Groth16ProofAdapter.sol](../../contracts/src/adapters/Groth16ProofAdapter.sol) |
| HTTP processing, durable transcripts and request evidence | [Root server](../../../crates/zkapi-serverd) |
| Defeats, raises and leaf retirement | [challenge_service.rs](../../../crates/zkapi-serverd/src/challenge_service.rs) |
| Contract event indexing | [Root indexer](../../../crates/zkapi-indexerd) |
| Desktop wallet companion and exit kit | [zkapi-companion](../../../crates/zkapi-companion) |

Registration commits to the user's secret. The leaf also commits to the note
ID, deposit and expiry. Both circuits include that private leaf in the balance
commitment, so a signed state remains bound to its original note. The
nullifier includes the note ID, and each signed state's anchor is derived from
the previous state's nullifier.
