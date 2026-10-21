# zkAPI concession exit: final specification (circuit `zkapi-v2-concession-v1`, vault revision 3), red-team revision

> **Status:** design and migration plan for circuit `zkapi-v2-concession-v1` (vault revision 3). Implemented with the `dev` setup in `protocol/setup/v2-concession-dev`; no revision-3 vault is deployed, and the packaged profiles are `not_deployed` placeholders. The multi-party setup, external review, Sepolia drill and mainnet rollout in §10 are operational gates, not yet run. Where the implementation differs from this text, [Implementation status](#implementation-status) records it. The operator runbook is [Migrating to the concession-exit vault](../migration-concession-vault.md).
>
> **Amendment A1 (any known root).** §4.2 step 6 and §4.5 accept any root the vault ever held, not only the current root or one retired within 1 day. The tree is append-only for every note that is not `Closed` (`retireClosedLeaf` only removes a `Closed` note's leaf), so every root recorded since a note's deposit contains that note's leaf, and `initiateEscapeWithdrawal` and `mutualClose` require `Active`. The vault records every root it sets (`knownRoots[root] = true`, one extra SSTORE per deposit and per retirement), and a client can exit with the Merkle path it saved at deposit, with no indexer and no log rebuild. §6.6's rebuild remains the fallback for a client that has no saved path.
>
> **Amendment A2 (the 30-day transition).** §10.7 C5 and E2 to E3 are read with this. The deployed legacy vaults give a note a 30-day life (rounded up to a UTC midnight) and a 24-hour challenge period, and the owner never pauses them, so the drain is bounded by the note life. **Day 0** is the moment the legacy deposit routes close, in the same change window as the new vault's go-live. `N_C = nextNoteId()` read then separates transition notes (ID below `N_C`) from late notes (direct deposits after day 0). **`X` is the expiry of note `N_C - 1`**, before day 31, not Phase C + 30 days: every transition note has expired or exited by `X`, so closing legacy admission at `X` costs no owner who acted in time any service. The legacy stack retires about a day after `X` (about day 32), or, with late notes, when they too are closed or swept (before day 63). A legacy server cannot tell the two kinds of note apart, because a request hides its note ID. The runbook's [30-day transition](../migration-concession-vault.md#the-30-day-transition-for-existing-users) is the schedule.


Baseline: repository at `ac9be63`, circuit `zkapi-v2-note-bound-v1`. Every "today" figure comes from the five maps in `scratchpad/circuit`. I computed the selectors and topics below with Foundry `cast` against the exact signatures given; implementers must re-derive them and pin them in tests. This revision answers the red-team findings. The appendix records what was done with each one.

---

## 1. Summary

### 1.1 The problem in one sentence
Today an exit names only the nullifier `N_k` of the state it leaves, and the vault treats any request proof at `N_k` as proof that the exit is stale. A withholding operator holds such a proof for every state the user can prove, so it can defeat every escape and sweep the deposit at expiry.

### 1.2 The fix
1. **Derived successor anchor, enforced at three layers.**
   - The server signs successors only at `τ_{k+1} = H(d_anchor', N_k)`.
   - Clients refuse any other anchor (S4).
   - The request circuit refuses to spend a signed state whose anchor does not have that form (Q6a), so a non-derived successor can never be spent.
   - Anyone can compute `τ_{k+1}`; only the holder of `s` can compute `N_{k+1}`.
2. **The exit names both nullifiers, concedes an amount and expires.** An escape publishes `N_k`, `next_nullifier = N_{k+1}` (computed in the circuit), `conceded = c` and `valid_until`. It pays `B_k − c`. The vault consumes both `N_k` and `N_{k+1}` and rejects the proof after `valid_until`.
3. **The challenge has two separate outcomes.**
   - **Defeat** (`challengeEscapeWithdrawal`). Only a valid request proof at **`N_{k+1}`** defeats an exit, because it shows the owner held and spent the successor.
   - **Raise** (`raiseEscapeConcession`, new). A valid request proof at **`N_k`** can only raise `c`, in place, to `min(amount, proof.solvencyBound, B_k)`.
4. **Clients fix one bound per state.** Every request proof at a state uses one `solvency_bound`, persisted as `bound_at_state` before any proof leaves the device. A raise can therefore never take more than `bound_at_state`, whatever the client concedes.
5. **Exits do no Merkle work.** The note tree becomes append-only: deposits insert leaves, and exits, defeats, closes and expiry claims leave the leaf in place.
   - After an exit, service is stopped by nullifiers, not by the tree. The vault consumes `N_k` and `N_{k+1}`. The honest server never delivers a key for a consumed nullifier (O3) and never signs a successor for one (O7).
   - Escape gas falls from about 6.5M to about 0.6M, a defeat costs about 0.37M, and no exit races the live root.
   - A permissionless `retireClosedLeaf` lets the operator remove a closed note's leaf when it wants the root check as a second barrier.
6. **Exits never wait on the operator or on a trusted RPC.**
   - Every operator call in exit mode has a hard timeout.
   - The latest time to start an exit is computed from the local `expiry_ts`.
   - The owner's pause is bounded.
   - The settlement window comes from the build-pinned profile.
7. **Clients verify the deployment they trust.** Profiles pin the runtime codehashes of the vault, adapter and Poseidon library, plus the verifying-key hashes, and clients check them through the user's own wallet provider before every deposit.

### 1.3 Riders included because they are cheap and close real gaps

| Rider | What it closes |
|---|---|
| Nullifier includes the note: `N = H(d_null', s, note_id, τ)` (0 extra constraints) | R6, and secret reuse across notes |
| `is_genesis` derived as `τ == 1` in both circuits | Born-spent successors at anchor 1 |
| Request-circuit anchor chain `τ = H(d_anchor', N(τ_prev))` on the signed branch (+724) | Server anchor bugs: a non-derived successor is unspendable, so G2 no longer depends on signing correctness |
| `B ≤ D` in the request circuit | R1 |
| Withdrawal `kind ∈ {0 escape, 1 close, 2 ownership}` | R2. The vault accepts kind 0 only for escape and kind 1 only for close. Ownership proofs publish no successor nullifier and no destination |
| `valid_until` public input (+65 constraints, +7.9k gas) | Replay of abandoned exit proofs, and of ownership proofs at the server |
| `withdrawal_tag` removed (−726) and replaced by an explicit 160-bit `destination` binding | Keeps the destination bound by a constraint |
| Append-only tree; exits do no Merkle work | 6M-gas exits, `StaleRoot` front-running, and the indexer dependence of defeats |
| `SupersededState` revert | Pointless defeats of exits from the state just below a defeated one |
| Bounded pause (`maxPauseDuration`, 1-day re-pause cooldown) | Indefinite freeze by an owner who is the operator |
| Codehash, VK-hash and setup-ID pins | Unverifiable deployments; dev keys reaching production |
| `request_evidence` table plus the O7 signing gate | Operator-side evidence holes; post-exit zero-charge successor chains |
| Tree rebuild from vault logs, user exit RPC, exit kit, clientd escape route | Exits that depend on the operator's indexer, RPC or host |

### 1.4 Scope dropped from the candidates, and why
- **Bumping `protocol_version` to 3: dropped.** The vault address already separates deployments. `protocol_version` stays 2, and the request public inputs, `RequestPublicInputsV2`, `ApiRequestV2` and `api_request_binding` stay byte-identical.
- **Anchor chain in the withdrawal circuit: dropped.** Exits must never need `τ_prev`, whose loss would lock the note. The chain is enforced only in the request circuit (Q6a), where losing `τ_prev` blocks requests but never exits.
- **On-chain `maxRequestCharge` clamp: dropped.** It would couple an immutable to the ETH price, and raises are already capped by the user's own bound. The server enforces a USD ceiling on leases instead (§5.2).
- **Cooperative "mode 3" concession close, and a clearance that binds `c` and an expiry (R3): dropped.** The raise takes an `amount`, and R3 is harmless under the client rule "never request from a state after sending its ownership proof" (§9).
- **Client self-defeat of an unintended exit: not adopted.** Once a released exit proof can land only before `valid_until`, while the client is frozen by C3, any exit that lands is one the client chose (§6.4 E6).
- **Raise-before-defeat in the challenger: not adopted.** With Merkle work gone, a defeat and a raise have identical failure modes. Both are about 0.35M-gas proof verifications with no indexer and no live root, so a raise adds no independent protection (§5.4).
- **On-chain deposit cap: not adopted.**
  - The operator's exposure is the service it delivers, not the size of the deposit, so the server-side lease ceiling (§5.2) is the right control.
  - The SDK canary cap protects honest SDK users, which is what it is for. Users who deposit directly bypass it, and the spec says so.
- **New pending-escape getter and new escape event: dropped.** The 6-word `pendingWithdrawals` getter and the 5-word `EscapeWithdrawalInitiated` event stay; new data goes into a side mapping and additive events.

### 1.5 Headline numbers (estimates from unit costs; measured in WP-A and WP-B)

| Item | Today | New |
|---|---|---|
| Request circuit | 30,821 constraints, 2^15 | ≈31,679 (+2.8%), 31,692 rows, ≈1,076 rows of headroom |
| Withdrawal circuit | 35,969 constraints | ≈36,458 (+1.4%), 2^16, 16 public inputs |
| Browser request / withdrawal prove (WASM, 1 thread) | ≈8.0 s / 9.6–11.4 s | ≈8.25 s / +≈0.15 s |
| Escape transaction | 6.42–6.47M gas | ≈0.55–0.62M |
| Defeat transaction | 6.29–6.35M | ≈0.33–0.40M |
| Raise transaction | n/a | ≈0.33M |
| `mutualClose` / `claimExpired` | ≈6.4M / ≈6.1M | ≈0.40–0.45M / ≈0.06–0.15M |
| Vault runtime size (protocol profile) | 15,689 B | ≈16.3–17.3 KB (≥7 KB under EIP-170) |

### 1.6 Migration headline
- A new MPC-phase-2 setup (snarkjs pipeline, `CircomReduction` provers from the first commit), a new adapter and a new vault (revision 3, capability `exit_concession: 1`). This vault replaces the built but undeployed hardened revision-2 vault, so users migrate once.
- The legacy vault drains through config-only re-cuts of the current SDK and clientd, frozen on `release/v2-note-bound` (cut at `ac9be63`), with deposits closed and a dated service cutoff.
- One client build per vault. The clientd companion is re-vendored into this repository (Option C).
- **Mainnet is gated** on the ceremony, a ceremony-fidelity test, external review, reproducible WASM, and published reproducible codehashes.

---

## 2. Threat model and goals

### 2.1 Parties
- **User / wallet.**
  - Holds: `s`; the current state `(B, r, τ, τ_prev, σ)`; the journal (ε and request proofs); the archive; `bound_at_state`; `exit_lock`.
  - May be honest, careless (loses data) or malicious (rolls back, under-concedes, replays).
- **Operator.**
  - Runs the server, holds the state and clearance keys, the challenger, and usually the indexer and gateway. It may operate or influence the pinned RPC and the browser host.
  - May be honest, crashed, slow or malicious: it withholds, signs bad successors, lies or stalls in recovery and clearance calls, refuses clearance, challenges, raises, front-runs, and deploys contracts.
- **Third parties.** The gateway and anyone else who sees transmitted proofs. Challenge and raise are permissionless.
- **Vault owner.** Usually the operator.
  - Can pause for at most `maxPauseDuration` before exits reopen.
  - Cannot re-pause within 1 day of an unpause.
  - Changes the treasury under a timelock.
- **Chain.** Live. It includes a user's transaction within hours and does not censor indefinitely.

### 2.2 Assumptions
- **A1 Cryptography.** Groth16 knowledge soundness for both verifying keys; Poseidon collision and preimage resistance in fixed-arity domains; EUF-CMA Schnorr on Baby-JubJub; Pedersen binding (no known discrete-log relation among `G`, `H`, `J`).
- **A2 Setup integrity.** Nobody knows the setup's toxic waste, which has a phase-1 part and a phase-2 part. Both of these hold:
  - **Phase 1.** At least one contributor to the public powers-of-tau transcript was honest, **and** the ceremony actually used that public transcript: one listed in `zkapi_proof::ceremony::PUBLIC_PTAU`, matched by the Blake2b-512 its publisher lists. A powers of tau that one party made alone passes every consistency check, so only its provenance shows that phase 1 is sound.
  - **Phase 2.** At least one phase-2 contributor was honest and outside the attacker's control.

  The keys must also be keys of this circuit (the binding checks of §10.2). This is load-bearing for G1 and G2, because a trapdoor holder can forge any proof, including defeat evidence. It is enforced by G-SETUP (§10.2), and users can audit it through the powers-of-tau hash in the setup manifest, the published transcript, and the codehash and VK-hash pins.
- **A3 Chain liveness.** The user can get one transaction included before `must_initiate_by` (§6.4). Owner pauses are bounded (§4.7) and are not an assumption.
- **A4 Operator liveness (G2 only).** Before each pending escape's deadline, the operator's challenger lands the one transaction its policy calls for: a defeat when evidence at `N⁺` exists, otherwise a raise when `Ω > c`.
- **A5 Durable client storage.** `bound_at_state`, the journal and `exit_lock` are written before transmission (§6.2 ordering).
- **A6 Browser host.** The browser host serves the pinned build. If it does not, or it disappears, browser users rely on a current exit kit (§6.4 E7). clientd users do not depend on a host.

### 2.3 Goals, stated precisely
- **G1 (funds safety).**
  - Setup: let `S_k` be the newest state an honest client installed, in a deployment whose codehashes matched its pins at deposit time. Let `b_k = bound_at_state(S_k)`, which is 0 if no request proof left the device at `S_k`.
  - Guarantee: without any operator cooperation, the client obtains a vault payout of at least `B_k − b_k`, where `B_k = D − Σ_{i<k} Δ_i` and each `Δ_i` was verified to be at most its request's `solvency_bound`.
  - This holds under A1–A3 and A5 (A6 for browser users), for every operator and owner behaviour.
  - The payout is gross of the user's exit gas, about 0.6M gas. The client warns when `B_k − b_k` is below three times the estimated exit cost.
- **G2 (operator payment).**
  - Setup: an honest operator (O1–O7, §7.1), with A1, A2 and A4.
  - Guarantee: for every note, the total paid to the user is at most `D − Σ_{served R} owed(R)`, where `owed(R) ≥` the actual charge of `R`. In particular, a user who received and spent `S_{k+1}` cannot exit from `S_k`.
  - If A4 fails, the loss is bounded as stated in §7.4.
- **G3 (privacy).**
  - Requests remain unlinkable across states and to the deposit, and prompts never reach the billing server.
  - Any new linkage happens only at exit, only for the exiting note, and at most to its last request, unless that user misbehaves (§8).
- **G4 (cost).** Small circuit deltas, an unchanged request ABI, browser proving within +4%, and exits about 10 times cheaper than today.
- **G5 (riders).** R1, R2 and R6; the born-spent successor; the vestigial tag; server anchor bugs; exit-proof replay; unbounded pause; unverified deployments; and operator dependence for Merkle paths, RPC and timing.

---

## 3. Circuit changes

### 3.1 Domains and native functions

| Domain label | Field value (big-endian bytes) | Arity incl. domain | Definition | Status |
|---|---|---|---|---|
| `zkapi.v2c.null` | `0x7a6b6170692e7632632e6e756c6c` | 4 | `N(τ) = H(d_null', s, note_id, τ)` | **new**, replaces `zkapi.v2.null` |
| `zkapi.v2c.anchor` | `0x7a6b6170692e7632632e616e63686f72` | 2 | `succ(N) = H(d_anchor', N)` | **new**, replaces `zkapi.v2.anchor` |
| `zkapi.v2.reg`, `.leaf`, `.node`, `.auth`, `.state`, `.clear`, `.sig` | unchanged | unchanged | unchanged | kept |
| `zkapi.v2.withdraw`, `zkapi.v2.blind`, `zkapi.v2.anchor`, `zkapi.v2.null` | | | | **retired** |

- Both new arities are even and fixed, so the sponge's odd-arity padding quirk cannot produce a collision.
- `leaf`, `node` and `reg` are unchanged, so the deposit ABI, `NoteLeafLib`, the indexer and clientd's Go Poseidon are untouched.
- **Chain:** `τ_0 = 1`, `τ_{i+1} = succ(N(τ_i))`, `N_i = N(τ_i)`.

**Native functions** (`protocol/rust/crates/zkapi-core/src/v2.rs`, replacing the old ones, mirrored by the circuits):

```
pub const GENESIS_ANCHOR: Felt252 = 1;
pub fn nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252     // H(d_null', s, n, τ)
pub fn next_anchor(request_nullifier: &Felt252) -> Felt252                        // H(d_anchor', N)
pub fn successor_nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252
    // = nullifier(s, n, next_anchor(nullifier(s, n, τ)))
```

`withdrawal_tag`, `blind_delta` and the old `next_anchor(ρ, N, x, y)` are deleted. The server needs only `next_anchor`.

### 3.2 RequestCircuit: public inputs unchanged, constraints changed

**Public inputs** (0-based) are identical to today: 12 inputs, 13 instance variables, the same encoding, `Types.RequestPublicInputs` and the same adapter array.

| # | Field | Type |
|---|---|---|
| 0 | `protocol_version` (= 2) | u16 |
| 1 | `chain_id` | u64 |
| 2 | `contract_address` | felt / address |
| 3 | `active_root` | felt |
| 4, 5 | `state_signing_key` x, y | point |
| 6 | `request_time` | u64 |
| 7 | `solvency_bound` | u128 |
| 8 | `request_nullifier` | felt |
| 9 | `authorization_tag` | felt |
| 10, 11 | `anonymous_commitment` x, y | point |

**Witnesses:** `secret s`, `request_context`, `note_id` (UInt32), `deposit_amount D` (UInt128), `expiry` (UInt64), `merkle_siblings[32]`, `current_balance B` (UInt128), `current_blinding r`, `rerandomization ε`, `current_anchor τ`, **`prev_anchor τ_p` (new)**, `state_signature σ`. The free `is_genesis` witness is removed.

**Constraints** (Δ marks a change):
- **Q1.** `s ≠ 0`.
- **Q2.** UInt64 `request_time` equals input 6, and `expiry ≥ request_time`.
- **Q3.** UInt128 `sb` equals input 7, and `B ≥ sb`.
- **Q4 Δ.** `D ≥ B` (UInt128 `is_ge`, both branches).
- **Q5.** `R = H(d_reg, s, 0)`, `L = H(d_leaf, n, R, D, expiry)`, and the depth-32 path over `n.bits` equals input 3.
- **Q6 Δ.** `g := τ.is_eq(1)`, and `g ⇒ B == D`. A signed state at τ = 1 is unprovable.
- **Q6a Δ (new).** `¬g ⇒ τ == H(d_anchor', H(d_null', s, n.to_fp(), τ_p))`, by conditional equality. At genesis `τ_p` is unconstrained; the prover passes 0.
- **Q7.** `C = B·G + r·H + L·J`, then `M_state = H(d_state, pv, chain, contract, C.x, C.y, τ)`, then `Schnorr(PK_state, M_state, σ)` iff `¬g`.
- **Q8.** `C + ε·H == (input 10, input 11)`.
- **Q9 Δ.** `H(d_null', s, n.to_fp(), τ) == input 8`.
- **Q10.** `H(d_auth, input 8, request_context) == input 9`.

**Cost**

| Change | Constraints |
|---|---|
| Q4 | +131 |
| Q6 (`is_eq` +3, booleanity −1) | +2 |
| Q6a (arity-4 Poseidon 483, arity-2 Poseidon 240, select 1) | +724 |
| Q9 (arity 3→4 costs the same) | ≈+1 |
| **Total** | **≈+858 → ≈31,679** |

QAP rows = constraints + 13 ≈ 31,692 ≤ 32,768. A CI assertion (`constraint_budget`, §11) requires request constraints + 13 ≤ 32,700.

### 3.3 WithdrawalCircuit: 16 public inputs

The public inputs (0-based) are also the field order of `Types.WithdrawalPublicInputs`.

| # | Field | Rust / Solidity type | Meaning |
|---|---|---|---|
| 0 | `protocol_version` | u16 / uint16 | 2 |
| 1 | `chain_id` | u64 / uint64 | |
| 2 | `contract_address` | felt / address | |
| 3 | `active_root` | felt / uint256 | |
| 4, 5 | `state_signing_key` x, y | felt / uint256 | |
| 6, 7 | `clearance_signing_key` x, y | felt / uint256 | |
| 8 | `note_id` | u32 / uint32 | |
| 9 | `final_balance` | u128 / uint128 | payout `= B − conceded` |
| 10 | `destination` | [u8;20] / address | 0 when kind = 2 |
| 11 | `withdrawal_nullifier` | felt / uint256 | `N = N(τ)` |
| 12 | `kind` | u8 / uint8 | 0 escape, 1 mutual close, 2 ownership proof |
| 13 | `next_nullifier` | felt / uint256 | `N(succ(N))` if kind = 0, else 0 |
| 14 | `conceded` | u128 / uint128 | 0 unless kind = 0 |
| 15 | `valid_until` | u64 / uint64 | **new**: the latest second at which the vault (kinds 0 and 1) or server (kind 2) accepts the proof |

**Witnesses:** `s`, `D` (UInt128), `expiry` (UInt64), `siblings[32]`, `state_balance B` (UInt128), `state_blinding r`, `anchor τ`, `state_signature σ`, `clearance_signature σ_c`. The prover derives the 160 destination bits and `k1`, `k2`. There is no `τ_prev`: exits never need it.

**Constraints:**
- **W1.** `s ≠ 0`.
- **W2.** UInt32 `n` equals input 8.
- **W3.** UInt128 `f` equals input 9; UInt128 `c` equals input 14; UInt128 `B` is a witness; `B.to_fp() == f.to_fp() + c.to_fp()`. The sum cannot wrap, so `c ≤ B` and `f ≤ B`.
- **W4.** `D ≥ B`. `expiry` is UInt64 with no time check.
- **W5.** Registration, leaf and depth-32 path to input 3.
- **W6.** `g := τ.is_eq(1)`; `g ⇒ B == D`.
- **W7.** `C = B·G + r·H + L·J`, then `M_state(C, τ)`, then `Schnorr(PK_state, M_state, σ)` iff `¬g`.
- **W8.** `N := H(d_null', s, n, τ) == input 11`.
- **W9.** `input 12 == k1 + 2·k2`, with `k1`, `k2` Boolean and `k1·k2 == 0`. Then `is_close := k1`, `is_own := k2`, `is_escape := 1 − k1 − k2`.
- **W10.** `τ⁺ := H(d_anchor', N)`; `N⁺ := H(d_null', s, n, τ⁺)`; `input 13 == is_escape · N⁺`.
- **W11.** `(k1 + k2) · c == 0`.
- **W12.** 160 Boolean witnesses with `Σ b_i·2^i == input 10`, and `k2 · input 10 == 0`.
- **W13.** `M_clear := H(d_clear, pv, chain, contract, N)`; `Schnorr(PK_clear, M_clear, σ_c)` iff `k1`.
- **W14 (new).** UInt64 `valid_until` equals input 15. This is a range check and an explicit use of the input, so binding does not depend on the QAP reduction. The time comparison is done by the vault and the server.
- **Removed:** the `withdrawal_tag` Poseidon and the `has_clearance` input.

**Cost**

| Change | Constraints |
|---|---|
| Tag removed | −726 |
| `kind` | +3 |
| `τ⁺` (arity 2) | +240 |
| `N⁺` (arity 4) | +483 |
| W10 select | +1 |
| `c` allocation and equality | +129 |
| `B` allocation and sum | +129 |
| W11 | +1 |
| W12 | +162 |
| `g` | +2 |
| W14 | +65 |
| **Net** | **≈+489 → ≈36,458** |

The domain is 2^16, with 17 instance variables and 17 IC points.

**Why W12 and W14 are explicit.** The provers use `CircomReduction` (§3.4). Explicit constraints keep destination and `valid_until` binding, and the range checks, independent of how a reduction binds instance variables. They also force `destination = 0` for ownership proofs.

### 3.4 Native helpers, witness structs and the proof system
- **`groth16.rs`:**
  - `RequestWitness` gets `prev_anchor` and drops `is_genesis`.
  - `WithdrawalWitness` drops `is_genesis`, gets `state_balance` and renames `final_blinding` to `state_blinding`.
  - `WithdrawalPublic` gets `kind: u8`, `next_nullifier`, `conceded: u128` and `valid_until: u64`, and drops `has_clearance` and `withdrawal_tag`.
- **`compact.rs`:**
  - `RequestWitnessData` gets `prev_anchor`.
  - `WithdrawalWitnessData` gets `state_balance`, `conceded`, `kind` and `valid_until`.
  - `validate_witness` checks:
    - (request) `τ ≠ 1 ⇒ τ == next_anchor(nullifier(s, n, τ_p))`;
    - (withdrawal) `f + c == B`, `B ≤ D`, `kind ∈ {0,1,2}`, kind 2 ⇒ `destination == 0`, and `c == 0` unless kind 0.
- **Canonical prover-side values:** `next_nullifier = 0` and `conceded = 0` for kinds 1 and 2.
- **Proof system (decided before WP-A).**
  - Every prover uses one type alias, `compact::Prover = Groth16<Bn254, CircomReduction>`: WASM, companion, fixture generators, the acceptance driver and the CLI.
  - `CircomReduction` (≈100 lines) is vendored into `zkapi-proof/src/reduction.rs` so the WASM gets no `ark-circom` dependency. A non-WASM test cross-checks it against the `ark-circom` crate.
  - Verification is unchanged: the adapter, the server verifier and the challenger use standard Groth16 verification, which does not depend on the reduction.
  - The **dev setup** is generated with the same reduction: `Groth16::<Bn254, CircomReduction>::circuit_specific_setup`. WP-A checks that ark-groth16's generator honours `CircomReduction::h_query_scalars`; if it does not, the dev setup is produced with snarkjs from a throwaway ptau, the ceremony pipeline. Every work-package test therefore runs the prover that ships.
  - Constraint synthesis for proving, setup and export uses `OptimizationGoal::Constraints` followed by `cs.finalize()`, so all three see identical matrices.

---

## 4. Vault and adapter changes

### 4.1 Types, storage, constants and constructor

```solidity
// Types.sol: static tuple; ABI words == public-input order (the fixture ABI trick depends on it)
struct WithdrawalPublicInputs {
    uint16 protocolVersion; uint64 chainId; address contractAddress; uint256 activeRoot;
    uint256 stateSigningKeyX; uint256 stateSigningKeyY;
    uint256 clearanceSigningKeyX; uint256 clearanceSigningKeyY;
    uint32 noteId; uint128 finalBalance; address destination; uint256 withdrawalNullifier;
    uint8 kind; uint256 nextNullifier; uint128 conceded; uint64 validUntil;
}
// RequestPublicInputs, Note, PendingWithdrawalData: UNCHANGED.
struct PendingConcession {          // 2 slots
    uint256 nextNullifier;          // slot 0: N_{k+1}
    uint128 stateBalance;           // slot 1: B_k
    uint128 conceded;               //         c (only ever increases)
}
```

**`ZkApiVault` additions:**

```solidity
uint16 public constant CONCESSION_ESCAPE_VERSION = 1;
uint64 public constant PAUSE_COOLDOWN = 1 days;
uint8 private constant KIND_ESCAPE = 0; uint8 private constant KIND_CLOSE = 1;   // 2 = ownership, never accepted
uint64 public immutable maxPauseDuration;                                        // new constructor argument
mapping(uint32 => Types.PendingConcession) public pendingConcessions;            // appended after escapePayoutCredits (slot 14)
```

- **Constructor:** 11 arguments, the existing 10 plus `maxPauseDuration_`. It requires `maxPauseDuration_ ≥ 2 · challengePeriod_`. Everything else is unchanged, including `PROTOCOL_VERSION = 2`, `ROOT_HISTORY_WINDOW = 1 days` and the unread `requestChargeCap`.
- `pendingWithdrawals[n].finalBalance` always holds the **current** payout. Its `activeRoot` word now stores the proof's `activeRoot` and remains informational.
- **Invariant for every pending escape:**

  ```
  pendingWithdrawals[n].finalBalance + pendingConcessions[n].conceded == pendingConcessions[n].stateBalance ≤ notes[n].depositAmount
  ```

- **New errors:** `WrongWithdrawalKind()`, `SupersededState()`, `NotSuccessorEvidence()`, `NotStateEvidence()`, `NotARaise()`, `ProofExpired()`, `PauseCooldown()`, `NoteNotClosed()`.
- **New events:**

  ```solidity
  event EscapeConcessionRecorded(uint32 indexed noteId, uint256 nextNullifier, uint128 stateBalance, uint128 conceded);
    // topic0 0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d
  event EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier, uint128 conceded, uint128 finalBalance);
    // topic0 0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c
  event ClosedLeafRetired(uint32 indexed noteId, uint256 newRoot);
    // topic0 0x64572cec8ef079a5baa4f2860f8b65efb52a96f64ee679d315fd2a0541ea28b3
  ```

- `EscapeWithdrawalInitiated` (`0xb0d1eb71…9cdf`, 5 data words) and `EscapeWithdrawalChallenged` (`0x5cc5343b…3581`) keep their shape. Their root word now carries the **unchanged** `currentRoot`. The close and expiry events likewise carry the unchanged root.
- In the new tree, only `NoteDeposited` and `ClosedLeafRetired` change leaves.

### 4.2 `initiateEscapeWithdrawal(WithdrawalPublicInputs inputs, bytes proof)`
Selector `0xa38d62aa` (was `0x9073639b`; the siblings argument is removed). Modifiers: `nonReentrant`, `whenExitsOpen` (§4.7). Checks run in this order:
1. `_validateWithdrawalBinding(inputs)` (pv == 2, chain, `address(this)`, all four key coordinates).
2. `inputs.kind == KIND_ESCAPE`, else `WrongWithdrawalKind()`.
3. `block.timestamp ≤ inputs.validUntil`, else `ProofExpired()`.
4. `_requireDestination(inputs.destination)`.
5. Let `N = withdrawalNullifier` and `Nn = nextNullifier`.
   - `Nn != 0 && Nn != N`, else `InvalidDeploymentBinding()`.
   - `challengedNullifiers[N]` → `ChallengedNullifier()`.
   - `challengedNullifiers[Nn]` → `SupersededState()`.
6. `isKnownRoot(inputs.activeRoot)` (any root the vault ever held, Amendment A1), else `UnknownRoot()`.
7. `proofAdapter.assertValidWithdrawal(inputs, proof)`.
8. The note is `Active` (else `NoteNotActive()`), and `uint256(finalBalance) + conceded ≤ depositAmount` (else `InvalidBalance()`).
9. `_consumeNullifier(N)`, then `_consumeNullifier(Nn)`. Either reverts `ReplayedNullifier()`.
10. **No Merkle work.** Set `deadline = uint64(block.timestamp) + challengePeriod` and `status = PendingWithdrawal`. Write:
    - `pendingWithdrawals[n] = {true, inputs.activeRoot, N, finalBalance, destination, deadline}`;
    - `pendingConcessions[n] = {Nn, finalBalance + conceded, conceded}`.
11. Emit `EscapeWithdrawalInitiated(n, N, finalBalance, destination, deadline, currentRoot)`, then `EscapeConcessionRecorded(n, Nn, stateBalance, conceded)`.

Calldata is 836 bytes: `selector | 16 tuple words | offset 0x220 | len 256 | 8 proof words`.

### 4.3 `challengeEscapeWithdrawal(uint32 noteId, RequestPublicInputs inputs, bytes proof)`: the defeat
Selector `0xda0ce43d` (was `0x8a43467c`; siblings removed). Modifier `nonReentrant` only, so it is open while paused. Anyone may call it.
1. The note is `PendingWithdrawal`, `pending.exists`, and `block.timestamp < challengeDeadline`.
2. `_validateRequestBinding(inputs)` (unchanged).
3. `inputs.requestNullifier == pendingConcessions[noteId].nextNullifier`, else `NotSuccessorEvidence()`. A request at the escaped nullifier never defeats.
4. `assertValidRequest(inputs, proof)`. Root, time and tag are not checked: historical evidence is valid.
5. Set the note `Active` (no Merkle work; the leaf was never removed).
6. Let `N = pending.withdrawalNullifier` and `Nn = nextNullifier`. Delete `pendingWithdrawals[noteId]`, `pendingConcessions[noteId]`, `usedNullifiers[N]` and `usedNullifiers[Nn]`. Set `challengedNullifiers[N] = true`.
7. `_grantChallengeGrace(noteId, note)`, unchanged: at least `challengePeriod` of active time.
8. Emit `EscapeWithdrawalChallenged(noteId, N, currentRoot)`.

Calldata is 740 bytes: `selector | noteId | 12 words | offset 0x1c0 | len 256 | 8 proof words`.

### 4.4 `raiseEscapeConcession(uint32 noteId, RequestPublicInputs inputs, bytes proof, uint128 amount)`
Selector `0xdd0064ba`. Modifier `nonReentrant` only, so it is open while paused. Anyone may call it.
1. The note is `PendingWithdrawal`, `pending.exists`, and `block.timestamp < challengeDeadline`.
2. `_validateRequestBinding(inputs)`.
3. `inputs.requestNullifier == pending.withdrawalNullifier`, else `NotStateEvidence()`.
4. Let `pc = pendingConcessions[noteId]` and `newC = min(amount, inputs.solvencyBound, pc.stateBalance)`. Require `newC > pc.conceded`, else `NotARaise()`. These checks run before verification.
5. `assertValidRequest(inputs, proof)`.
6. Set `pc.conceded = newC` and `pending.finalBalance = pc.stateBalance − newC`. Emit `EscapeConcessionRaised(noteId, N, newC, finalBalance)`.

The deadline, nullifiers and grace do not change, and a defeat is still possible afterwards. Calldata is 772 bytes: `selector | noteId | 12 words | offset 0x1e0 | amount | len 256 | 8 proof words`.

### 4.5 Other entry points
- **`mutualClose(WithdrawalPublicInputs, bytes)`.** Selector `0x72cd2e44` (was `0x7fca9c82`). Modifiers `nonReentrant`, `whenExitsOpen`.
  - Order: binding, `kind == KIND_CLOSE`, `block.timestamp ≤ validUntil`, destination, `isKnownRoot`, proof, `_closeActive`.
  - `_closeActive`: `finalBalance ≤ D`; consume `N`; set `Closed`; `_transfer(finalBalance)` (reverts on failure); `_payTreasury(D − finalBalance)`. There is **no leaf removal**.
  - It does not consult `challengedNullifiers` (decision G2) and does not consume `next_nullifier`, which is 0 for kind 1.
- **`finalizeEscapeWithdrawal(uint32)`.** Selector `0xff8f5585`, unchanged, open while paused. It adds `delete pendingConcessions[noteId]`.
  - It pays the **current** `pending.finalBalance` with `ESCAPE_PAYOUT_GAS`; on failure the amount is credited to `escapePayoutCredits[destination]` with `EscapePayoutDeferred`.
  - Then `_payTreasury(D − finalBalance)`.
- **`claimExpired(uint32 noteId)`.** Selector `0xa940507e` (was `0xd0e1bf46`; siblings removed). `nonReentrant`, `whenNotPaused`. It requires `Active` and `now ≥ _claimableAt`, sets `Closed` and calls `_payTreasury(D)`. No leaf removal: the request circuit's `expiry ≥ request_time` already bars requests after `expiry_ts ≤ effectiveExpiry`.
- **`retireClosedLeaf(uint32 noteId, uint256[32] siblings)`** (new). Selector `0xe41f4c31`. `nonReentrant`, permissionless, open while paused.
  - It requires `notes[noteId].status == Closed` (else `NoteNotClosed()`).
  - It runs `newRoot = verifyAndUpdate(currentRoot, noteId, _leaf(noteId, note), 0, siblings)`, which reverts `StaleRoot` if the siblings are stale or the leaf is already retired. Then `_setCurrentRoot(newRoot)` and emit `ClosedLeafRetired`.
  - This is an operator tool (§5.4) and costs about 6.0M gas.
- **`deposit`, `claimEscapePayout`, treasury and owner functions:** unchanged, except `pause()` (§4.7).
- **Kind 2 (ownership) proofs** are rejected by every entry point.

### 4.6 Nullifier bookkeeping and `challengedNullifiers`

| Event | `usedNullifiers[N]` | `usedNullifiers[N⁺]` | `challengedNullifiers[N]` | `challengedNullifiers[N⁺]` | `pendingConcessions` |
|---|---|---|---|---|---|
| `initiateEscapeWithdrawal` | unset → set | unset → set | must be unset | must be unset (`SupersededState`) | written |
| `raiseEscapeConcession` | — | — | — | — | `conceded` increases |
| `challengeEscapeWithdrawal` (defeat) | deleted | deleted | **set** | — | deleted |
| `finalizeEscapeWithdrawal` | stays set | stays set | — | — | deleted |
| `mutualClose` | unset → set | — | not checked (G2) | — | — |

`challengedNullifiers` keeps its getter (`0x6cda756a`). It now means "an escape from this state was defeated by successor evidence", which an honest user can never trigger (§7.3).

**Re-escape after a defeat of an escape from `S_k`:**
- **From `S_k`:** cheap revert, `ChallengedNullifier`.
- **From `S_{k−1}`:** cheap revert, `SupersededState`.
- **From `S_{k−2}` or older:** not blocked. The proof is verified, and the escape is recorded and defeated again with `R_{k−1}`. That defeat flags `N_{k−2}`, so the escape after it reverts cheaply. A user holding `k` archived states can therefore force at most `⌈(k−1)/2⌉` further defeats. Each costs the operator about 0.37M gas and the user about 0.6M, and each grants at least `challengePeriod` of grace (§5.4 budgets for this).
- **From `S_{k+1}` or newer:** not blocked; judged on its own evidence.

### 4.7 Grace, payout credits, accounting and pause
- **Grace:** only a defeat grants `_grantChallengeGrace`.
- **Accounting:** for every exit, `payout + treasury share = D`. A raise moves value from payout to treasury. The invariant `balance = Σ active and pending deposits + treasuryArrears + Σ escapePayoutCredits` (in gwei) is preserved.
- **Bounded pause:**
  - `whenExitsOpen` is `!paused || block.timestamp ≥ pausedAt + maxPauseDuration`.
  - `pause()` additionally requires `lastUnpausedAt == 0 || block.timestamp ≥ lastUnpausedAt + PAUSE_COOLDOWN`, else `PauseCooldown()`.
  - So each pause blocks exits for at most `maxPauseDuration`, and every unpause leaves at least 1 day before the next pause. Paused time still extends `_claimableAt`, and `claimExpired` stays blocked while paused.

**Pause matrix:**

| Function | While paused |
|---|---|
| `deposit`, `claimExpired`, treasury functions, `renounceOwnership` | blocked |
| `initiateEscapeWithdrawal`, `mutualClose` | blocked until `pausedAt + maxPauseDuration`, then open |
| `challengeEscapeWithdrawal`, `raiseEscapeConcession`, `finalizeEscapeWithdrawal`, `claimEscapePayout`, `retireClosedLeaf`, `cancelTreasuryChange`, ownership transfer | open |

### 4.8 Adapter
- **Generation.** `Groth16ProofAdapter` is regenerated by `compact::setup` (dev) or `examples/import_zkey.rs` (ceremony) from the VKs.
- **`_verifyRequest`:** 12 values, unchanged.
- **`_verifyWithdrawal`:** builds `uint256[16]`, ending `..., uint256(kind), nextNullifier, uint256(conceded), uint256(validUntil)`, with IC indexes 0–16.
- **Identity constants** (template and `IZkApiProofAdapter`):

  ```solidity
  bytes32 public constant CIRCUIT_ID_HASH     = 0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687; // keccak256("zkapi-v2-concession-v1"), 0xda0e8385
  bytes32 public constant REQUEST_VK_HASH     = <keccak256(request.vk bytes without header)>;     // 0xfe351488
  bytes32 public constant WITHDRAWAL_VK_HASH  = <keccak256(withdrawal.vk bytes without header)>;  // 0x7fcd0926
  ```

  `CIRCUIT_ID_HASH` identifies the statement. The VK hashes identify the setup, and so tell dev keys from ceremony keys.
- Function names are unchanged. The three mocks implement the three constants.

### 4.9 Gas and size (estimated; WP-B measures them and pins a gas snapshot)

| Operation | Today | New | Main components |
|---|---|---|---|
| `assertValidWithdrawal` | 296.8k | ≈312.6k | +2 public inputs |
| `initiateEscapeWithdrawal` (transaction) | 6.42–6.47M | ≈0.55–0.62M | 21k base, ≈12k calldata, 313k verify, 2×22.1k nullifiers, 5 pending slots (≈110k), 2 concession slots (44.2k), events |
| Defeat (transaction) | 6.29–6.35M | ≈0.33–0.40M | 281k verify, flag 22.1k, grace ≤22.1k, deletes (refunds) |
| Raise (transaction) | n/a | ≈0.33M | 281k verify, 2 slot updates, event |
| `mutualClose` | ≈6.4M | ≈0.40–0.45M | verify, nullifier, transfers |
| `finalizeEscapeWithdrawal` | 30–206k | ≈ unchanged | two extra slot deletes (refunds) |
| `claimExpired` | ≈6.10M | ≈0.06–0.15M | treasury push |
| `retireClosedLeaf` | n/a | ≈6.0M | `hash5` and pair path |
| `deposit` | ≈6.02–6.04M | unchanged | |

- **Size:**
  - Removing four Merkle call sites (escape, challenge, close, claim) saves about 1.5 KB.
  - The raise, `retireClosedLeaf`, the side mapping, three events, the kind, `validUntil` and pause checks add about 2.5 KB.
  - Net ≈16.3–17.3 KB at the protocol profile, with at least 7 KB of EIP-170 headroom. The adapter grows by about 0.3 KB.
- **Reproducible bytecode.** The protocol Foundry profile pins the exact solc version, `via_ir`, 10,000 runs, `bytecode_hash = "none"` and `cbor_metadata = false`, so the runtime code depends only on source, settings, immutables and linked addresses (§10.4).
- **Poseidon.** The library is unchanged. Relink the deployed library if its runtime codehash equals the compiled `Bn254Poseidon`. Only `deposit` and `retireClosedLeaf` call it now.

---

## 5. Server, settlement and challenger changes

### 5.1 Successor signing (`finalize_request`, `crates/zkapi-serverd/src/processor_v2.rs:2735-2879`)

**Anchor**
- `next_anchor = core::v2::next_anchor(&public.request_nullifier)`.
- Before the signing call, assert `next_anchor ∉ {0, 1}` and that it equals an independent recomputation inside the signing helper. On failure return `Internal` and never sign.
- Keep `δ = random_scalar()`, the clamp `charge = min(charge, solvency_bound)`, the transcript columns and `RequestResponseV2`.

**Settle, then sign (O7).** Every finalize path (`settle_openrouter_lease`, `settle_oa_org_lease`, `finalize_lease_fallback`, `finalize_never_delivered_lease`, `finalize_conceded_lease`) is split into two steps.
1. **`settle_charge`** computes the charge exactly as today and persists `settled_charge`, `settled_basis` and `settled_at` on the `nullifiers` row, which stays `Reserved`. The charge is fixed by the settlement deadline, as before.
2. **`sign_successor`** first runs `assert_request_unspent(N)` (`usedNullifiers(N)` at the latest block).
   - If the nullifier is unused, it signs and writes the `Finalized` transcript as today.
   - If it is used, it does not sign. It sets `exit_deferred_since` (first observation) and the lease status `exit_deferred`, and every sweep re-checks:
     - if the flag clears (the consuming exit was defeated), it signs with the persisted charge;
     - if the flag is still set at `exit_deferred_since + challengePeriod + 3600`, it sets the nullifier status `ExitedUnsigned` (terminal; no successor ever).
3. **Terminality:** every accepted lease reaches either a signed transcript or `ExitedUnsigned`, and its charge is fixed by the settlement deadline (G5).

**O1 invariant.** At most one signed successor per nullifier, always at the derived anchor, and never while the nullifier is consumed on chain.
- Write-once `finalize` (`UPDATE … WHERE status='Reserved'`) enforces "at most one".
- Unit tests prove that no path (`settlement reopen`, `rebind_reservation`, `reconcile_finalized_lease`) signs a second, different successor.

**Startup self-test.** It runs the finalize code path, including the anchor assertion, with an **ephemeral in-memory key** generated from OsRng and dropped afterwards. The production signer is never invoked.

**Dashboard.** Remove `next_anchor` and `blind_delta_srv` from the unauthenticated dashboard payload (`dashboard.rs`).

### 5.2 Admission (`validate_and_reserve`, `reserve_openrouter_lease`) and evidence

**Checks.** The existing checks and their order are unchanged. Request types, `api_request_binding`, the OA request ID and the double `assert_request_unspent` read are unchanged. Two checks are added.
- **Root freshness (O5).** The root poller reads the indexer root and the vault's `currentRoot()` at `latest`. Admission refuses with retriable `root_unavailable` when either:
  - the last refresh in which both values agreed is older than `root_max_staleness_seconds` (default 60); or
  - the two disagree.
- **Lease ceiling.** `--request-limit-max-usd-micros` (default disabled; **6,000,000 during the canary, and recommended permanently**) refuses a request whose `limit_micro_usd(solvency_bound)` exceeds it. This bounds the operator's per-request exposure and is not needed for G1.

**Evidence table** (append-only; created in `nullifier_store.rs`):

```sql
CREATE TABLE IF NOT EXISTS request_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nullifier TEXT NOT NULL, client_request_id TEXT NOT NULL,
  solvency_bound TEXT NOT NULL,                       -- decimal u128
  request_inputs_json TEXT NOT NULL,                  -- serde RequestPublicInputsV2
  proof_blob BLOB NOT NULL CHECK (length(proof_blob) = 256),
  source TEXT NOT NULL CHECK (source IN ('reserve','rebind')),
  created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS request_evidence_nullifier ON request_evidence(nullifier);
CREATE TRIGGER IF NOT EXISTS request_evidence_no_update BEFORE UPDATE ON request_evidence BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER IF NOT EXISTS request_evidence_no_delete BEFORE DELETE ON request_evidence BEGIN SELECT RAISE(ABORT,'append-only'); END;
```

- **Writes.** `reserve_openrouter_lease` inserts the `nullifiers` row and the evidence row in one SQLite transaction. `rebind_reservation` appends a row with `source='rebind'`.
- **New `nullifiers` columns:** `settled_charge`, `settled_basis`, `settled_at` and `exit_deferred_since`; status adds `ExitedUnsigned`.
- **Retention:** keep evidence until the deployment is retired.

**Evidence read for the stale-device check.** `GET /v2/nullifiers/{N}/evidence` returns `{public_inputs, proof}` from the earliest `reserve` row at `N`, or `404`.
- It refuses (`410 published`) when `N` is consumed or challenged on chain, or appears as a `withdrawalNullifier` or `nextNullifier` in any vault event (from the indexer's published-nullifier table). It therefore never serves evidence for a nullifier that is public.
- It is rate-limited like recovery.

**Recovery.** `GET /v2/requests/{id}` and `/v2/nullifiers/{N}` add `nullifier_status ∈ {exit_deferred, exited_unsigned}`. When `N` is published on chain, they return the status only and omit `request_response`.

### 5.3 Clearance (`process_clearance`, `verify_clearance_ownership`)
- **Request type.** `ClearanceRequestV2C {withdrawal_nullifier, ownership_proof: {public_inputs: WithdrawalPublicInputsV2C, proof}}`, with `deny_unknown_fields`. The ownership proof is required: the server refuses to start on this deployment with `--allow-legacy-clearance`.
- **Checks:**
  - `kind == 2`, `next_nullifier == 0`, `conceded == 0`, `destination == [0;20]`, `withdrawal_nullifier == N`;
  - `now ≤ valid_until ≤ now + 3600`;
  - deployment triple and both keys; a root the server saw within its window, the vault's `currentRoot()`, or any root the vault ever held (`knownRoots`, Amendment A1); Groth16 verification.
- **Unchanged:** `NullifierUsed` if `N` has any non-`ClearanceReserved` row; sign `M_clear(pv, chain, vault, N)`; permanent `ClearanceReserved` row; the `ClearanceResponseV2` response.

### 5.4 Challenger evidence policy (`zkapi-challenged`; `watcher.rs`, `challenge_service.rs`, `challenge_status.rs`)

**Tracking**
- `PendingChallenge` gets `next_nullifier`, `state_balance`, `conceded` and `attempt {nonce, action ∈ {Raise{amount}, Defeat}, digest, tx}`. The action and digest are persisted per attempt.
- Each poll reads `pendingWithdrawals(noteId)` (6 words, strict) and `pendingConcessions(noteId)` (`0xf8ffe6e0`, 3 words, strict) **at the same block tag**.
- `scan_events` reads `EscapeWithdrawalInitiated` (5 words), `EscapeConcessionRecorded`, `EscapeConcessionRaised` and `EscapeWithdrawalChallenged`.
- `/v1/escapes/pending` adds `next_nullifier`, `state_balance` and `conceded`.

**Evidence source.** `request_evidence`, opened read-only. Every candidate is re-verified locally with `RequestVerifier`; `request_nullifier` and the deployment fields are checked against the vault.

**Ω(N), the amount owed for the request at the escaped nullifier**

| Row at `N` | Ω |
|---|---|
| `Finalized` | `charge_applied` |
| `exit_deferred`, `ExitedUnsigned`, or `Reserved` with `settled_charge` | `settled_charge` |
| `Reserved`, possibly delivered (key issued and `delivered ≠ Some(false)`; unreadable lease row; cancelled with a delivered key), not settled by `deadline − raise_lead_seconds` | `solvency_bound` |
| `Reserved`, never issued or never delivered; reservation with no lease row; `ClearanceReserved`; no row | 0 |

**Decision for each pending escape `(n, N, N⁺, B, c, deadline)`:**
1. **Defeat.** If any verified evidence row exists at `N⁺`, whatever its lease status, submit `challengeEscapeWithdrawal(n, inputs, proof)`.
   - No indexer path and no live root are needed. Gas limit default 600,000.
   - `evidence_digest` is unchanged (noteId, field elements, proof).
2. **Raise.** Otherwise, once Ω is final (a settled charge), or at `deadline − raise_lead_seconds` at the latest: if `Ω > c` and `Ω − c ≥ raise_min_units` (default 0), submit `raiseEscapeConcession(n, inputs, proof, amount = Ω)` with the evidence row at `N` that has the largest `solvency_bound`.
   - Gas limit default 450,000.
   - `evidence_digest_raise = keccak("zkapi:v2c:raise-evidence\0" ‖ noteId_be32 ‖ to_field_elements() ‖ proof ‖ amount_be16)`.
3. Otherwise do nothing. This is the honest outcome.
4. **After a raise,** keep checking for evidence at `N⁺` until the deadline.

**Nonce lane and transitions**
- One signer and one nonce lane. Replacements may change fees only.
- There is exactly one allowed digest transition: a **Defeat may replace an unmined Raise** at the same nonce. A Raise never replaces a Defeat.
- After a Defeat lands, pending raises for that note are dropped. A Raise that lands first does not block the Defeat, which goes on the next nonce.
- The transition is persisted, so it survives restarts.
- Fee caps are per transaction. At about 0.6M gas, the existing cap of about 1 ETH allows more than 1,600 gwei per gas.

**Why no raise-before-defeat.** A defeat and a raise are now the same kind of transaction: one request-proof verification plus a few storage writes, no Merkle path, no indexer and no root race. A raise sent first adds no protection against any failure the defeat has, and it can delay the defeat on the nonce lane. The transition rule covers a raise that is already in flight.

**Miss accounting and alarms**
- **Missed defeat:** verified evidence at `N⁺` existed before the deadline and the escape finalized.
- **Missed raise:** `Ω > conceded` at finalization.
- **Metric:** `escapes_finalized_with_successor_evidence_total`.
- On a missed defeat, if `--retire-on-miss` is set (default on), the challenger calls `retireClosedLeaf(n, siblings)` after finalization. This bounds post-exit service from the user's newest state (§7.4).

**Budget.** The gas float is sized for `⌈m/2⌉` defeats per note (§4.6), at most 64 concurrent escapes, and a 20% margin.

**Startup checks**
- The existing G5 check: `ttl + grace + settlement_deadline + 2·poll + 600 ≤ challengePeriod/2`.
- The raise check: `ttl + grace + settlement_deadline + raise_lead_seconds + 4·poll + 1200 ≤ challengePeriod`.
- The loaded `.vk` hashes (header stripped) equal the adapter's `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH` and the deployment manifest.
- CI runs both checks over the documented mainnet, Sepolia and drill parameter sets (§10.4).

**Signer sidecar** (`docker/aws/signer/signer.mjs`): allowlist the new `challengeEscapeWithdrawal`, `raiseEscapeConcession` and `retireClosedLeaf` ABIs and drop the old challenge ABI.

### 5.5 Indexer, store binding, probes and status
- **Indexer** (`crates/zkapi-indexerd/src/poller.rs`).
  - The tree is append-only plus retirements: `NoteDeposited` sets a leaf and `ClosedLeafRetired` zeroes one. Every other event's root field must equal the current computed root.
  - It decodes the new events and keeps a published-nullifier table for §5.2.
  - The zero-slot path endpoint is deprecated.
- **`deployment_binding`** gains `circuit_id`, `setup_id`, `request_vk_keccak256` and `withdrawal_vk_keccak256`. serverd, challengerd and indexerd refuse any mismatch.
- **`zkapi db init --deployment <manifest> --db <path> --proof-setup-dir <dir>`** (new CLI command). It creates the schema, the `request_evidence` triggers and `deployment_binding`. challengerd's `open_read_only` required-schema list adds `request_evidence`, the new `nullifiers` columns and the new binding columns, and fails startup with "run `zkapi db init` first" otherwise.
- **Startup probes** (serverd and challengerd), each failing closed:
  - `CONCESSION_ESCAPE_VERSION() == 1`, `ROOT_HISTORY_WINDOW() == 86400`;
  - adapter `CIRCUIT_ID_HASH()` and both VK hashes equal the local values;
  - vault, adapter and Poseidon codehashes equal the deployment manifest.
- **`/health` and `/v1/attestation`** add `circuit_id`, `setup_id`, `exit_concession: 1` and `settlement_window_seconds`. Clients treat these as informational and use the build-pinned values (§6.4).
- **Adversary modes.** A cargo feature `adversary` (test and acceptance builds only) adds `--adversary {withhold, born-spent, reuse-anchor, random-anchor, overcharge, lie-expired, hang}`. `hang` holds connections open, drips bytes and returns 429 or 5xx with long `Retry-After`. CI asserts that release binaries reject the flag.

---

## 6. Client changes (SDK/WASM, Rust companion wallet, clientd)

### 6.1 What a successor must satisfy before install
The checks run in `complete_response` (browser `zkapi-browser/src/lib.rs`; companion `wallet_v2.rs`).
- **S1.** `response.client_request_id == journal.client_request_id`, `response.request_nullifier == journal.nullifier`, and `journal.nullifier == nullifier(s, note_id, current_anchor)`.
- **S2.** `response_hash` equals the hash of `response_payload`.
- **S3.** `charge_applied ≤ bound_at_state`, and the journal's `solvency_bound`, when present, equals `bound_at_state`.
- **S4.** `next_anchor == next_anchor(journal.nullifier)`.
- **S5.** `server_update(C + ε·H, charge, δ) == next_commitment`.
- **S6.** The Schnorr signature verifies under the build-pinned state key over `state_message(2, chain, vault, next.x, next.y, next_anchor)`.

**Install** (atomic; companion ordering in §6.2): `prev_anchor = τ`; `B -= charge`; `r = r + ε + δ (mod l)`; `τ = next_anchor`; `is_genesis = false`; `σ = sig`; `bound_at_state = 0`; archive disposition `installed`. A correctly signed response that fails S3, S4 or S5 is treated exactly like a withheld successor and archived as `invalid_successor`.

### 6.2 What to store, and write order

| Item | Browser | Companion |
|---|---|---|
| `bound_at_state: u128` (`serde(default) = 0`) | note state | `note_state.json` |
| `prev_anchor: Option<felt>` (`serde(default)`; missing ⇒ requests refused with `prev_anchor_missing`, exits allowed) | note state | `note_state.json` |
| `exit_lock {noteId, anchor, mode ∈ {mutual, escape}, since, released: [{kind, valid_until, conceded, txHash?}]}` | `runtime.exitLock` | `exit_lock.json` |
| Withdrawal record `{noteId, stateBalance B, concededAtInit c, boundAtState b, destination, validUntil, startBlock}` | `withdrawals` store | `prepared_withdrawal.json` |
| Ownership-proof-sent flag | existing | `oa-ownership-proof-sent.json` |
| Journal and archive | unchanged; new dispositions `invalid_successor`, `late_successor` | unchanged; never pruned |

**C2 write rule.** Before any request proof is transmitted at a state:
- if `bound_at_state == 0`, set it to `sb`;
- otherwise require `sb == bound_at_state` and refuse with `bound_fixed_at_state`.

**Write order.**
- **Browser:** the note state, journal and archive record are written in one IndexedDB transaction, then the request is transmitted.
- **Companion request:** (1) fsync `note_state.json` with `bound_at_state`; (2) fsync `pending_journal.json` and the archive record; (3) transmit.
- **Companion install:** (1) fsync the new `note_state.json` (bound 0, `prev_anchor`); (2) the archive disposition; (3) remove the journal.
- **Companion exit:** fsync `exit_lock.json` before generating any exit proof, and append each `released` entry before the proof leaves the process.

Archive eviction and compaction never touch `bound_at_state`. `N_k` and `N_{k+1}` are derived, not stored.

### 6.3 Request-side rules
- **C1 (one lock).** Request preparation, successor installation and every exit decision run under one lock: the browser's existing Web Lock `'zkapi-wallet:active-runtime'`, and in the companion a new process-wide `WalletLock` mutex wrapping `prepare_request`, `recover_*` and `complete_response`, and every withdrawal route. Request preparation reads `exit_lock` under that lock.
- **C2.** One bound per state (§6.2).
- **C3 (freeze).** While `exit_lock` is held, the client creates no request proofs. The only proofs it may create are those of the lock's mode at the lock's state:
  - mode `mutual`: at most one kind-2 ownership proof, plus kind-1 close proofs;
  - mode `escape`: kind-0 proofs with any `c ∈ [0, bound_at_state]`.
- **C4 (near expiry).**
  - Refuse new requests with `note_near_expiry` when `now + W + 900 + 3600 > must_initiate_by`.
  - `W` is the build-pinned `settlement_window_seconds` and `must_initiate_by` is defined in E0.
- **C5.** Never request from a state after its ownership proof was sent.

### 6.4 Exit decision and choice of the conceded amount

**E0 (constants and timing; nothing here depends on operator data):**

| Name | Value |
|---|---|
| `CALL_TIMEOUT` | 20 s per operator HTTP call in exit mode, covering connect and full body. Timeout, 5xx and 429 all count as unreachable, and `Retry-After` is ignored. |
| `RECOVERY_BUDGET` | 120 s for one E1 pass |
| `E_low` | `expiry_ts`. Raised to the minimum of the two `effectiveExpiry` reads only when the user configured an exit RPC and both that RPC and the pinned RPC report a larger value. |
| `must_initiate_by` | `E_low − 43,200` |
| `W` | build-pinned `settlement_window_seconds` (mainnet 21,905) |
| `VALIDITY` | 10,800 s for kinds 0 and 1; 3,600 s for kind 2 |

`expiry_ts` is a lower bound on `effectiveExpiry`: `_claimableAt = activeExpiry + pausedDuration ≥ expiryTs`, and grace only raises it. So `must_initiate_by` can never be too late.

**E1 (recover, bounded).** Under C1, run one pass over the pending journal and every unresolved archive record at the current anchor: `GET /v2/requests/{id}` or `/v2/nullifiers/{N}`, within `RECOVERY_BUDGET`. Install any response that passes S1–S6, then repeat once from the new state. **Never exit from a state older than the newest installed one.** E1 is skipped when `now ≥ must_initiate_by`.

**Record classes (they match `zkapiRequestArchive.mjs`):**
- **Resolved-unreserved:**
  - `discarded_stale_root`, `discarded_expired_unaccepted` (which also covers the server's `superseded_unaccepted`) and `discarded_clearance_reserved`;
  - any transmitted record whose latest server reading is `unknown` and was taken at least 1,200 s after its `request_time` (the server rejects stale `request_time`, so it can no longer be reserved).
- **Unresolved:** `pending`, `evicted` (non-terminal and transmitted), `abandoned_for_escape`, and any record whose last reading is `reserved`, `exit_deferred`, `unavailable`, or `finalized` without an install.
- **Terminal:** `installed`, `superseded`, `invalid_successor`, `late_successor`.

**E2 (fresh state: `bound_at_state == 0`, or every released record at this state is resolved-unreserved).**
1. Set `exit_lock` (mode `mutual`) and rerun E1.
2. If `now ≥ must_initiate_by − 3600`, go to E4 with `c = 0`.
3. Otherwise: ownership proof (kind 2) → `POST /v2/withdraw/clearance` → close proof (kind 1) → `mutualClose`.
4. If the clearance answer is `NullifierUsed`, the server claims a reservation: switch to E3, using the newest released record's `created_at`.
5. Any other refusal or unreachability: switch the lock to `escape` and go to E4 with `c = 0`. If the server lied about a reservation, a raise can take at most `bound_at_state`.

**E3 (a released request is unresolved).** Do not attempt a clearance.
1. Wait until `T = min(min(settlement_deadline_reported, created_at + W) + 900, created_at + unsettled_request_escape_after_seconds, must_initiate_by)`. The knob keeps its default of 43,200 s and its clamp to 3,600–604,800.
2. At `T`, set `exit_lock` (mode `escape`) and rerun E1. If a successor installs and no exit proof was released yet, move the lock to the new state and go to E2.
3. Choose `c`:
   - **Lost ε.** If the server reports `Finalized` for `N_k` with a response passing S1, S2, S4 and S6 that cannot be installed (ε or journal lost): `c = min(reported charge, bound_at_state)`. This may be done at once, without waiting for `T`.
   - **At or after `T`:** `c = bound_at_state`. An honest, reachable operator would have delivered the successor by then. A dishonest one can raise to `b_k` anyway, and a full concession avoids publishing the request on chain.
   - **Forced early exit** (the user exits before `T`): `c = 0` by default. The honest challenger raises to the actual charge once it settles (settlement fits within the challenge period), and a dishonest operator can take at most `b_k`. The UI offers `c = b_k` instead, with the text "no on-chain record of your last request; may forfeit up to `b_k − actual charge`".
4. Server responses can only lower `c` below `bound_at_state`. Raises are capped by the user's own bound.

**E4 (escape).**
1. Get a path at a known root: from the indexer, with the root checked against `currentRoot()` or a known root, or from the §6.6 rebuild. No live-root race exists.
2. **Stale-device pre-check.**
   - `GET /v2/nullifiers/{N⁺}/evidence` (`CALL_TIMEOUT`).
   - If it returns a request proof whose `request_nullifier == N⁺` and which verifies locally under the pinned request VK, refuse with `device_not_newest` ("another device spent this state; restore the newest backup").
   - Errors and unverifiable answers are ignored.
3. Rerun E1 (single pass) immediately before proving. If a successor installs and nothing is released, restart at E2 on the new state.
4. Prove kind 0 with `(destination, c, valid_until = now + VALIDITY)`. Append to `exit_lock.released` before the proof is handed to any wallet, RPC, `eth_call` or `eth_estimateGas`.
5. **Advisory reads** (never blocking): `challengedNullifiers(N)` and `(N⁺)`; a simulation through the user's wallet provider, or the exit RPC if set. A disagreement shows a warning, and the user may submit anyway; a genuinely flagged nullifier reverts cheaply.
6. Rerun E1 once more before broadcast. If a successor installs now, a proof has already been released: archive it as `late_successor` and keep the lock (E6).
7. Submit. If `valid_until` passes before inclusion, re-prove (another release). Private orderflow is optional; a front-run copy of the proof lands the same exit.

**E5 (after initiation).**
- On `EscapeConcessionRaised`, update the displayed payout.
- After the deadline, call `finalizeEscapeWithdrawal`. On `EscapePayoutDeferred`, call `claimEscapePayout`.
- **Payout matching.** Every matcher accepts a finalized or credited amount `f'` iff:
  - `f' == B − c_final`, where `c_final` is the maximum of `concededAtInit` and every `EscapeConcessionRaised.conceded` for the note between initiation and finalization; and
  - `B − b ≤ f' ≤ B − concededAtInit` when `b` is known.

  If `f' < B − b`, the client records `concession_exceeded_bound` (an alert) and still closes the record. This applies to every SDK matcher (`zkapiClient.js` near lines 2375, 2771, 3208, 3576, 4237, 4475 and 5178) and to Go `validateWithdrawalReceipt`, `withdrawalStatusMatches` and the credit matcher.
- `EscapeWithdrawalChallenged` cannot happen to an honest, newest device. Surface it as `device_not_newest`.

**E6 (lock release).** The lock is released only when one of these holds:
- the note is `Closed`;
- no kind-0 or kind-1 proof was ever released and the user cancels;
- every released kind-0 or kind-1 proof is dead: the finalized block's timestamp is greater than its `valid_until + 900`, and the note is `Active` with no pending exit.

On release, rerun S1–S6 on every `late_successor` at the lock's state and install it, resetting the bound, if it passes. A landed exit is always one the client chose, because C3 kept the client from spending any successor while a released proof was live.

**E7 (exit kit; browser).**
- `exportExitKit({passphrase})` produces `zkapi-exit-kit-v1`: PBKDF2-SHA256 with 600,000 iterations and a random salt, then AES-256-GCM. The contents are:
  - the `trusted_deployment` profile;
  - `s`, `note_id`, `D`, `expiry`, `B`, `r`, `τ`, `τ_prev` and `σ`;
  - `bound_at_state`, `state_seq` and `exported_at`.
- The UI offers it at deposit and shows a "backup out of date" indicator after each install.
- `zkapi-walletd exit-kit escape --kit <file> --destination <addr> [--rpc <url>] [--conceded <units>]` runs E4 with the companion's bundled keys and the codehash pins. It prints the target and calldata, or submits with a key the user supplies.
- The browser host option `provingKeysBaseUrlOverride` lets exits fetch keys elsewhere; SHA-256 pins still apply.

**Lost or stale data.**
- If `bound_at_state` is unknown, escape with `c = 0`; raises are capped at the largest bound that device created.
- A stale kit or device is caught by the E4 pre-check when the operator serves evidence. Otherwise the escape is defeated: it costs gas, and the note returns to `Active` with grace.

The browser's `transmitted_anchor_escape_unsafe`, `anchor_challenged` and `receipt_journal_missing` paths, and `transmittedAnchorGate` and `transmittedAnchorDecision`, are deleted on `main`.

### 6.5 SDK / WASM changes
- **WASM** (`zkapi-browser/src/lib.rs`):
  - `browser_circuit_id()` returns `"zkapi-v2-concession-v1"`, and a new `browser_setup_id()`.
  - New nullifier formula. `prepare_request` takes `prev_anchor`. `complete_response` adds S4, `prev_anchor` and the bound reset.
  - `browser_successor_nullifier(state_json)`.
  - `prepare_withdrawal(PrepareWithdrawalArgs {mode ∈ {"escape","mutual","ownership"}, destination, conceded, valid_until, merkle_siblings, clearance?})`. Ownership forces destination 0 and `c = 0`; mutual forces `c = 0`.
  - `browser_verify_request(public_json, proof_b64, vk_bytes)`.
  - `browser_tree_path_from_leaves(leaves_json, note_id)`.
  - Update the export-list test.
- **`sdk/wallet.js`:**
  - Selectors: `initiateEscapeWithdrawal 0xa38d62aa`, `mutualClose 0x72cd2e44`, `finalizeEscapeWithdrawal 0xff8f5585`, `raiseEscapeConcession 0xdd0064ba` (decode only), `challengeEscapeWithdrawal 0xda0ce43d` (decode only), `pendingConcessions 0xf8ffe6e0`, `CONCESSION_ESCAPE_VERSION 0x5e00b426`, `maxPauseDuration 0x64433d27`, `CIRCUIT_ID_HASH 0xda0e8385`, `REQUEST_VK_HASH 0xfe351488`, `WITHDRAWAL_VK_HASH 0x7fcd0926`.
  - `encodeWithdrawal` writes 16 tuple words, offset `17*32`, `len 256` and 8 proof words: 836 B.
- **`browserWalletRuntime.js`:**
  - `REQUIRED_CIRCUIT_ID = 'zkapi-v2-concession-v1'`. Profiles without `exit_concession: 1` are refused on `main`.
  - **Deployment verification** at init and before every deposit, through the injected wallet provider (the one that will sign) and the pinned RPC:
    - `keccak(eth_getCode)` for the vault, adapter and Poseidon library equals the profile codehashes;
    - `proofAdapter()` equals the pinned address;
    - the getters `stateSigningKeyX/Y`, `clearanceSigningKeyX/Y`, `challengePeriod`, `noteTtl`, `maxPauseDuration`, `CONCESSION_ESCAPE_VERSION`, `ROOT_HISTORY_WINDOW`, the adapter VK hashes and `CIRCUIT_ID_HASH` equal the pins.
    - A mismatch refuses deposits with `deployment_mismatch`. Exits stay allowed.
  - Implements C1–C5, E0–E7, `exitLock` and the payout matchers. `assertOwnershipProof` checks kind 2.
  - Canary limits from the profile: a per-note cap, and an aggregate cap checked against the vault balance read through the wallet provider.
- **`zkapiClient.js`:** decoders for the new events and `pendingConcessions`. The 6-word `pendingWithdrawals` decoder is unchanged.
- **`zkapiRequestArchive.mjs`:** the dispositions and record classes of E1–E3. `assertAnchorAcceptsRequest` enforces C2 and C3.
- **New `sdk/services/zkapiTreeRebuild.mjs`** (§6.6) and `exitRpcUrl` (persisted per origin).
- **Worker:** loads `request.vk` with its SHA-256 pinned (`request_verifying_key_sha256`).

### 6.6 Merkle paths without the operator
- **Events.** `NoteDeposited(noteId, commitment, amount, expiryTs, newRoot)` sets `L_n`, and `ClosedLeafRetired(noteId, newRoot)` zeroes it. All other root-bearing events must report the current computed root.
- **Rebuild procedure:**
  1. Read the `finalized` block number through the user's exit RPC, or the pinned RPC.
  2. Fetch logs from `deploy_block` to the finalized block. Start with 2,000-block chunks; on a range or size error, halve the chunk (minimum 100) and retry.
  3. Apply the logs in `(blockNumber, logIndex)` order and build the sparse depth-32 tree in WASM.
  4. **After each event, require the computed root to equal that event's root.** The final root is the last event's root.
  5. No archive-state reads are needed. The proof's root stays usable at the vault for good (Amendment A1).
- **Cost:** roughly `#notes × (32 − log2 #notes)` hashes, a few seconds for 10k notes.
- **When:** whenever the indexer is unreachable or disagrees with the chain. The companion uses the same procedure with `zkapi_core` hashing.

### 6.7 Companion (Rust wallet) and clientd (Go)

**Companion** (`zkapi-client` `wallet_v2.rs`, `journal.rs`, `note_state.rs`; companion `service.rs`):
- the same S1–S6, C1–C5 and E0–E7, with `WalletLock`;
- `WITHDRAWAL_INPUTS_ABI = "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)"`;
- the durable write order of §6.2, and the `exit-kit` subcommand.

**New clientd routes, required for G1 for clientd users:**
- companion `POST /oa/v1/withdraw/escape/prepare`, `/submit`, `GET /status` and `POST /finalize`;
- Go routes and UI that sign and submit `initiateEscapeWithdrawal`, `finalizeEscapeWithdrawal` and `claimEscapePayout` through the existing address-withdrawal signing path. The mutual flow uses kind 2, then kind 1.

**Go `address_withdrawal.go`**
- `withdrawalSelector` comes from the new `mutualClose` signature.
- `withdrawalCalldata` writes 16 words, offset `17*32`, `len 256` and the proof.
- `validateSignedWithdrawal` (close) requires:
  - length `4 + 26·32 = 836`;
  - fixed words `0, 1, 2, 8, 9, 10, 11`, `12 == 1`, `13 == 0`, `14 == 0`, `16 == 17·32`, `17 == 256`;
  - word 15 (`validUntil`) within `[now, now + 10,800 + 300]`.
- The binding keccak covers `words[:16]` with words 3 and 15 blanked.

**New `escape_withdrawal.go`** applies the same structure plus:
- `word 12 == 0`, `word 13 ≠ 0` and `≠ word 11`;
- `word 9 + word 14 ==` the companion-reported `B`;
- `word 14 ==` the conceded amount shown to and confirmed by the user, which is at most the companion's `bound_at_state` unless the user chose zero.

**Go deployment checks.** At startup and before every deposit, Go verifies the three codehashes, the adapter address and the getters through the pinned RPC and the user's `--exit-rpc-url` (new flag and UI setting). Exits submit through the exit RPC when it is set.

**Go Poseidon is unaffected** (leaf and node hashing are unchanged).

---

## 7. Security argument

### 7.1 Honest-party definitions
- **Honest operator (O):**
  - **O1.** Signs a state only in `sign_successor` for a reserved request at `N`: at most once per `N`, at `next_anchor(N)`, with `charge ≤ sb`.
  - **O2.** Writes `request_evidence` in the reservation transaction and never deletes it.
  - **O3.** Checks `usedNullifiers(N)` before key issuance and again before delivery.
  - **O4.** Clears only a nullifier with no request row, against a valid, fresh kind-2 proof.
  - **O5.** Admits requests only at the exact current root, refreshed within 60 s and equal to the vault's `currentRoot()`.
  - **O6.** Runs the §5.4 policy within every window (A4).
  - **O7.** Never signs a successor while its predecessor nullifier is consumed on chain. It signs only if the consuming exit is defeated.
- **Honest client (U):** S1–S6, C1–C5, E0–E7. It keeps `s` secret and deposits only into a deployment whose codehashes match its pins.

### 7.2 Lemmas
- **L1 (only the owner proves).** A valid request or withdrawal proof at `N(s, n, τ)` yields, by A1 and A2, a witness with the same `(s, n, τ)` by collision resistance. Only the holder of `s` produces proofs at any nullifier of note `n`, and the operator never learns `s`.
- **L2 (the successor nullifier is fixed).** An escape at `(n, τ)` publishes exactly `N(succ(N(τ)))` (W8, W10).
- **L3 (spendable states).**
  - Q6 and Q6a: every state usable in a request is genesis (`τ = 1`, `B = D`) or has `τ = succ(N(τ'))` for some `τ'` of the same `(s, n)`.
  - Under O1, the signed states of note `n` are genesis and the unique `S_{i+1}` at `succ(N_i)` for each request reserved at `N_i`.
  - A signed state at any other anchor (a server bug) is unspendable by preimage resistance. Exiting from it pays its signed balance, which already deducts its charge.
  - Signed states at anchor 1 are unprovable.
- **L4 (notes are separate).** For `n ≠ n'`, nullifier chains are disjoint, even when `s = s'`.
- **L5 (no service after an exit, honest operator).** Let an exit from `S_j` land and never be defeated: an escape consuming `N_j` and `N_{j+1}`, or a close consuming `N_j`. Then the honest server delivers no key for note `n` after the exit lands, except a request at `N_j` reserved before initiation (which Ω charges). It also signs no successor beyond `S_{j+1}`.
  - Requests at `N_i` with `i < j` are `Replay` (by L3 they are already reserved).
  - At `N_j` and `N_{j+1}`, O3 refuses delivery.
  - `S_{j+2}` would need a successor of `N_{j+1}`, which O7 never signs while `N_{j+1}` is consumed, and an undefeated escape keeps it consumed forever.
  - For a close, `S_{j+1}` never exists, since O4 implies no reservation at `N_j` and `ClearanceReserved` blocks later ones.
- **L6 (bounded proof lifetime).** A kind-0 or kind-1 proof cannot land after its `valid_until` (§4.2, §4.5).

### 7.3 Goal 1: an honest client against any operator and owner
Let `S_k` be the newest installed state and `b_k = bound_at_state(S_k)`. The client exits with `c ≤ b_k` (E2, E3).
1. **Initiation succeeds.**
   - `usedNullifiers[N_k]` and `[N_{k+1}]` are set only by exits that name them, which need `s` (L1). By C3 and L6, every exit proof the client released can land only while the client is frozen, so any landed exit is the client's chosen one.
   - `challengedNullifiers[N_k]` is set only by a defeat with a proof at `N_{k+1}` (point 2).
   - `challengedNullifiers[N_{k+1}]` is set only by the defeat of an escape at `N_{k+1}`, which needs a withdrawal proof from `S_{k+1}` that the client never made.
   - The path needs only a known root (§6.6), so no deposit or front-run can invalidate a submission. A proof's root stays known for good (Amendment A1), and `valid_until` triggers a re-proof.
   - **Timing.** No operator call can delay the decision past `must_initiate_by` (E0 timeouts; E1 is skipped after it).
   - **Note still `Active`.** `must_initiate_by ≤ effectiveExpiry − 12 h`, `claimExpired` requires `Active` and `now ≥ _claimableAt`, and a pending escape cannot be swept.
   - **Pause.** If a pause is in force at `must_initiate_by`, exits reopen at `pausedAt + maxPauseDuration` at the latest. `claimExpired` is blocked while paused, paused time extends `_claimableAt`, and after any unpause `_claimableAt ≥ lastUnpausedAt + unpauseClaimGrace` (at least 1 day), with no re-pause for 1 day.
   - The client deposited only into a deployment whose immutables, adapter VKs and library match its pins, so the keys, `challengePeriod` and verifier are the expected ones.
   - Front-running cannot change `destination`, `c` or `valid_until`, because they are proof inputs.
2. **No defeat is possible.** A defeat needs a valid request proof at `N_{k+1}`, which only the client can make (L1), and only from a state at `τ_{k+1}`.
   - S4 forces any installed successor of `S_k` to sit at `τ_{k+1}`, and `S_k` is the newest installed state.
   - C3 forbids requests once the lock is set. A successor that installs before release moves the exit to the new state (E2, E4), and one arriving after release is only archived.
   - This covers withholding, never finalizing, anchor 1, reused, random or foreign anchors (S4), phantom commitments (S5), overcharging (S3), lying or stalling responses (E0), and refused clearance.
3. **Raises stay within the bound.** Every request proof at `N_k` is the client's (L1) and carries `sb = b_k` (C2). The vault sets `newC = min(amount, sb, B_k) ≤ b_k`.
4. **Payout.**
   - `finalizeEscapeWithdrawal` is permissionless and open while paused. It pays `B_k − c' ≥ B_k − b_k`, or credits it to `escapePayoutCredits`.
   - For a mutual close (E2), the payout is `B_k`.
   - The total the user pays is at most `Σ_{i<k} Δ_i + b_k`. ∎

### 7.4 Goal 2: an honest operator against any user
Fix note `n`. By L3, the spendable signed states are `S_0 … S_m`, with `S_{i+1}` following the reserved `R_i` (`Δ_i ≤ sb_i`), plus possibly one reservation `R_m`. The note pays its user at most once. `owed(R_i) = Δ_i` for settled requests, and `owed(R_m) = Ω(N_m) ≥` its actual charge (§5.4).
- **Mutual close at `N_j`.** O4 implies no row at `N_j`, so `j = m` and nothing is reserved at `N_m`. W11 forces `c = 0`, so the payout is `B_m = D − Σ_{i<m} Δ_i`. After the close, L5 holds.
- **Escape from `S_j` that finalizes.**
  - Any request at `N_{j+1}` reserved before the deadline is in `request_evidence` (O2), and O6 defeats the escape. This includes one reserved after initiation: O3 refuses its key, but the reservation still counts as evidence.
  - So no request at `N_{j+1}` was reserved before the deadline. By L3, `j ≥ m − 1`. After the deadline, L5 rules out further service.
  - **`j = m − 1`:** `R_{m−1}` is settled with `Δ_{m−1}` (signed, or deferred by O7 with its charge persisted), and `S_m` was never spent. If `c < Ω = Δ_{m−1}`, O6 raises it with `R_{m−1}`'s proof. The payout is at most `B_m`.
  - **`j = m`:** if `R_m` was served, O6 raises to `Ω(N_m)`. Requests at `N_m` admitted before initiation but delivered after it are refused by the second O3 read, so their charge is 0. A lagging read that delivered anyway is covered by `Ω`. The payout is at most `B_m − Ω(N_m)`.
- **Defeat.** The note returns to `Active`, `N_j` is flagged permanently, and grace is granted.
  - Service the user took from newer states while the stale escape was pending was charged along the chain.
  - Re-escapes revert cheaply or are defeated again (§4.6), and each defeat flags a new nullifier. The note therefore ends in one of the cases above, or at expiry with `D` going to the treasury.
- **Signing bugs.** A successor signed at a non-derived anchor is unspendable (L3), and exiting from it pays its already-charged balance. G2 does not depend on the server's anchor derivation.
- **If A4 fails** (a missed defeat of an exit from a stale `S_j` while the user holds `S_m`):
  - The operator loses at most the stale payout `B_j − c'` plus service the user takes later from `S_m` with the leaf in place. The latter is at most `B_m` and stops when the challenger calls `retireClosedLeaf` (O5 then rejects every proof built on an older root).
  - Today's bound (with leaf removal at initiation) is `B_j − c' − B_m`. The difference is the price of about 6M gas less per exit and per defeat, and it applies only when A4 fails.

### 7.5 Case matrix

| Case | Outcome | Why |
|---|---|---|
| Honest operator, honest user, nothing in flight | Mutual close at `B_k` (or escape with `c = 0` if the server is unreachable) | E2 |
| Honest operator, request in flight | Wait to `T`; the successor installs; the user exits from `S_{k+1}` | E1–E3 |
| Honest but crashed or slow; G5 holes | E2: `c = 0`, and nothing is raised if nothing was reserved. E3 at `T`: `c = b_k`, and the honest challenger raises nothing | §5.4 |
| User forces an early exit | `c = 0`; the honest challenger raises to the actual charge | E3 |
| User lost ε, server finalized | `c = min(reported Δ, b_k)` | E3 |
| Malicious operator withholds, never finalizes, or refuses clearance | Escape at `T` with `c = b_k`; payout `≥ B_k − b_k` | §7.3 |
| Operator stalls HTTP (hang, long `Retry-After`) | Timeouts; E1 is skipped at `must_initiate_by`; the escape lands before expiry | E0 |
| Pinned RPC lies about expiry or flags | `E_low` comes from `expiry_ts`; pre-checks are advisory | E0, E4 |
| Fake or backdoored deployment (keys, adapter, library) | Codehash and getter pins refuse deposits | §6.5 |
| Born-spent successor at τ = 1, reused anchor, random anchor | S4 rejects it (treated as withheld). The circuit refuses τ = 1, and a random anchor is unspendable (Q6a) | L3 |
| Phantom successor or overcharge | S5 or S3 fails; treated as withheld | L1 |
| Reissued successors | Both share `N_{k+1}`; O1 forbids reissue | L3 |
| Several request proofs per state with different bounds | C2 keeps one bound for an honest client. A modified client is raised at most to the largest bound it released | §4.4 |
| Unaccepted, expired or `stale_root` requests | Counted in `b_k`. A lie gains the operator at most `b_k` | C2 |
| Malicious user exits from `S_j` after spending `S_{j+1}` | Defeated; `N_j` flagged; re-escapes per §4.6 | §7.4 |
| Malicious user under-concedes | Raised in place to `Ω` | §4.4 |
| User spends `S_{k+1}` during their own escape | O3 refuses; the reservation is evidence; defeat | §7.4 |
| Abandoned exit proof replayed later | `ProofExpired` after `valid_until`; the lock held until then | L6, E6 |
| Successor arrives late | Switch to it if nothing was released; otherwise archive it and install after lock release | E4, E6 |
| Post-exit zero-charge successor chain | O7 signs nothing beyond `S_{j+1}` | L5 |
| Ownership proof submitted on chain | Reverts `WrongWithdrawalKind` | §4.2 |
| Ownership proof sent, clearance refused | Publishes `N_k` only; `NullifierUsed` leads to E3, otherwise escape with `c = 0` | E2 |
| Concurrent escapes; close racing an escape | One pending exit per note; the first to land wins | |
| Indexer down or lying | Rebuild from logs with per-event root checks | §6.6 |
| Deposit or root front-running | No effect: exits need only a known root | §4.2 |
| Expiry | A pending escape is not swept; clients start at least 12 h early, from local data | §7.3 |
| Owner pause | Exits reopen after `maxPauseDuration`; cooldown of 1 day; the expiry clock is paused | §4.7 |
| Stale device or stale backup | Pre-check refuses on verified evidence; otherwise defeated (gas only) | E4 |
| Browser host gone or hostile | Exit kit and companion CLI (A6) | E7 |
| Third party holding transmitted proofs | Can raise at most to `b_k`; cannot defeat an honest exit | L1 |
| Missed defeat (A4 fails) | Bounded loss; `retireClosedLeaf` | §7.4 |
| Setup trapdoor known to an attacker | G1 and G2 fail | A2, §10.2 |

---

## 8. Privacy analysis

| Observer / event | Today | New | Change |
|---|---|---|---|
| Server, each request | root, time, `sb`, `N`, tag, `C_anon` | identical public inputs | none |
| Request anonymity set | active notes at the root with `expiry ≥ time`, `B ≥ sb` | Closed notes stay as leaves but can produce no acceptable request (L5), so the effective set is unchanged. `B ≤ D` and the anchor chain hold for every honest state | none |
| Successor anchor | random, known to the server | `succ(N_k)`, computable from `N_k` | Linking `R_{k+1}` to `R_k` still needs `s`. Anyone who learns `s` can link the note's whole request log (documented) |
| Notes sharing a secret | share every genesis nullifier | disjoint | better |
| Escape from a fresh state | `note_id`, `B`, destination, `N` | adds `N⁺` (never used), `c = 0` and `valid_until` (proof time to within 3 h) | negligible |
| Escape with `c = b_k` at `S_k` | (not completable) | `N_k` links the last request `R_k` to `note_id` and the destination **for the server and gateway**. `c` publishes `R_k`'s tier. `D − B_k` gives earlier totals | Exit-only, exiting note, last request. Recovery and evidence endpoints stop serving `N_k`'s data once it is published |
| Escape with `c = 0` and a raise | | The raise publishes `R_k`'s public inputs (time, tier, root, `C_anon`, tag) on chain | Public linkage of the last request; it is the user's choice (E3 explains the trade-off) |
| Operator colluding with the provider | | key→prompt mapping for `R_k` | prompt linkage of `R_k` only, at exit; documented |
| Defeat | publishes the request at `N` | publishes `R_{k+1}` | only for users exiting a superseded state |
| Stale-device pre-check | | reveals `N⁺` to the server just before broadcast | `N⁺` becomes public at initiation anyway. If the proof later expires unlanded, a later request at `N⁺` is linkable to that query by timing and IP (documented) |
| Ownership proof (kind 2) | server sees `note_id`, `B`, destination, `N` | `note_id`, `B`, `N`; destination 0; no `N⁺`; fresh `valid_until` | better |
| Mutual close | `note_id`, `B`, destination, `N` | same | none |
| Exit kit | | contains `s`; encrypted with the user's passphrase; never uploaded | user-held |
| Codehash checks | | Reads through the user's wallet provider reveal interest in the vault to that RPC | the same as using a wallet at all |
| Dashboard | `next_commitment`, `next_anchor`, `δ` | `next_anchor` and `δ` removed | better |

New linkage stays confined to exits, the exiting note and its last request. Clients prefer waiting and mutual close, which link nothing new.

---

## 9. Residuals closed and residuals remaining

### 9.1 Closed
- **R5 (withholding operator).** Concession exit, defeated only by successor evidence.
- **Born-spent successors:** anchor 1 (circuit), reused anchors (client) and random anchors (client and circuit).
- **R1:** `B ≤ D`.
- **R2:** kind gating.
- **R6:** note-bound nullifiers.
- **Vestigial tag.**
- **Key headers per kind and setup;** on-chain circuit and setup identification (`CIRCUIT_ID_HASH`, VK hashes).
- **Server anchor bugs:** unspendable non-derived successors.
- **Replay of abandoned exit proofs:** `valid_until`.
- **Unbounded owner pause:** `maxPauseDuration` plus cooldown.
- **Unverified deployments:** codehash pins checked by clients.
- **6M-gas exits and root-race griefing:** append-only tree.
- **Operator-side evidence holes:** `request_evidence`.
- **Post-exit zero-charge successor chains:** O7.
- **Unbounded server root staleness:** O5.
- **Exits depending on operator HTTP, indexer, RPC or host timing:** E0, §6.6, exit RPC, exit kit.
- **clientd has no escape path.**
- **`Deploy.s.sol` literals; adapter not CI-checked** (§10.4, §11).

### 9.2 Remaining (documented)
- **Chain censorship.**
- **Operator liveness (C12).** One cheap transaction per escape that needs action.
- **Strategic under-conceding on L1.** A raise costs about 0.33M gas (about $10 at 10 gwei and $3,000/ETH) against tiers of $1–6. A modified client may bet that the operator will not raise. Operators may set `raise_min_units`.
- **Forced early exits with `c = b_k`.** These forfeit `b_k − Δ`; the client asks the user to choose this.
- **Exit-time linkage of the last request** (§8).
- **Leaked state key.** Forged states, each capped at `D`.
- **Leaked clearance key.** A dishonest owner can close at a spent state.
- **R3, permanent clearance reservations.** Harmless under C5.
- **Setup trust.** An honest public phase 1 that the ceremony actually used, and at least one honest phase-2 contributor (A2).
- **Stale-backup restore without operator evidence.** The note is defeated; the user loses only gas, but must find the newest state.
- **A4-failure bound.** Includes post-exit service until `retireClosedLeaf` (§7.4).
- **Owner pause** up to `maxPauseDuration` (mainnet 45 days) per cycle.
- **Browser host dependence** without a current exit kit (A6).
- **Request timing correlation.**
- **The legacy vault** keeps withholding, the burn and the pause defects until drained (§10.7 E).

---

## 10. Migration plan

### 10.1 Versioning, circuit and setup identifiers
- **`CIRCUIT_ID = "zkapi-v2-concession-v1"`** (`compact.rs:32`), the statement identity.
- **Key headers carry the setup:** `b"zkapi-v2-concession-v1/<setup_id>/<kind>\0"`, with `kind ∈ {request, withdrawal}` and `setup_id ∈ {dev, mpc-1}`.
  - `decode_compressed(bytes, KeyKind) → (key, setup_id)` rejects a wrong kind or circuit.
  - **Release builds accept only `RELEASE_SETUP_IDS = ["mpc-1"]`.** Test builds (`--features dev-setup`) also accept `dev`.
  - The drill vault and all CI use `dev`.
- **`protocol_version` stays 2.** Request wire types stay `*V2`. The new withdrawal and clearance types are `WithdrawalPublicInputsV2C`, `ClearanceRequestV2C` and `ClearanceOwnershipProofV2C`.
- **Setup directories:** `protocol/setup/v2-concession/` (ceremony, `mpc-1`) and `protocol/setup/v2-concession-dev/` (dev). `manifest.json` records:
  - `setup_id`, `reduction: "circom"`, `files` (SHA-256 of all four keys), `vk_keccak256` per kind;
  - `ptau_sha256` and `transcript_sha256` (ceremony).
- **Vault:** revision 3 with capability `exit_concession: 1` (non-monotone). On `main`, profiles without it are refused.
- **Branches:**
  - `release/v2-note-bound` is cut at `ac9be63`, with tag `setup-v2-note-bound-v1`. It carries security fixes and the legacy re-cuts of §10.7 E.
  - `main` carries only the new circuit.

### 10.2 Setup and ceremony
- **The decision is made before WP-A: S1 (MPC phase 2) is mandatory for mainnet.** `CircomReduction` provers are used from the first commit, and the dev setup uses the same reduction (§3.4).
- **G-SETUP steps:**
  1. **Export.** `examples/export_r1cs.rs` builds the circom `.r1cs` from arkworks `ConstraintMatrices` after `OptimizationGoal::Constraints` and `cs.finalize()`. Wire order is `[one, public inputs in order, witnesses]`.
  2. **Fidelity gate** (CI, and again on the frozen circuit):
     - (a) parse the file back (ark-circom R1CS reader) and assert A, B, C, `num_instance`, `num_witness` and the instance order equal the in-memory matrices;
     - (b) for every WP-A negative case, generate the full unsatisfying assignment and assert that an independent evaluator over the exported file rejects it;
     - (c) after the ceremony, assert that the matrices from `ark_circom::read_zkey` equal the synthesized matrices for both circuits.
  3. **ptau.** A public BN254 powers-of-tau of at least 2^16, listed in `zkapi_proof::ceremony::PUBLIC_PTAU` (the Hermez `powersOfTau28_hez_final_16.ptau` to `_27.ptau`) and checked against the Blake2b-512 that the snarkjs README publishes for it, then pinned by SHA-256 (`ptau_sha256`). An `mpc-1` import refuses any file not on that list; another public transcript is a reviewed change to the list. Each external reviewer downloads the file from its public source, not from the coordinator.
  4. **Contributions.** `snarkjs groth16 setup`, then at least 3 contributions, **at least 2 by parties not selected by the operator** (nominated by the external reviewers or a public call), then a public random beacon.
  5. **Publication.** The transcript, `snarkjs zkey verify` output and all hashes.
  6. **Import.** `examples/import_zkey.rs` writes arkworks keys with the `mpc-1` headers and regenerates the adapter with the VK hashes.
  7. **Proving gate before the keys are published.** Using the imported keys, the `CircomReduction` prover and the Anvil-deployed adapter, run the mutate-each-public-input tests and the negative proving tests, plus positive proofs of every kind: genesis and signed; `c = 0` and `c > 0`; kind 1 and kind 2; a full 160-bit destination.
- **Fallback if S1 is short of contributors:** still S1, with at least 2 contributions from externally nominated parties plus the beacon. **Otherwise mainnet slips.** No single-party setup ever reaches mainnet or production Sepolia.
- **One setup serves Sepolia and mainnet** (`chain_id` is a public input). Never regenerate after a public deploy.

### 10.3 Artifacts and pins (all change together)
- **Protocol:** `compact.rs` (`CIRCUIT_ID`, headers, `Prover`, `setup()`, the adapter template with 16 values, IC 0–16, `CIRCUIT_ID_HASH` and VK hashes); `reduction.rs`; both setup directories; the generated `Groth16ProofAdapter.sol` plus `forge fmt`. `Bn254Poseidon.sol` is unchanged.
- **SDK:**
  - `sdk/wasm/*` (reproducible build), `sdk/assets/proofs/{request,withdrawal}.pk`, and `request.vk`.
  - `sdk/assets/manifest.json`: `circuitId`, `setupId`, all file hashes, `sourceRevision`, `schema: 2`.
  - `sdk/assets/config/{sepolia,mainnet}.json` `trusted_deployment`:
    - `deployment_id`, `contract_address`, `deploy_block`, `circuit_id`, `setup_id`;
    - both `*_proving_key_sha256` and `request_verifying_key_sha256`;
    - `request_vk_keccak256`, `withdrawal_vk_keccak256`;
    - `vault_runtime_codehash`, `proof_adapter_address`, `adapter_runtime_codehash`, `poseidon_library_address`, `poseidon_runtime_codehash`;
    - `challenge_period`, `note_ttl`, `max_pause_duration`, `settlement_window_seconds`;
    - `vault_revision: 3`, `exit_concession: 1`, `clearance_ownership_proof: "required"`;
    - `canary: {per_note_max_wei, aggregate_max_wei, until}`;
    - `deployment_status` (`"not_deployed"` for a placeholder).
  - Literals: `sdk/build.mjs:12`, `scripts/sync-sdk-assets.mjs:17` (now `--network <n>`; skips `not_deployed` profiles), `zkapiWasmWorker.js:24`, `browserWalletRuntime.js:187`, `scripts/prove-browser-fixture.mjs:9`.
- **clientd:** `deployments/{sepolia,mainnet}.json` with the same pins (the existing `deployment_evidence.*_runtime_keccak256` fields are now **checked**), `deployments.go:98`, `deployments_test.go:58,362`, `testdata/browser-profiles/*`; remove the manifest-migration exceptions for the new ID.
- **Ops:** `docker/aws/run-daemon.sh:18`, `deployment.env.example:2`, `run-daemon.test.mjs:30`, `signer.mjs:10`, `Deploy.s.sol`, `scripts/v2-acceptance.mjs:389`, `v2_acceptance_wallet.rs:80`.
- **Fixtures:** `vault-challenge.json`, adapter-test literals, `ZkApiVaultGroth16.t.sol:30`, and the selector and topic pins in `NativeEthVault.t.sol:348-378`.
- **Reproducible WASM** (mainnet gate): `rust-toolchain.toml` pinning `1.99.0` with `wasm32-unknown-unknown`; `RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/src"`; `wasm-bindgen-cli 0.2.117`; a CI job that rebuilds and compares against the manifest.
- **Key URLs:** new keys are served under a new `publicPath`.

### 10.4 Vault and adapter deployment (Sepolia, then mainnet)
1. **`Deploy.s.sol`.**
   - Require a `POSEIDON_ADDRESS` whose runtime codehash equals the compiled library and link it; otherwise deploy a fresh library and record that address.
   - Deploy the adapter, then the vault with 11 constructor arguments.
   - Assert `adapter.CIRCUIT_ID_HASH()` and both VK hashes against the manifest.
   - Write the actual linked addresses and the three runtime codehashes.
2. **Expected codehashes.** `scripts/expected-codehashes.mjs` computes the expected runtime code:
   - from the pinned-compiler `deployedBytecode`;
   - with the library link applied;
   - with `immutableReferences` filled from the constructor arguments (keys, periods, adapter address, `maxPauseDuration`, `requestChargeCap`, and the derived `treasuryChangeDelay` and `unpauseClaimGrace`).

   CI publishes the result so third parties can audit any profile against the ceremony transcript.
3. **Parameters.**

   | Parameter | Mainnet | Sepolia production | Sepolia drill |
   |---|---|---|---|
   | `challengePeriod` | 172,800 s | 43,200 s | 7,200 s |
   | `noteTtl` | 30 d | 30 d | 1 d |
   | `maxPauseDuration` | 45 d | 7 d | 14,400 s |
   | `requestChargeCap` | 50,000 | 50,000 | 50,000 |
   | server ttl / grace / settlement deadline / poll | 300 / 5 / 21,600 / 2 | 300 / 5 / 14,400 / 2 | 300 / 5 / 1,800 / 2 |
   | `--raise-lead-seconds` | 21,600 | 21,600 | 1,800 |
   | G5 check (`≤ cp/2`) | 22,509 ≤ 86,400 | 15,309 ≤ 21,600 | 2,709 ≤ 3,600 |
   | Raise check (`≤ cp`) | 44,713 ≤ 172,800 | 37,513 ≤ 43,200 | 5,113 ≤ 7,200 |
   | Setup | `mpc-1` | `mpc-1` | `dev` (test build) |

   Use fresh state and clearance keys, verified off chain (on the curve, in the prime-order subgroup, distinct).
4. **Post-deploy checks** (scripted, recorded in the manifest): `PROTOCOL_VERSION`, `CONCESSION_ESCAPE_VERSION`, `ROOT_HISTORY_WINDOW`, `maxPauseDuration`, the keys, the periods, the adapter constants, and the three codehashes equal to the CI-published values.
5. **CI:** the `src` adapter equals the formatted generator output; its constants equal `manifest.json`; the parameter-set test runs both checks on every row of the table above.

### 10.5 Side-by-side vaults and client builds (no multi-circuit loader)
- **Browser.**
  - The legacy build is served at its current `publicPath` from the config-only re-cut (§10.7 E). The new build is served at `/zkapi/v2c/` on the same origin.
  - Both share IndexedDB `zkapi-browser-wallet-v1` version 3 and the lock. `reload()` refuses another deployment's runtime.
  - **Host recipe:**
    - two package entries: `"zkapi-sdk-legacy": "git+…#v0.1.<n>"` and `"zkapi-sdk": "git+…#v0.2.<n>"`;
    - each package resolves its own relative `../wasm/zkapi_browser.js`;
    - a tiny host loader calls `readBrowserWalletHoldings()` and `import()`s the legacy entry while a legacy runtime holds an open note, and the new entry otherwise.

    WP-D ships a sample host that builds both and tests this.
- **`main` staging.** Until the mainnet vault exists, `mainnet.json` is a placeholder with `deployment_status: "not_deployed"`, `circuit_id`, `setup_id` and the pk hashes. `buildBrowserSdkAssets` refuses it with `deployment_not_deployed`, and CI asserts that refusal in place of `build:mainnet` until Phase C.
- **clientd.** The new release pins only the new deployment. **When a legacy note is open, it warns and links to the legacy release instead of refusing to start;** state directories are per deployment ID, so the two never collide. The legacy release stays installable as a versioned formula.
- **Stacks.** Each vault has its own serverd, challengerd, indexerd, DB, signer key, hostname and gateway limits. `deployment_binding` makes cross-binding impossible.

### 10.6 clientd companion delivery
- **Primary: Option C, re-vendor into this repository.**
  1. Add `crates/zkapi-companion` (binary `zkapi-walletd`), ported from `20aa542`'s `crates/zkapi-clientd` plus `companion.patch` and the `client` subcommand of `crates/zkapi-cli`. Keep the exact arguments Go passes, and add the `exit-kit` subcommand.
  2. Add `crates/zkapi-auth` from `20aa542`.
  3. Replace `protocol/rust/crates/zkapi-client` with upstream `8b2d4e3` plus `protocol-transport.patch`. Drop `zkapi-crypto` and the STARK paths, port the `wire.rs` additions, and implement §6.7.
  4. **Packaging.**
     - `packaging/zkapi-source.env` holds `ZKAPI_SOURCE_COMMIT`; the old pins and patches are deleted.
     - `prepare-zkapi.sh` checks out this repository; `verify-zkapi-source.py` checks the commit and a clean tree.
     - `build-native.sh` runs `cargo build --release --locked -p zkapi-companion --bin zkapi-walletd` and copies `protocol/setup/v2-concession/.`.
     - **`test-companion.sh` runs `cargo test -p zkapi-companion -p zkapi-auth` at the root and `(cd protocol/rust && cargo test -p zkapi-client)`**, because `zkapi-client` is in the excluded workspace.
     - `collect-release-notices.py` writes `build-info.json {source_commit}`.
  5. Companion integration tests run against this repository's serverd in-process.
- **Fallback: Option A′** (only if C slips). P′ and C′ are as specified before: a `server` feature left off in `build-native.sh`, the cross-source CI gate (proofs verify against this repository's VKs and the Anvil adapter, and the circuit files are byte-compared), and both pins bumped.
- **Go side (either option).** New `deployments/*.json`; the `deployments.go:98` literal; the warning-only legacy guard; `address_withdrawal.go`; `escape_withdrawal.go`; escape UI; `--exit-rpc-url`; codehash checks; payout matchers (§6.4 E5); and `bridge_version == 5` against the companion's `/oa/v1/status` (which reports `exit_concession: 1` and `setup_id`).

### 10.7 Ordered rollout

**Phase A: build and freeze**
1. Cut `release/v2-note-bound`.
2. Implement WP-A to WP-F on `main` with the `dev` setup and the `CircomReduction` prover. All suites must pass, including the adversarial and fidelity tests.
3. Freeze the circuits (`circuit-freeze-v2c`) and record constraint counts.
4. **External review.** Scope: circuit diff, reduction, R1CS export and zkey import, vault, adapter template, codehash derivation, challenger policy, client exit logic.
5. **G-SETUP** (§10.2), including both fidelity gates. Then replace the keys, regenerate the adapter, fixtures and pins, rebuild the WASM reproducibly, and publish the expected codehashes.

**Phase B: Sepolia**
1. **Drill vault** (dev setup, adversary-enabled test build, drill parameters). Scripted drills in `scripts/v2-acceptance.mjs --network sepolia-drill`:
   - honest flow;
   - withholding, then concession at `T`;
   - `hang`, with the escape landing before `must_initiate_by`;
   - born-spent anchor 1; reused anchor; random anchor (also unspendable by circuit); overcharge;
   - lying `expired_unaccepted`;
   - forced early exit with `c = 0`, then raise to `Δ`, then client state `closed`;
   - under-concession, then raise, then finalize and deferred credit, then claim;
   - stale exit after spending, then defeat, then `SupersededState`, then re-escape from `S_{k−2}` and defeat;
   - stale-device pre-check;
   - replay of an abandoned proof after `valid_until`;
   - late successor, then switch;
   - ownership proof on chain;
   - indexer down, then rebuild;
   - pause with an escape pending, then finalize; pause past `maxPauseDuration`, then escape; re-pause cooldown;
   - codehash mismatch profile refuses deposits;
   - missed defeat (challenger stopped), then `retireClosedLeaf`.
2. **Production Sepolia** (§10.4, `mpc-1`). Daemon order:
   1. indexer from `deploy_block`;
   2. `zkapi db init`;
   3. challengerd (own signer key; healthy, alarms armed);
   4. serverd.

   **The challenger must be healthy before the first deposit.**
3. Hosts publish the new Sepolia build at `/zkapi/v2c/` and the legacy Sepolia re-cut with `deposits: "closed"`.
4. Soak for at least 14 days with weekly drills on the drill vault.

**Phase C: mainnet**
1. Deploy, run the checks, and publish the manifest and expected codehashes.
2. Start the daemons in the order of Phase B step 2.
3. **Smoke tests with small notes:**
   - deposit, request, settle, mutual close;
   - escape with `c = 0` at a fresh state, then finalize;
   - a served request, then a deliberate escape with `c = 0`, raised to `Δ`, then finalize; assert that the client state is `closed`.
4. **Hosts publish the new mainnet build with the canary for 30 days:**
   - SDK per-note cap 0.25 ETH;
   - SDK aggregate cap 25 ETH (vault balance through the wallet provider);
   - server `--request-limit-max-usd-micros 6000000`.

   The canary protects honest SDK users and bounds the operator's per-request exposure; direct depositors bypass the SDK caps, as documented. In the same release, publish the legacy mainnet re-cut with `deposits: "closed"`.
5. **Announce the legacy service cutoff `X`** (the last transition note's expiry, before Phase C + 31 days; Amendment A2).
6. **Users.** New users deposit into the new vault. Legacy browser users are routed to the legacy build to close, then deposit. A legacy note with a request in flight waits for settlement; the operator publicly commits to finalizing every legacy lease and to running the legacy challenger.

**Phase D: clientd**
1. Release the new clientd once Option C and its escape route pass the §11 tests and a Sepolia drill.
2. **Release the legacy clientd point release** from `release/v2-note-bound`:
   - Go pins `deposits: closed` and refuses deposits;
   - an in-product fresh-state escape (companion `/wallet/withdraw` with mode escape) and finalize;
   - a documented CLI escape runbook for other cases.
3. clientd users close their legacy note with the point release, upgrade, and deposit.

**Phase E: drain and retire the legacy vault**
1. **Legacy re-cut** (both networks): same WASM, worker and key bytes; new configs with `deposits: "closed"`; regenerated config hashes in `manifest.json` and `sdk-assets.json`; same `publicPath`. A test checks that `browser-config.json` is fetched with `cache: 'no-store'`. Confirm that every host serves this revision.
2. **From `X`:** legacy serverd runs with `--admission closed`, refusing new requests with `deployment_retiring`. In-flight leases still settle, clearances for fresh nullifiers stay allowed, and the legacy challenger keeps running.
3. **Retirement condition:** every legacy note deposited before `X` is `Closed` or past `effectiveExpiry`, and the last challenge deadline has passed. This is bounded by `X + noteTtl + challengePeriod` with late notes, and is about `X + challengePeriod` without them (Amendment A2); `pauses` and `grace` are zero on the deployed vaults.
   - Notes deposited after `X` can only hold genesis, so they need no challenger. They exit at `D` by escape (hosted legacy build or clientd point release) or are swept at expiry.
   - The treasury sweep of stragglers is announced in advance.
4. Keep the legacy SDK bytes and keys hosted until retirement.

### 10.8 Rollback

| Stage | Action |
|---|---|
| Before Phase C step 4 | Do not publish; the contracts stay unused. |
| After new deposits; client or server bug | Fix forward. Exits never depend on server or client cooperation (§7.3). Optionally set the new profile to `deposits: "closed"`. |
| After new deposits; vault or circuit functional bug, exits still sound | Close deposits on the new profile. Reopen the legacy profile only while the legacy stack runs, before `X`. Keep the new stack running until the new vault drains. Deploy a corrected vault with a new circuit ID if needed. |
| Exit-soundness bug (forgery) | **Pausing stops only new initiations and closes, and only for up to `maxPauseDuration`.** Pending escapes finalize at their deadlines unless defeated or raised, and the challenger must act inside each escape's window. A forged escape with no successor evidence cannot be defeated. Decision criteria are written in advance: pause, publish, keep challengers running, and let honest users exit when exits reopen, since the vault has no upgrade path. The canary caps bound honest SDK users' exposure, and the server ceiling bounds per-request service. |
| Server signs non-derived anchors (bug) | Clients reject them (S4), and the circuit makes them unspendable (Q6a). Fix the server; nothing on chain changes. |

### 10.9 Compatibility matrix

| Component | Legacy vault (`0x4386…81fe` mainnet, `0x49fA…590F` Sepolia) | New vault (revision 3, `zkapi-v2-concession-v1`) |
|---|---|---|
| Legacy SDK re-cut (current `publicPath`) | requests and exits; deposits closed | refused: `incompatible_proof_circuit` |
| New SDK build (`/zkapi/v2c/`) | refused: circuit mismatch | supported |
| Legacy clientd point release | supported; deposits closed; fresh-state escape | refused (pins) |
| New clientd release (bridge 5) | warns and links to the legacy release | supported |
| Legacy stack | supported; admission closed from `X` | refused (binding) |
| New stack | refused | supported |
| Request JSON (`ApiRequestV2`) | same schema; legacy VK | same schema; new VK |
| Withdrawal and clearance wire | V2 (14 fields) | V2C (16 fields), `deny_unknown_fields` |
| Challenge calldata | `0x8a43467c`, evidence at `N`, with siblings | `0xda0ce43d`, evidence at `N⁺`, no siblings; raise `0xdd0064ba` |
| Proving keys and WASM | `setup/v2` | `setup/v2-concession` (`mpc-1`), new URLs |

---

## 11. Implementation plan

Work packages are listed in dependency order. Estimates are confirmed in WP-A and WP-B.

### WP-A: protocol core and circuits (first)
**Files:**
- `zkapi-core/src/v2.rs`;
- `zkapi-types/src/inputs.rs` (`WithdrawalPublicInputsV2C`, `to_field_elements() -> [Felt252; 16]`) and `wire.rs`;
- `zkapi-proof/src/{groth16,compact,reduction}.rs`;
- `examples/{setup,solidity_fixture,vault_challenge_fixture,wasm_roundtrip,export_r1cs,import_zkey}.rs`.

Generate the `dev` setup with `CircomReduction`.

**Tests:**
- **Positive:** genesis request; signed request with a valid `τ_prev`; escape with `c = 0`, `c = sb` and genesis `c > 0`; close; ownership; a full 160-bit destination.
- **Negative** (unsatisfiable, or verification fails):
  - request with `B > D`; signed state at τ = 1 (both circuits); genesis with τ ≠ 1 and no signature;
  - **signed state whose τ is not `succ(N(τ_p))` (request)**; wrong `note_id` in a nullifier;
  - `f + c ≠ B`, `c > B`, `B > D`; kind 3 and `k1 = k2 = 1`;
  - kind 1 or 2 with `next_nullifier ≠ 0` or `c ≠ 0`; kind 0 with a wrong `next_nullifier`; kind 2 with `destination ≠ 0`; kind 1 without a clearance signature;
  - `destination ≥ 2^160`; `valid_until ≥ 2^64`.
- **Mutate each public input** (12 request, 16 withdrawal) with the `CircomReduction` prover.
- **Note binding**; native equals circuit for `nullifier`, `next_anchor` and `successor_nullifier`; the end-to-end Rust chain (escape `next_nullifier` equals the nullifier of a request from the installed successor).
- **Key kinds and setup IDs:** release builds refuse `dev`; a request key loaded as withdrawal fails.
- **`constraint_budget`:** request constraints + 13 ≤ 32,700.
- **R1CS fidelity:** `r1cs_export_roundtrip`, `r1cs_negative_assignments`; `zkey_matrices_match` after the ceremony. Plus a cross-check of `reduction.rs` against `ark-circom`.

### WP-B: contracts
**Files:** `ZkApiVault.sol`; `Types`, `Errors`, `Events`; `IZkApiProofAdapter.sol`; the generated adapter; mocks; existing suites; new `ZkApiVaultConcession.t.sol`, `ZkApiVaultInvariant.t.sol` and `ZkApiVaultMutation.t.sol`; `vault-challenge.json`; `Deploy.s.sol`; `scripts/expected-codehashes.mjs`; the `ci.yml` jobs.

**Forge tests:**
- **Initiation:** kind gating; `ProofExpired`; `SupersededState`; `ChallengedNullifier`; `Nn` equal to 0 or to `N` reverts; both nullifiers consumed; concessions written; events; **no root change**; a deposit landing first does not invalidate the escape.
- **Defeat:** only at `next_nullifier`; deletes both used flags, flags `N`, grants grace; a request at `N` reverts `NotSuccessorEvidence`.
- **Raise:** monotone; `min(amount, sb, B)`; `NotARaise`; `NotStateEvidence`; the deadline does not move; a defeat after a raise works; a raise after the deadline reverts.
- **Pause:** a bounded pause opens exits after `maxPauseDuration`; the cooldown applies; defeat, raise, finalize and retire are open while paused.
- **Finalize:** pays the raised amount; push-failure credit and claim.
- **Other entry points:** re-escape rules exactly per §4.6; `mutualClose` (kind 1 only, `validUntil`); `claimExpired` without siblings; `retireClosedLeaf` (Closed only, `StaleRoot` on a second call, root change); notes with a shared secret are independent.
- **Pins:** selectors and topics.
- **Invariant fuzz:** balance accounting; `finalBalance + conceded == stateBalance ≤ D`; one payout per note; payout plus treasury equals `D`.
- **Gas snapshot:** escape ≤ 0.70M, defeat ≤ 0.50M, raise ≤ 0.40M, close ≤ 0.55M, claim ≤ 0.20M.
- **Generated mutation test:** for every one of the 12 request and 16 withdrawal inputs, mutate one input of a real fixture proof and expect `InvalidProof` from the real adapter.
- **Real-proof fixtures:** withholding concession; raise; defeat by `R_{k+1}`; `R_k` does not defeat; `SupersededState`; ownership rejected; close; genesis concession; same-secret notes; an expired proof.
- **Regression:** `ProbeWithholdingOperator` asserts treasury gain `= D − (B_k − sb_k)`.

### WP-C: server, challenger and indexer
**Files:**
- `processor_v2.rs`: the settle/sign split; O7 deferral and `ExitedUnsigned`; anchor assertion; ephemeral-key self-test; V2C clearance; evidence endpoint; recovery restrictions; root freshness; lease ceiling.
- `nullifier_store.rs`: schema, triggers, new columns, transactional reserve, `deployment_binding` extensions, the `open_read_only` schema list.
- `routes.rs`, `config.rs` (both checks), `dashboard.rs`, `watcher.rs`.
- `challenge_service.rs`: decision order, Ω table, the Raise→Defeat transition, same-block reads, miss accounting, retire-on-miss.
- `challenge_status.rs`, `bin/zkapi-challenged.rs`, `crates/zkapi-indexerd/src/poller.rs`.
- `crates/zkapi-cli/src/main.rs` (`db init`, `settlement reopen`); signer and docker files; the `adversary` feature (including `hang`).

**Tests:**
- Derived anchor; anchors 0 and 1 refused; no second finalize on any path; the self-test never calls the production signer.
- O7: deferral when `N` is used; signing after a defeat; `ExitedUnsigned` after the window; Ω uses the settled charge.
- Evidence atomic with the reservation (fault injection); append-only triggers.
- Ownership proof: kind 2, freshness, zero fields.
- Evidence endpoint: refuses published nullifiers.
- Root staleness refusal.
- **challengerd refuses a DB without `request_evidence`** ("run `zkapi db init`").
- Challenger:
  - defeat for every lease status at `N⁺`;
  - **evidence only at `N` never yields a defeat attempt**;
  - the Ω table; raise with the max-`sb` proof; raise-lead timing;
  - **a raise pending when evidence at `N⁺` appears: the defeat replaces it at the same nonce and is mined before the deadline**;
  - **restart in the middle of the replacement**;
  - a raise mined after a defeat reverts harmlessly;
  - miss accounting; strict decoders; calldata golden vectors against Forge `abi.encode`.
- **Parameter-set test** for mainnet, Sepolia and drill.
- Release binaries reject `--adversary`.

### WP-D: WASM and SDK
**Files:** `zkapi-browser/src/lib.rs`; `scripts/build-browser-client.sh`; `rust-toolchain.toml`; `sdk/wallet.js`; `sdk/services/{browserWalletRuntime,zkapiClient,zkapiRequestArchive,zkapiWasmWorker,zkapiNativeEth,zkapiTreeRebuild,zkapiExitKit}.js/.mjs`; `sdk/build.mjs`; scripts; `sdk/assets/**`, `sdk/wasm/**`, `sdk/test/**`; `examples/sample-host/`.

**Tests:**
- S4 rejects anchors 0, 1, reused, random and foreign; S3 uses the bound; S5.
- Bound written in the same transaction as the journal (crash injection); C2 refusal.
- C1: a request preparation racing an exit decision.
- C3 frozen proof set, including mutual mode.
- E0: timeouts and `Retry-After` ignored; a hanging mock server cannot delay past `must_initiate_by`; `E_low` from `expiry_ts`.
- E1–E6 decision table, including:
  - E2 `NullifierUsed` leads to E3;
  - E2 unreachable leads to `c = 0`;
  - forced early `c = 0`; lost-ε `c = min(Δ, b)`;
  - the late-successor switch before release, and install after lock release;
  - lock release only after `valid_until`.
- Stale-device pre-check (verifying and non-verifying answers).
- Advisory pre-checks never block.
- Codehash and getter checks through the wallet provider, and mismatch refuses deposits.
- Canary caps.
- **Raise then finalize, and raise then deferred credit then claim, reach `closed`**, with every matcher site covered.
- 16-word encoder golden vectors (836 B); event and `pendingConcessions` decoders.
- Tree rebuild: per-event root checks, adaptive chunking, a fixture with retirements.
- Exit-kit round trip; capability probes; export list.
- **Coexistence:** a legacy-build test (run on the release branch) over a store fixture written by the new build, including new dispositions and runtime fields, asserting no throw and no rewrite of new-deployment records. Plus the reverse.
- `not_deployed` placeholder refusal; sample host with two builds; reproducible WASM hash; `wasm_roundtrip` with the new keys.

### WP-E: companion and clientd
**Files (Option C):** `crates/zkapi-companion/**`, `crates/zkapi-auth/**`, `protocol/rust/crates/zkapi-client/**`, root `Cargo.toml`, `zkapi-clientd/scripts/*`, packaging, `internal/zkapi/{address_withdrawal.go, escape_withdrawal.go, deployments.go, deployments/*.json, companion.go, client.go}`, UI, `testdata/browser-profiles/*`; and on `release/v2-note-bound`, the legacy point release.

**Tests:**
- S1–S6, C1–C5 and E0–E7 parity with the SDK through shared vectors.
- `WalletLock` race test.
- **Crash tests at each step of the §6.2 write orders.**
- Escape routes end to end against the in-process serverd.
- Go calldata length and word checks; `word 9 + word 14 == B`; `conceded` confirmation; binding over `words[:16]`.
- Codehash checks with `--exit-rpc-url`.
- Payout matchers after a raise.
- Warning-only legacy guard; `bridge_version` 5.
- `exit-kit escape`.
- Companion proofs verify against this repository's VKs and the Anvil adapter.
- **`test-companion.sh` runs the protocol-workspace tests from `protocol/rust`.**

### WP-F: end to end and docs
**Shared golden vector.** A real kind-0 and kind-1 proof with the expected calldata bytes, consumed by the Rust, JS and Go encoders, with each encoder's output submitted to an Anvil vault.

**`scripts/v2-acceptance.mjs`** (Anvil, real proofs, real contracts) runs every Phase B drill scenario plus a gas-measurement run. Every scenario asserts the client's final state as well as on-chain balances.

**Docs:**
- `docs-site/content/docs/{protocol,cryptography,architecture,api-reference/vault}.mdx`: remove the withholding limitation; describe the concession, append-only tree, bounded pause, privacy linkage, MPC setup and codehash audit.
- `protocol/{PROTOCOL,SPEC,README}.md`.
- `docs/{challenge-service,native-eth-billing,migration-hardened-vault,note-bound-commitments,api-spec}.md`: the Phase-1 runbook for revision 3, daemon order, the legacy cutoff, the retire-on-miss runbook.
- `zkapi-clientd/docs/PRIVACY.md`; `sdk/README.md` (host recipe, exit kit, `exitRpcUrl`).

### Ordering summary
```
decide S1 + CircomReduction ─► WP-A ──► WP-B ─┐
                                   ├──► WP-C ─┼──► WP-F ──► freeze, review, G-SETUP + fidelity gates ──► regenerate pins, codehashes ──► Sepolia (§10.7 B) ──► mainnet (§10.7 C)
                                   ├──► WP-D ─┘
                                   └──► WP-E ───────────────────────────────────────────────────────────────────────► clientd releases (§10.7 D)
```

**Mainnet gates:**
- G-SETUP (S1 with at least 2 external contributors and a beacon) and both fidelity gates;
- external review including the reduction and export;
- reproducible WASM and published expected codehashes;
- all WP-F scenarios green on Sepolia, plus 14 days of soak with weekly drills;
- daemon order with the challenger healthy before the first deposit;
- canary configured (SDK caps and server lease ceiling);
- legacy re-cut published and cutoff `X` announced.

---

## Appendix: red-team disposition

| # | Sev. | Finding | Disposition | What changed / argument |
|---|---|---|---|---|
| 1 | high | Exit path waits on operator HTTP with no deadline | **Fixed** | E0: 20 s per-call timeout; 5xx, 429 and timeout count as unreachable; `Retry-After` ignored; single bounded E1 pass. `must_initiate_by = E_low − 12 h`, with `E_low` from local `expiry_ts`, a proven lower bound of `effectiveExpiry`; E1 and E2 are skipped once past it. The near-expiry rule (C4) and `T` use the build-pinned `W`. `--adversary hang` drill. §6.3, §6.4, §5.5, §10.7 B |
| 2 | high | Clients never check vault, adapter or Poseidon | **Fixed** | Profiles pin three runtime codehashes, the adapter address, the VK hashes and the parameters. Clients check `eth_getCode` and getters through the user's wallet provider and the pinned RPC at init and before every deposit, and refuse deposits on mismatch. The vault codehash covers immutables and the linked library address. CI publishes reproducible expected codehashes from source, the ceremony VK and constructor arguments. §4.9, §6.5, §6.7, §10.3, §10.4 |
| 3 | medium | Abandoned escape proofs replayable; E6 releases the lock early | **Fixed** (self-defeat not adopted) | New public input `valid_until` (+65 constraints, +7.9k gas) checked by the vault for kinds 0 and 1 and by the server for kind 2. A proof counts as released when it is handed to any wallet or RPC, including simulation. E6 releases the lock only after every released proof is dead (`valid_until` passed at a finalized block). Self-defeat is unnecessary: during a proof's lifetime C3 keeps the client from creating `N⁺` evidence, so any exit that lands is one it chose. §3.3, §4.2, §6.4 |
| 4 | medium | Exit timing and pre-checks trust one pinned RPC | **Fixed** | `E_low` from `expiry_ts`, raised only when the user's exit RPC and the pinned RPC agree. All pre-checks are advisory and simulation runs through the user's provider. clientd `--exit-rpc-url`. §6.4 E0 and E4, §6.7 |
| 5 | medium | Canary cap below escape cost; front-run deposits force reverts | **Fixed** | Append-only tree: exits do no Merkle work, so escapes cost about 0.6M gas and are immune to root races (they need only a known root). The G2 argument without leaf removal is in §7.4 (L5 and O7), with `retireClosedLeaf` as the remedy when A4 fails. Canary changed to 0.25 ETH per note plus a 25 ETH aggregate. G1 is stated gross of exit gas, with a warning below three times the escape cost. Private orderflow is optional because front-running cannot alter or revert an exit. §1.2, §4, §2.3, §10.7 C |
| 6 | low | Late successor discarded | **Fixed** | E1 reruns after the lock is set, before proving and before broadcast. Switch to `S_{k+1}` if nothing was released; otherwise archive it and install on lock release. §6.4 E3, E4, E6 |
| 7 | low | Exit decision not atomic; C3 contradicts E2 | **Fixed** | C1 single lock (Web Lock; companion `WalletLock`). Lock set before E1. C3 rewritten to allow exactly the lock mode's own proofs. Race test. §6.3, §11 WP-D and WP-E |
| 8 | low | Legacy clientd drain depends on clearance; guard blocks | **Fixed** | Legacy clientd point release with deposits closed and an in-product fresh-state escape, plus a CLI runbook. The new release's guard is a warning only. §10.5, §10.7 D |
| 9 | low | Unbounded owner pause | **Fixed** | Immutable `maxPauseDuration` (≥ 2·challengePeriod; mainnet 45 d), after which escape and close ignore the pause; 1-day re-pause cooldown. `claimExpired` stays blocked while paused. §4.7, §7.3 |
| 10 | low | S2 lets the operator pick the trusted party | **Fixed** | S1 is mandatory. The fallback is still S1 with at least 2 externally nominated contributors and a beacon; otherwise mainnet slips. §10.2 |
| 11 | medium | Defeat-first leaves no raise fallback | **Partly fixed; raise-first rejected** | The fragility is removed structurally: a defeat no longer needs the indexer, a zero-slot path or the live root, and costs about 0.37M gas. With identical failure modes, a preceding raise adds no protection and can delay the defeat on the nonce lane. Adopted: the Raise→Defeat nonce transition, the miss metric, A4 restated as "one cheap transaction lands", and retire-on-miss. §5.4, §2.2 |
| 12 | medium | Export fidelity untested for soundness | **Fixed** | Export from finalized `ConstraintMatrices`; parse-back equality; negative assignments must fail the exported R1CS; `read_zkey` matrices equal synthesized ones; mutation and negative tests rerun with the imported keys and the `CircomReduction` prover against the Anvil adapter before publication. §10.2, §11 WP-A |
| 13 | medium | Legacy retirement held hostage by direct deposits | **Fixed** | Dated cutoff `X`: legacy admission closed; retirement defined over notes deposited before `X`; notes after `X` are genesis-only and exit at `D` or are swept (announced). §10.7 E |
| 14 | medium | Canary cap SDK-only; operator exposure unbounded | **Fixed (on-chain cap rejected)** | A server lease ceiling (`--request-limit-max-usd-micros`, $6) bounds per-request exposure, which is what the operator risks. The SDK caps are explicitly for honest SDK users. An on-chain cap would not bound service exposure. Rollback text corrected. §5.2, §10.7 C, §10.8 |
| 15 | low | Zero-charge successors mint unconsumed nullifiers; root staleness | **Fixed** | O7 settle-then-sign gate (defer while consumed, sign after a defeat, `ExitedUnsigned` otherwise). O5 root freshness at most 60 s, corroborated with the vault. L5. §5.1, §5.2, §7.2 |
| 16 | low | Server anchor bug yields undefeatable stale exits | **Fixed** | Q6a anchor chain in the request circuit only (+724; 31,692 rows ≤ 32,700). Non-derived successors are unspendable, and exits never need `τ_prev`. §3.2, L3, §7.4 |
| 17 | low | "Older re-escapes revert cheaply" is false | **Fixed (text)** | Corrected to "at most `⌈(k−1)/2⌉` forced defeats", each now about 0.37M gas; challenger budget sized accordingly. §4.6, §5.4 |
| 18 | low | Sepolia fails the raise-lead check | **Fixed** | Check restated as `ttl + grace + settlement_deadline + raise_lead + 4·poll + 1200 ≤ challengePeriod` (Sepolia 37,513 ≤ 43,200); a parameter-set CI test covers all three networks. §5.4, §10.4 |
| 19 | low | `CIRCUIT_ID_HASH` identifies the circuit, not the setup | **Fixed** | `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH` in the adapter, manifest and profiles; a setup ID in key headers; release builds refuse `dev`. §4.8, §10.1 |
| 20 | high | Nothing ties a deployment to the ceremony keys | **Fixed** (with 19) | Daemons hash the loaded `.vk` files against the adapter and manifest and fail closed. Clients check VK hashes and codehashes. The dev and drill setup is labelled `dev` and unloadable in release builds. §5.4, §5.5, §6.5 |
| 21 | high | S1 switches the reduction after freeze and review | **Fixed** | S1 and `CircomReduction` are decided before WP-A. The dev setup uses the same reduction, so every test runs the shipping prover. Reduction and export are in the review scope, and the cross-test covers every branch. §3.4, §10.2, §10.7 A |
| 22 | medium | Daemon start order cannot run | **Fixed** | `zkapi db init` creates the schema and binding. Order: indexer, `db init`, challenger, serverd. The read-only schema list includes `request_evidence`, with a startup test. §5.5, §10.7 |
| 23 | medium | Sepolia raise-lead check (duplicate of 18) | **Fixed** | As 18, with explicit per-network values in §10.4 |
| 24 | medium | Payout matching breaks after a raise | **Fixed** | `B`, `c` and `b` persisted; every SDK and Go matcher accepts `f' = B − c_final` within `[B − b, B − c_init]`; raise-then-finalize and raise-then-credit tests assert client state `closed`. §6.2, §6.4 E5, §11 |
| 25 | medium | C3 contradiction; wrong dispositions; late-successor rule | **Fixed** | C3 rewritten. Record classes match the archive code (`evicted` is unresolved; `discarded_superseded_unaccepted` does not exist; `discarded_stale_root` and `discarded_clearance_reserved` included; an `unknown` reading counts as resolved after `request_time + 1200`). Late successors are installed on lock release. §6.3, §6.4 |
| 26 | medium | Legacy drain contradictions; endless legacy deposits | **Fixed** | Config-only legacy re-cut (same bytes, new config hashes, same `publicPath`, `no-store` test); legacy clientd point release with deposits closed; cutoff `X`; revised Phase E condition; straggler sweep announced. §10.5, §10.7 D and E |
| 27 | medium | Nonce lane for raise then defeat unspecified | **Fixed** | Single allowed transition (Defeat replaces an unmined Raise), persisted per attempt; same-block reads; restart and ordering tests. §5.4, §11 WP-C |
| 28 | medium | Browser exits depend on the host origin | **Fixed** | A6 stated. Encrypted exit kit, `zkapi-walletd exit-kit escape`, key URL override with SHA-256 pins. §2.2, §6.4 E7 |
| 29 | medium | Stale device escapes without a pre-check | **Fixed** | `GET /v2/nullifiers/{N⁺}/evidence`, verified locally under the pinned VK and run after the lock, just before broadcast. An unverifiable answer is ignored, so a lying server cannot block exits. The endpoint never serves published nullifiers. §5.2, §6.4 E4 |
| 30 | medium | clientd and companion specifics open | **Fixed** | (a) Go escape checks `word 9 + word 14 == B`, a confirmed `c`, kind and next-nullifier words, binding over `words[:16]`. (b) Explicit fsync orders with crash tests. (c) S3 uses `bound_at_state`. (d) Protocol-workspace tests run from `protocol/rust`. §6.2, §6.7, §10.6 |
| 31 | medium | Tests miss order and encoder bugs outside Rust | **Fixed** | Generated Forge mutation test over real proofs; a shared golden vector across Rust, JS and Go submitted to Anvil; a challenger "evidence at `N` only, no defeat" test; legacy-build tests over a new-build store fixture. §11 |
| 32 | low | Root-change front-running taxes escapes and defeats | **Fixed structurally** | No exit, defeat, close or claim depends on the live root (append-only tree). The proof root stays valid for good (Amendment A1). §4.2, §7.3 |
| 33 | low | `main` staging and host bundling underspecified | **Fixed** | `deployment_status: "not_deployed"` placeholder and CI exemption; host recipe with two package entries, dynamic import and a sample host test; `main` refuses profiles without `exit_concession: 1`, and the revision-2 code paths are deleted. §10.5, §6.5 |
| 34 | low | Rollback over-promises for pause | **Fixed** | §10.8 says explicitly that pausing stops only new initiations and closes, for at most `maxPauseDuration`; pending escapes finalize unless acted on; decision criteria written in advance. |
| 35 | low | Tree rebuild needs per-event checks and realistic RPC limits | **Fixed** | Per-event root equality, scan only to the finalized block, comparison to the last event's root (no archive reads), adaptive chunking, retirement fixture. §6.6 |
| 36 | low | For a forced early exit, conceding 0 dominates | **Fixed** | Forced early exits default to `c = 0` (the user may pick `b_k` for privacy). E2-unreachable also uses `c = 0`. `c = b_k` only at or after `T`. §6.4 E2, E3; §9.2 |
| 37 | low | Startup self-test signs with the production key | **Fixed** | The self-test uses an ephemeral in-memory key. The production path asserts anchor derivation before the signing call. §5.1 |
---

## Implementation status

Work packages A to E are implemented with the `dev` setup (`protocol/setup/v2-concession-dev`). No revision-3 vault is deployed: the SDK and clientd profiles are `deployment_status: "not_deployed"` placeholders, which every build and client refuses. G-SETUP, the external review, the Sepolia drill and soak, and the mainnet rollout (§10.2, §10.7 A step 4 onwards) have not run. The operator runbook is [Migrating to the concession-exit vault](../migration-concession-vault.md).

The implementation differs from the text above as follows. Each item names the section it amends.

### Measured figures (§1.5, §4.9)

| Item | Estimate | Measured |
|---|---|---|
| Request circuit | ≈31,679 constraints | 31,670 constraints, 12 public inputs, 31,378 witnesses, domain 2^15 |
| Withdrawal circuit | ≈36,458 constraints | 36,452 constraints, 16 public inputs, 36,001 witnesses, domain 2^16 |
| Native prove (Apple Silicon, release, median of 3) | n/a | request 356 ms, escape 395 ms; verify 1.5 ms |
| `initiateEscapeWithdrawal` (transaction gas) | 0.55–0.62M | 574,544 |
| Defeat | 0.33–0.40M | 374,881 |
| Raise | ≈0.33M | 335,128 |
| `mutualClose` | 0.40–0.45M | 427,837 |
| `finalizeEscapeWithdrawal` | 30–206k | 91,898 |
| `claimExpired` | 0.06–0.15M | 77,509 |
| `retireClosedLeaf` | ≈6.0M | ≈5.95M; a duplicate that reverts `StaleRoot` costs ≈5.9M |
| Vault runtime size | 16.3–17.3 KB | 17,431 B (7,145 B under EIP-170); adapter 7,343 B, Poseidon 9,723 B |

The gas figures are pinned in `protocol/contracts/snapshots/concession-exit-gas.json`, with a ceiling of 250k added for `finalizeEscapeWithdrawal`. All are dev-setup figures; G-SETUP replaces the keys, adapter, fixtures and snapshot.

### Circuits, setup and key policy (§3, §10.1, §10.2)

- **Setup ids.** Besides `dev` and `mpc-1`, a `rehearsal` id labels dry runs of the ceremony pipeline. The test-build policy is split across two features: `dev-setup` accepts `dev`, `rehearsal` and unpinned `mpc-1` keys, and `dev-fixtures` exposes the fixture module without changing the policy. Generating keys needs neither.
- **Ceremony pins.** A release build accepts an `mpc-1` key only when its verifying key's keccak256 equals `CEREMONY_VK_KECCAK256` in `compact.rs`, which is `None` until G-SETUP step 7. A release build therefore loads no key at all until the ceremony keys are committed with their pins. The binary `release_policy_check` (CI job `release-key-policy`) enforces this, and checks that no production build enables `dev-setup`: the operator image (`docker/Dockerfile`), the WebAssembly client (`scripts/build-browser-client.sh`) and the companion every clientd release ships (`zkapi-clientd/scripts/build-native.sh`), each resolved in its own workspace.
- **Public phase 1 only (A2, step 3).** An `mpc-1` import accepts only a powers of tau on `ceremony::PUBLIC_PTAU` (Hermez `powersOfTau28_hez_final_16..27`), matched by its published Blake2b-512. The importer also checks the file's consistency itself: exact snarkjs section sizes, that the points it uses form one reference string, and the top block of section 12. `rehearsal` imports may use any file.
- **Import gates (step 6).** `import_zkey` requires `--setup-id`, `--ptau`, `--ptau-sha256` and the ceremony's `.r1cs` files, which must be byte for byte this build's export. It refuses an `mpc-1` zkey with fewer than three contributions before its beacon. Besides the coefficient check of step 2(c), it runs a binding check of every circuit-dependent point against this build's A, B **and C** matrices (`check_key_binding`), which refuses keys set up from an R1CS that differs only in C. The contribution chain itself is checked only by each reviewer's `snarkjs zkey verify`.
- **Setup manifest.** `manifest.json` also records `r1cs_sha256`, `zkey_sha256` and `ptau_sha256` (computed by the import) and the circuit shapes.
- **Canonical inputs.** Provers and verifiers refuse public inputs at or above the BN254 scalar order instead of reducing them, and the vault refuses such a nullifier itself (`InvalidFelt`), in addition to the adapter's range check.
- **Legacy setup.** `protocol/setup/v2` (circuit `zkapi-v2-note-bound-v1`) stays in the tree for the legacy release line; the gateway image ships only `protocol/setup/v2-concession`, so it serves no proving keys until G-SETUP commits them.

### Contracts and deployment (§4, §10.4)

- **Amendment A1.** `isKnownRoot` returns `knownRoots[root]`, every root the vault ever set; `rootRetiredAt` is informational. `ROOT_HISTORY_WINDOW()` stays 86400 and is now only a probe value and the default bound of off-chain root windows.
- **Two-stage deployment manifest (§10.4 items 1 and 4).** `Deploy.s.sol` writes only a provisional manifest, `$OUTPUT_PATH.pending`, with `deploymentStatus` `"pending"` (or `"simulated"` without `--broadcast`) and `deployBlockLowerBound`. `node scripts/expected-codehashes.mjs --deployment $OUTPUT_PATH.pending --rpc $RPC_URL --finalize $OUTPUT_PATH` then reads the creation receipts from forge's broadcast log, checks each creation, the three runtime codehashes, the owner and the treasury on chain, and only then writes the final manifest with `deploymentStatus: "deployed"`, `deployBlock` (the vault's creation block) and `deployTransactions`. `deploy_block` (§10.3, §10.7 B step 2.1) is that `deployBlock`. serverd, `zkapi db init`, the companion, the SDK build and clientd refuse a `pending` or `simulated` manifest. Finalize needs forge's broadcast log (or `--broadcast-log`), defaults to `--confirmations 1`, and checks owner and treasury only when it runs; `--check --rpc` later audits codehashes only.
- **Setup policy (§10.2 "no single-party setup").** Enforced by `SetupPolicy` in `Deploy.s.sol`: off local chains a `dev` or `rehearsal` setup needs `ALLOW_DEV_SETUP=1` (recorded as `allowDevSetup`), mainnet included since v0.2 (a single-party vault trusts its setup's generator; see `docs/deployment.md`, "Single-party setup"), and an `mpc-1` setup must have the verifying keys of the committed `protocol/setup/v2-concession/manifest.json`. Local chains (31337, 1337) accept any setup id.
- **Deployment script.** It links `Bn254Poseidon` itself; requires `OWNER`, `TREASURY`, `SETUP_MANIFEST` and `MAX_PAUSE_DURATION_SECONDS` off local chains; checks the signing keys (prime-order subgroup, distinct, not the published development keys off local chains); and writes key coordinates as decimal strings. The demo Foundry profile uses the protocol profile's compiler settings, so both build the same runtime code.
- **Tests (§11 WP-B).** Besides the listed tests: closed-note re-exit tests (mock, real proofs and invariant), tampered-statement real-proof tests, setup-policy tests, an Anvil broadcast-and-finalize scenario in CI, and a shared golden vector (`protocol/contracts/test/fixtures/withdrawal-golden.json`, a real escape conceding 100,000 and a real close) that the Rust, JS and Go encoders reproduce byte for byte and that `scripts/check-withdrawal-golden.mjs` submits to an Anvil vault. `crates/zkapi-serverd/tests/fixtures/check-calldata-golden.sh` pins every selector, getter layout and event the server, challenger, indexer, SDK and clientd read against the real contracts.

### Server, challenger and indexer (§5)

- **Settle, then sign (§5.1).** Between `settle_charge` and `sign_successor` the lease row already reads `finalized`; clients poll recovery until `nullifier_status` is `finalized`. The reserve transaction also writes the provisioning lease row. The signing pass pages never-deferred and deferred requests separately, at most 200 of each per pass, so a deferred request is re-checked within ⌈deferred/200⌉+1 passes rather than every pass. Dashboard events are recorded at settlement, without successor fields. `settlement reopen` adds the refusals `AlreadySettled` and `RebindSettled`.
- **Recovery and evidence (§5.2).** Both read `usedNullifiers` and `challengedNullifiers` first, then the indexer's published-nullifier table (`/v1/nullifiers/{N}/published`). When no indexer is configured, or (for recovery only) the indexer fails, they scan the vault's `EscapeConcessionRecorded` logs from an hour before the reservation, over at most 50,000 blocks; anything else they cannot read is `503 chain_read_unavailable`. The evidence endpoint stays strict while an indexer is configured. The one publication the scan cannot see is a nullifier its owner published before the reservation, through an escape with a proof the server never saw; recovery serves that case, where §5.2 says "never". The endpoint is not rate-limited by the server; the reference gateway counts only POST requests.
- **Root freshness (§5.2).** With no indexer configured, the vault's root alone counts.
- **Clearance (§5.3).** The legacy clearance code is deleted, and `--allow-legacy-clearance` refuses startup. A clearance accepts any root the vault ever held (`knownRoots`, Amendment A1), so an ownership proof at the deposit-time root is accepted. A nullifier already `ClearanceReserved` is signed again.
- **Binding and manifest (§5.5).** serverd requires `--deployment`. `deployment_binding` gains a `source` column (`vault` or `manifest`); a manifest binding is verified against the vault before serving, and a database whose binding cannot be read is refused at startup by serverd and by `zkapi db init`. serverd also refuses manifest keys that its seeds do not derive, a `challenge_period` other than the vault's, and a settlement window above the manifest's `settlement_window_seconds`. The indexer binds by its checkpoint's `circuit_id` and the `CONCESSION_ESCAPE_VERSION` probe, not by `deployment_binding`; its checkpoint is version 3 and records `last_lifecycle_block`, and it rebuilds after a deep reorganization near lifecycle events.
- **Challenger (§5.4).** `zkapi-challenged` requires `--deployment`; `--chain-id` and `--contract-address` are optional and must equal the manifest. It checks `challengePeriod` against the manifest and the binding, and takes `--settlement-window-seconds` (default and ceiling: the manifest's) and `--settlement-poll-seconds`. Evidence at `N⁺` that does not verify never holds back the raise at `N`; it keeps the obligation critical (`evidence_invalid`) and counts as a possible missed defeat. A raise that became moot releases its nonce, and a raise mined after a defeat is accepted as harmless. Gas limits: defeat 600,000 and raise 450,000, each raised to the estimate plus 20% when that is higher; a retirement uses the estimate plus 20%. The status schema is `zkapi-challenged-status/v2`, and a miss logs `MISSED escape deadline` with `missed="defeat"` or `missed="raise"`.
- **Retire on miss (§5.4).** It is sent only after a confirmed miss on a `Closed` note, with an indexer path that hashes to the live root; a stale path is never sent, a zero leaf means the obligation is done, and the obligation stays a warning until the retirement mines. The signer sidecar adds a bound §5.4 does not have: it signs `retireClosedLeaf` only while `ZKAPI_CHALLENGE_RETIRE_ON_MISS` is on and only for a note whose escape finalized within `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS` (default 50,400); it counts retirement nonces against `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY` (default 2, rolling 24 hours, in memory), refuses a note's retirement on a new nonce while an earlier counted nonce may still mine (`retirement_in_flight`), and requires canonical re-encoding of every call it signs. This trades retirement liveness for a hard gas bound: forced root races can spend the budget and delay a retirement.
- **Indexer (§5.5).** Escapes change no leaf, so the root check does not cover `/v1/escapes/pending`; it is a hint, and the challenger relies on its own event scan and the vault. The zero-slot path endpoint is kept with a `Deprecation: true` header.
- **Adversary modes (§5.5).** `overcharge` persists the overcharged amount, and adversarial successors skip the anchor assertion. A release build, and the Docker image, reject `--adversary`.
- **Docker.** By default the images ship only `protocol/setup/v2-concession`, so `/proofs/*` answers 404 and the daemons refuse to start until G-SETUP commits the pinned keys. Built with `ALLOW_DEV_SETUP=1`, they ship and accept the development setup instead, for a single-party vault.

### Clients (§6)

- **Record classes (§6.4 E1).** `invalid_successor` is unresolved, handled like a withheld successor (§6.1), not terminal; `late_successor` is terminal. The SDK, the companion and clientd share one vector file, `protocol/rust/crates/zkapi-client/tests/vectors/exit-rules.json` (S1–S6, C3–C4, E0–E7, the exit kit), which each test suite reproduces.
- **E2.** `bound_at_state == 0` is fresh whatever the records say. A `nullifier_used` answer while no released request of the state is on record escapes at once, conceding `bound_at_state` (nothing when nothing left the device), instead of waiting in E3. E3 waits from the newest unresolved release, E2 step 4 from the newest release. A lost ε concedes `min(charge, bound_at_state)` at once, whatever the records say.
- **C3 ownership proofs (§6.3).** At most one live kind-2 proof per state, across exit locks: it is sent again while valid, a new one is made only after it expired, and within 5 seconds of its expiry the client waits (`ownership_proof_wait` in the SDK). The marker of C5 keeps it past a cancelled lock. The SDK makes ownership proofs valid 55 minutes, not 3,600 s, to absorb a client clock up to 5 minutes fast.
- **E0.** The SDK also counts a 401 as unreachable, and ends every other operator call after 90 seconds.
- **E6.** The SDK reads the note status and the finalized block from the exit RPC (on the vault's chain), then the wallet provider (during a withdrawal or a cancel, on the vault's chain), then the pinned RPC; the companion reads them through its escape's RPC (the exit RPC when one is configured, else the pinned RPC). In both, a lock that released an escape or close proof is released only once this device's clock also passes `valid_until + 900`, whoever answered the reading, and only a reading through the exit RPC releases it early on `Closed` (`exit_policy::lock_releasable` and `exitLockReleasable`; the shared vectors carry the device clock and the reading's trust). Without an exit RPC, the pinned RPC still decides when a dead lock is released and whether an escape landed, was defeated or paid. That is not only liveness: a pinned RPC that drops the escape's transactions and fakes their receipts and logs makes clientd and the companion record the escape as finalized and paid, and archive the note, while the note is still `Active` on chain, where the operator can take `D` with `claimExpired` at expiry. Owners should therefore set an exit RPC before escaping, or check through an independent source (their own node or a block explorer) that the payout reached the destination. clientd warns on every open escape while no exit RPC is set, and repeats that check on an escape it completed without one. When a dead lock cannot be released yet while a verified `late_successor` waits, a withdrawal refuses with `exit_release_pending` before `must_initiate_by` rather than exit from the older state; from `must_initiate_by` on it exits from the older state, conceding nothing. The chat path still reads only the exit RPC, then the pinned RPC.
- **Exit RPC (§1.2(6), §6.6, §6.7, red-team #4).** Every client asks the exit RPC for `eth_chainId` first and ignores one on another chain. In the SDK an exit RPC that fails or is on another chain gives way to the wallet provider and the pinned RPC for roots and logs, but is never used for `E_low` or a gas estimate. In the companion and clientd, an escape with an exit RPC configured reads and sends only through it (nonces, gas, receipts, logs, chain ID, known roots, rebuild, status), retrying twice (1 s, 3 s) and then stopping with an error; the pinned RPC is never used in its place. `E_low` still reads both RPCs.
- **E4.** Merkle paths come from the deposit-time path first (Amendment A1), then the indexer, then the rebuild, which has a 5-minute total budget in the SDK. Wallet simulations are advisory: after a refusal the SDK uses the exit RPC's estimate or a fixed limit, and after `UnknownRoot` it proves once more at another root. clientd signs escapes at gas floors of 900,000 (initiation), 350,000 (finalization) and 150,000 (claim), retires a signed escape that can no longer be included (phase `escape_expired`: its proof expired, its nonce was taken in a finalized block, or its nonce stayed above the pending nonce for 15 minutes), and signs it again at the account nonce, replacing a mempool copy with fees raised by 12.5% plus 1 wei. The G1 exit-cost warning never delays a withdrawal, and a deposit waits for its gas read at most 20 seconds.
- **Closes.** A mutual close near its `valid_until` is proved again from the kept clearance signature at the plan's root (A1), under a re-taken mutual lock, for the wallet's current state only. Only a granted mutual close can be set aside in the SDK (`park_requires_clearance`).
- **Initialization.** The SDK runs in exit-only mode from the build-pinned profile while the operator's manifest is missing or different; deposits and chats wait for it, exits never do.
- **Exit kits (§6.4 E7).** The companion has `exit-kit export` as well as `exit-kit escape`, and reads both the SDK's envelope and its own earlier one.
- **E5 defeats.** `EscapeWithdrawalChallenged` (a defeat, `device_not_newest`) is reported only from the defeat's log in a finalized block, with the note `Active` there, never from the `challengedNullifiers` flag at the latest block; the companion marks each reading `trusted` (through the exit RPC) or not. A reading whose defeat logs fail to load settles nothing: the companion still releases a dead lock, but reports the escape `unknown` and untrusted, never `expired`, and keeps a saved defeat; clientd retires an escape as never landed only from a trusted reading that read those logs (`defeat_checked`). clientd never treats one reading as final: it asks again on every run, follows an escape the chain shows pending after all, decides again when the exit RPC shows that a followed escape never landed, and lets the owner clear a defeated record once the chain shows it neither pending nor closed.
- **clientd (§6.7, §10.6).** Escapes use the existing quote-and-approve signing path, and a cancel route implements E6's "user cancels". The companion is built from this repository at the commit pinned in `packaging/zkapi-source.env`; the upstream pins and patches are deleted. Packaged profiles are `not_deployed`, so package tests use invented deployed profiles.

### Migration (§10)

- **The legacy point release (§10.7 D).** zkapi-clientd 0.1.7 exists only as local commits on `release/v2-note-bound` (deposits closed, an in-product fresh-state escape and finalize, and `docs/LEGACY_ESCAPE.md`). Its escape refuses a destination that rejects a plain ETH transfer from the vault (`escape_destination_unpayable`, simulated before any proof), because the legacy vaults pay inside `finalizeEscapeWithdrawal` and have no payout credit. It is not pushed, tagged or packaged. The new clientd's `scripts/assemble-release.py` refuses to assemble a release until `packaging/releases/clientd-0.1.7.json` records the published point release, so the legacy release must ship first.
- **Acceptance (§11 WP-F).** The wallet driver (`examples/v2_acceptance_wallet.rs`) is ported to this circuit and built by default. `scripts/v2-acceptance.mjs` (`npm run test:e2e:v2`, described in `docs/v2-acceptance.md`) runs this circuit end to end on Anvil with the drill build and the real indexer, challenger, signer sidecar, SDK and companion: every §10.7 B drill, `hang`, the late successor and switch and the rebuild from logs included, the Phase C smoke tests (the SDK's and the companion's own mutual closes), and a gas run. The SDK and the companion take their exit decisions themselves; the wallet driver has no exit rules, so where it escapes the harness applies them, and an SDK or companion scenario of the same drill shows the client deciding. Anvil uses chain ID 11155111 because the signer signs only for chains 1 and 11155111, and the drill timings are scaled down. It does not run reorganizations, the Go clientd's signing path or live Sepolia. The scripted Sepolia drills of §10.7 B (`--network sepolia-drill`) do not exist yet; the drill list there is the checklist for running them by hand with an `adversary` build.

- **Runbook (§11 WP-F docs).** The operator runbook is `docs/migration-concession-vault.md`; `docs/migration-hardened-vault.md` now only points to it, and its full text stays on `release/v2-note-bound` for the legacy stack. The legacy line has no `--admission closed` switch (§10.7 E step 2); the runbook closes legacy admission at `X` at the legacy gateway instead (410 `deployment_retiring` on `POST /v2/openrouter/leases`, the only route that admits a request). Step 3's "notes deposited after `X` can only hold genesis", and with it the retirement bound, depend on that closure: deposits stay permissionless, and a note that could still buy service after `X` would need the legacy challenger until its own expiry.
- **Profiles (§10.3).** `scripts/deployment-profile.mjs` writes the server's `trusted_deployment`, the SDK config and clientd's packaged profile from a finalized manifest: the signing-key coordinates as `0x` hex, a new `deployment_id`, and the setup's key pins checked against the vault's verifying keys. An SDK profile may carry `deployment_status: "deployed"`.
- **Rollback (§10.8).** `"deposits": "closed"` reaches only the SDK: clientd's profile is compiled in and has no such switch. The runbook also closes the new gateway's two deposit-only routes, which every clientd deposit needs, until a clientd release that refuses deposits ships.

### Open items

- G-SETUP and the mainnet gates of §11.
- No live Sepolia or drill run of this stack has happened.
- The residual risks of §9.2, plus the signer's retirement budget above.
