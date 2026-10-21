# ZK API Usage Credits

This note describes the active zkAPI v2 usage-credit protocol, circuit
`zkapi-v2-concession-v1` (vault revision 3). The implementation uses BN254
Groth16 proofs, BN254 Poseidon hashing, Baby-JubJub Schnorr signatures, and
native ETH settlement in whole gwei. See [SPEC.md](SPEC.md) for exact public
statements, the [concession exit design](../docs/design/concession-exit.md) for
the exit's security argument, and the [ceremony setup](setup/v2-concession/README.md)
for the setup's trust assumptions.

The goal is: a user deposits funds on-chain once, and then makes many anonymous off-chain API requests. The server must be protected against replay and non-payment, while honest users remain unlinkable.

Compared to the original [RLN-based design](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104), this version removes:
- the "two points on a line" construction,
- ticket indices,
- growing refund histories.

Instead, it uses a much simpler **state-anchor chain**: each valid request consumes the user's current private spend state and yields a fresh next state signed by the server.

## Overview

A user registers on-chain with a commitment derived from a secret.  
Off-chain, the user carries a private state consisting of:
- a private balance commitment,
- a one-time state anchor,
- a server signature on that state.

To make a request, the user proves in zero knowledge that:
- they are a registered depositor,
- they know the secret behind the registration commitment,
- they know a valid current state,
- they are authorized to spend from that state,
- they have enough balance for the maximum per-request charge.

The server accepts the request only if the derived nullifier has not been seen before.

After execution, the server computes the actual deduction, updates the private balance, derives the next anchor from the spent nullifier, signs the new state, and returns it to the user.

The funds remain escrowed on-chain until close-out. The server is paid by net settlement when the user withdraws or when an expired note is claimed.

This makes the protocol naturally sequential: one state authorizes one next request.

## Primitives

- $s$: user secret.
- $C = H(s, 0)$: on-chain registration commitment.
- $D$: prepaid usage deposit locked in the contract.
- $C_{\max}$: maximum ordinary per-request charge.
- $S_{\max}$: optional higher cap for policy-violation deductions.
- $B$: current private available balance.
- $L = H_{\text{leaf}}(\text{noteId}, C, D, T_{\text{exp}})$: active membership leaf.
- $E(B)$: shorthand for the note-bound homomorphic commitment
  $E(B,r,L) = B G + r H + L J$ on Baby-JubJub. The private leaf term remains
  fixed throughout every state transition and rerandomization.
- $\tau$: current state anchor.
- $x(\tau) = H_{\text{null}}(s, \text{noteId}, \tau)$: the nullifier of the state at $\tau$.
- $\text{succ}(x) = H_{\text{anchor}}(x)$: the anchor of the state that follows a request spending $x$.
- $\sigma_{\text{srv}}$: server signature on the current state $(E(B), \tau)$.
- $b$: the state's solvency bound, the same for every request from one state.
- $\sigma_{\text{clear}}$: server clearance signature on a nullifier for instant withdrawal.
- $A_{\text{srv}}$: server treasury address.
- $T_{\text{exp}}$: note expiry time / TTL.

Initial private state:
- $B = D$
- $\tau = 1$

The states of a note form a chain: $\tau_0 = 1$, $x_i = x(\tau_i)$ and
$\tau_{i+1} = \text{succ}(x_i)$. Anyone can compute the next anchor from a
nullifier; only the holder of $s$ can compute the next nullifier. Including
the note ID keeps the chains of two notes with the same secret apart.

## Registration

1. The user samples a secret $s$.
2. The user computes the registration commitment:

$$
C = H(s, 0)
$$

3. The user deposits:

$$
D
$$

into the smart contract.

4. The contract records the deposit amount $D$ and expiry $T_{\text{exp}}$, then inserts the full note leaf $L$ into the on-chain Merkle tree at the note ID.

## Request Generation

To make a request, the user sends:
- payload $M$,
- nullifier $x$,
- rerandomized balance commitment $E(B)_{\text{anon}}$,
- proof $\pi_{\text{req}}$.

The proof $\pi_{\text{req}}$ proves:

1. **Membership**  
   $L = H_{\text{leaf}}(\text{noteId}, H(s, 0), D, T_{\text{exp}})$ is in the active Merkle tree.

2. **Secret knowledge**  
   The prover knows $s$.

3. **Spend authorization**  

$$
x = H_{\text{null}}(s, \text{noteId}, \tau)
$$

   where $\tau = 1$ for the first request and otherwise the anchor of the current signed state.

4. **State validity**  
   Either genesis ($\tau = 1$ and $B = D$), or the prover knows a valid server signature on the current state:

$$
\sigma_{\text{srv}} \text{ on } (E(B), \tau)
$$

   and $\tau = \text{succ}(x(\tau_{\text{prev}}))$ for an earlier anchor $\tau_{\text{prev}}$ of the same note. A signed state at any other anchor, or at $\tau = 1$, cannot be spent.

5. **Balance correctness**  
   The prover knows the opening of $E(B)$.

6. **Rerandomization correctness**  
   $E(B)_{\text{anon}}$ is a valid rerandomization of $E(B)$.

7. **Solvency**

$$
D \geq B \geq C_{\max}
$$

If the optional policy-penalty extension below is enabled, this lower bound becomes:

$$
B \geq \max(C_{\max}, S_{\max})
$$

The public request statement includes an authorization tag binding the request
nullifier to the exact client request ID and payload hash. It also includes a
request time; the proof requires the private note expiry to be at least that
time. The server validates the current time and deployment-bound public inputs.

## Server Verification

Upon receiving a request, the server:

1. verifies $\pi_{\text{req}}$;
2. checks whether $x$ is already in `spent_nullifiers`;
3. rejects the request if $x$ was already seen;
4. otherwise stores $x$ and executes the request.

The server stores **all seen nullifiers**.

Importantly, the server does **not** need to know which state is the user's "latest" one.  
It only needs to enforce one-time use of nullifiers.

## Settlement and State Update

After execution, the server computes the actual deduction $\Delta$, with:

$$
0 \leq \Delta \leq C_{\max}
$$

The updated private balance is:

$$
B_{\text{new}} = B - \Delta
$$

The server then:

1. derives the next anchor $\tau_{\text{new}} = \text{succ}(x)$;
2. computes the updated balance commitment $E(B_{\text{new}})$;
3. signs the new state, but only while $x$ is not consumed on chain by an exit (if an exit consumed it, the signature waits and is made only if that exit is defeated):

$$
\sigma_{\text{new}} = \text{Sign}_{\text{srv}}(E(B_{\text{new}}), \tau_{\text{new}})
$$

4. returns:

$$
(\text{response}, E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

The user checks that $\tau_{\text{new}} = \text{succ}(x)$, that $\Delta$ is at most the request's solvency bound, the commitment update and the signature, then stores:

$$
(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

as their new private spend state. A successor that fails these checks is treated as withheld.

## Optional Policy Penalty Extension

The base protocol only needs the ordinary per-request cap $C_{\max}$.

If a deployment wants a stronger deterrent for policy-breaking requests, it may additionally define:

$$
S_{\max} \geq C_{\max}
$$

When this extension is enabled:
- the request proof must establish $B \geq \max(C_{\max}, S_{\max})$;
- ordinary requests still deduct at most $C_{\max}$;
- a request that violates provider policy may instead apply a policy deduction $\Delta_{\text{policy}}$ with:

$$
0 \leq \Delta_{\text{policy}} \leq S_{\max}
$$

In that case, the server still consumes the current nullifier, computes:

$$
B_{\text{new}} = B - \Delta_{\text{policy}}
$$

and returns a rejection payload together with the fresh next state $(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})$.

A practical deployment may additionally require the server to attach signed policy metadata, such as a reason code and an evidence hash, so abusive deductions remain externally auditable.

No separate on-chain policy stake or `slashPolicyStake` function is required. The larger policy penalty is just an optional bounded state transition, and it is automatically included in the eventual net settlement $D - B_{\text{final}}$.

## Withdrawal

Withdrawal is a **final spend** of a state. A withdrawal proof shows:

1. membership for the full note leaf $L$ derived from $C = H(s, 0)$;
2. knowledge of $s$;
3. a valid state $(E(B), \tau, \sigma)$ of that note (genesis, or signed);
4. knowledge of the opening of $E(B)$, with $B \leq D$;
5. the state's nullifier $x = x(\tau)$;
6. a **kind**, a payout $f$ and a conceded amount $c$ with $f + c = B$, a destination $\text{Dest}$, and a validity time $t_{\text{valid}}$ after which nobody accepts the proof.

There are three kinds. Only the first two settle on chain.

| Kind | Purpose | Extra statement |
| --- | --- | --- |
| Escape | Exit without the operator | $x^{+} = x(\text{succ}(x))$, the nullifier of the state's successor; any $c \leq B$ |
| Mutual close | Instant exit with the operator's consent | $\sigma_{\text{clear}}(x)$; $c = 0$ |
| Ownership | Prove ownership to the server | $\text{Dest} = 0$, $c = 0$, no $x^{+}$; the contract refuses it |

No withdrawal changes the Merkle tree: notes are never removed by an exit, and a proof may use any root the contract ever held.

### Mutual Close (Instant Path)

1. The user sends $x$ together with an ownership proof $\pi_{\text{own}}$ for the same $x$, valid for at most an hour.
2. The server checks whether $x$ is already in `spent_nullifiers`, and verifies $\pi_{\text{own}}$ against its deployment, signing keys and a root the contract held. Only the note owner can produce it.
3. If both checks pass, the server signs:

$$
\sigma_{\text{clear}}(x)
$$

and marks $x$ as spent in its nullifier set.

4. The user submits a mutual-close proof with $\sigma_{\text{clear}}$ as a private witness, for $(f = B, \text{Dest}, x)$, to the contract.
5. The contract verifies it, consumes $x$, and immediately settles the note.

The ownership proof shows the server the note ID, $B$ and $x$ when clearance is requested, slightly before the contract publishes them. It names no destination and no successor, and the contract refuses it, so it cannot start an escape.

### Concession Escape (Fallback Path)

If the server is offline or refuses to clear the withdrawal, the user escapes from their newest state $S_k$ with:

$$
(x_k,\ x_{k+1} = x(\text{succ}(x_k)),\ c,\ f = B_k - c,\ \text{Dest},\ t_{\text{valid}})
$$

The contract verifies the proof, consumes both $x_k$ and $x_{k+1}$, and starts the configured challenge window. If nothing defeats the escape in that window, the contract pays $f$ to $\text{Dest}$ and $D - f$ to the server, except that a payout the destination does not accept is held for it as a credit (see How the Server Gets Paid).

The user chooses $c$ from what they know:
- a state from which no request left the device: $c = 0$, normally after the operator refused or ignored a mutual close;
- a state with a request that never settled: $c = b$, the state's solvency bound, once the request's settlement time has passed; an honest operator would have delivered the successor by then;
- a state whose signed successor the user received but cannot install: $c = \min(\Delta, b)$.

The user may also escape earlier with $c = 0$, leaving the operator to raise it.

## Defeat and Raise Rules for the Escape

During the challenge window, anyone may submit a request proof for the escaped note:

- **Defeat.** A valid request proof at $x_{k+1}$ shows that the user held the successor state $S_{k+1}$ and spent it, so $S_k$ was stale. The contract cancels the escape, restores the note to active, releases both nullifiers, and records $x_k$ as challenged: no later escape from $S_k$ is accepted, and one from the state just below it is refused too. The honest user continues from their newest state.
- **Raise.** A valid request proof at $x_k$ cannot defeat the escape; it shows only that a request was made from $S_k$. It raises the concession in place:

$$
c' = \min(\text{amount},\ \text{solvency\_bound},\ B_k)
$$

  so the operator recovers what that request owes, never more than the bound the user's own proof authorized.

Because only the holder of $s$ can produce a request proof at $x_{k+1}$, and an honest user makes none once it starts to exit, an honest user's escape from its newest state is never defeated. It pays at least $B_k - b$ without any cooperation from the operator. Because the server signs a successor only at $\text{succ}(x_k)$ and only while $x_k$ is unspent, a user who spent $S_{k+1}$ cannot escape from $S_k$ undefeated.

This is the clean replacement for RLN-style secret-recovery slashing in the simplified design.

## How the Server Gets Paid

Because honest off-chain requests are unlinkable, the contract cannot settle funds on a per-request basis. Instead, it pays the server in aggregate when the note closes.

On either the instant mutual-close path or a finalized escape, the contract knows the payout $f$ (on an escape, $B_k$ minus the concession as raised). It then performs net settlement:

$$
\text{payout to user} = f
$$

$$
\text{payout to server} = D - f
$$

and closes the note.

On an escape, if the transfer of $f$ to Dest fails (Dest rejects ETH or needs more than 100,000 gas), the contract still closes the note and pays $D - f$ to the server; it holds $f$ as a credit for Dest that anyone can push to Dest later (`claimEscapePayout`). A mutual close to a destination that cannot receive ETH reverts instead, and the user proves the close again to another destination.

This means the server is paid for the user's entire lifetime of API usage in one aggregated settlement transaction, including any optional policy deductions reflected in the final private balance.

To handle abandoned accounts, each note carries the expiry time $T_{\text{exp}}$. If the note is still open and no withdrawal is in progress after its effective expiry, the server may call:

$$
\text{claimExpired}(\text{noteId})
$$

The contract then closes the note and transfers the full deposit $D$ to the server treasury $A_{\text{srv}}$. The effective expiry is $T_{\text{exp}}$ extended by any time the contract spent paused, and by at least one challenge window after a defeat. The claim is unavailable while the contract is paused and for a grace period after each unpause, and never applies to a note with a pending escape. Requests still require $T_{\text{exp}}$ to be at least the request time, so a user starts an exit well before it.

This guarantees that the server is eventually paid even if the user disappears without withdrawing. An implementation may additionally offer a separate rollover / renewal transaction that extends $T_{\text{exp}}$, but that mechanism is orthogonal to the accounting model described here.

## Privacy Note

The current state anchor $\tau$ and the server signature $\sigma_{\text{srv}}$ should remain **private witnesses inside the ZK proof**, not public inputs.

This is important because it prevents the server from trivially correlating requests by directly observing the user's carried state.

The next anchor $\text{succ}(x)$ is computable from $x$, but linking a later request to an earlier one still needs $x(\text{succ}(x))$, which needs $s$. Anyone who learns $s$ can link the note's whole request history.

In the mutual-close path, the server sees the nullifier $x$ and, through the ownership proof, the note ID and balance. The contract reveals them, with the destination, when the user closes the note. Waiting for settlement and a mutual close link nothing new.

An escape from a state that served a request links that last request to the note ID and destination for the server (it knows the request at $x_k$), and a raise publishes that request's public inputs on chain. An escape from a fresh state publishes only $x_{k+1}$, which is never used, its concession and its validity time.

## Extensions

This base design is **sequential**: one state authorizes one next request.

If parallelism is needed, it should be added as a separate extension, for example by allowing one state transition to mint multiple child anchors.

That should remain outside the base specification so the core design stays simple and easy to reason about.

## Summary

The simplified protocol replaces RLN's line-based nullifier construction with a one-time **state-anchor chain**.

Each request:
- consumes the current state,
- emits one nullifier,
- updates the private balance,
- yields a fresh server-signed next state.

This keeps the main properties we want in the single-server setting:
- anonymous prepaid access,
- unlinkable honest usage,
- replay prevention,
- net settlement at withdrawal or expiry,
- instant mutual close, with a concession escape that needs no operator cooperation,
- optional higher policy-penalty cap via $S_{\max}$.

At the same time, it substantially simplifies both the protocol logic and the proving interface.
