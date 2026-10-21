# Operating the v2 escape challenge service

`zkapi-challenged` is the operator's defence against stale and under-conceded
escapes from the concession-exit vault (circuit `zkapi-v2-concession-v1`,
vault revision 3). It follows every pending escape, reads the API server's
append-only request evidence, and, before each escape's deadline:

- **defeats** it with `challengeEscapeWithdrawal` when it holds a verified
  request proof at the escape's successor nullifier, which shows that the
  owner spent a newer state;
- otherwise **raises** its concession with `raiseEscapeConcession` to what the
  request at the escaped state owes;
- after a missed defeat, **retires** the closed note's leaf with
  `retireClosedLeaf`.

It sends EIP-1559 transactions whose fees rise as the deadline approaches. It
never signs a balance or changes usage accounting. The design is in §5.4 of
the [concession exit design](design/concession-exit.md).

Build and run it separately from the API server, after `zkapi db init`:

```sh
cargo build --release -p zkapi-serverd --bin zkapi-challenged
RUST_LOG=info target/release/zkapi-challenged \
  --rpc-url "$OPERATOR_SIGNER_RPC_URL" \
  --indexer-url http://127.0.0.1:3001 \
  --sender "$DEDICATED_CHALLENGE_ACCOUNT" \
  --deployment /etc/zkapi/deployment.json \
  --from-block "$VAULT_DEPLOYMENT_BLOCK" \
  --db-path /var/lib/zkapi/server.db \
  --checkpoint /var/lib/zkapi/challenges.json \
  --proof-setup-dir /srv/zkapi/protocol/setup/v2-concession \
  --confirmations 2 \
  --max-fee-per-gas-wei 100000000000 \
  --max-priority-fee-per-gas-wei 10000000000 \
  --status-listen 127.0.0.1:3002
```

The RPC must implement `eth_sendTransaction` using an operator-controlled
signer for the dedicated, funded sender address. A public read-only RPC is
insufficient. Configure signing permissions at that RPC; do not expose an
unlocked account over a public RPC. Use one service and one exclusive sender
per deployment. The daemon locks `<checkpoint>.lock` (`challenges.lock` above)
so two instances cannot share a checkpoint.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--rpc-url` | `ZKAPI_CHALLENGE_RPC_URL` | required | Signer RPC for `--sender`. |
| `--indexer-url` | `ZKAPI_CHALLENGE_INDEXER_URL` | required | The deployment's indexer: a hint of pending escapes, and the path of a leaf retirement. |
| `--sender` | `ZKAPI_CHALLENGE_SENDER` | required | Dedicated gas-paying account. |
| `--deployment` | `ZKAPI_DEPLOYMENT_MANIFEST` | required | The deployment manifest (`trusted_deployment` profile) the database was initialized from. |
| `--chain-id`, `--contract-address` | | the manifest's | Optional; must equal the manifest. |
| `--from-block` | | required | The vault's deployment block. Never start at the current head. |
| `--confirmations` | | 2 | Depth for scanning events and for retiring obligations. |
| `--db-path` | | required | The API server's database, opened read-only; `zkapi db init` must have created it. |
| `--checkpoint`, `--proof-setup-dir` | | required | Durable state; the deployment's proof setup, whose verifying keys must equal the adapter's. |
| `--raise-lead-seconds` | `ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS` | 21600 | A raise for an unsettled request is decided at the escape's deadline minus this, at the latest. 1800 for the drill. |
| `--raise-min-units` | `ZKAPI_CHALLENGE_RAISE_MIN_UNITS` | 0 | The smallest raise, in gwei, worth a transaction. |
| `--retire-on-miss` | `ZKAPI_CHALLENGE_RETIRE_ON_MISS` | true | After a missed defeat, retire the closed note's leaf. |
| `--defeat-gas-limit`, `--raise-gas-limit` | | 600000, 450000 | Gas limits, raised to the estimate plus 20% when that is higher. |
| `--settlement-window-seconds` | | the manifest's | The server's lease TTL + grace + settlement deadline, for the timing checks; at most the manifest's `settlement_window_seconds`. |
| `--settlement-poll-seconds` | | 2 | The server's settlement poll interval, for the timing checks. |
| `--max-fee-per-gas-wei` | `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` | required | Highest `maxFeePerGas` the daemon proposes; at most the signer's fee cap. |
| `--max-priority-fee-per-gas-wei` | `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` | required | Highest tip; at most the signer's tip cap and `--max-fee-per-gas-wei`, at least twice `--priority-fee-per-gas-wei`. |
| `--priority-fee-per-gas-wei` | `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` | 2 gwei | Tip of a first attempt. |
| `--tx-fee-cap-wei` | `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` | 1 ETH | Highest gas limit x `maxFeePerGas` of one transaction, in decimal wei (empty means the default); the upstream node's RPC fee cap. The signer's lower value applies too. |
| `--fee-bump-after-blocks`, `--fee-bump-percent` | | 3, 25 | Replacement pace and fee-cap step (10 to 100 percent). |
| `--status-listen` | `ZKAPI_CHALLENGE_STATUS_LISTEN` | `127.0.0.1:3002` | Internal `/livez`, `/health` and `/status`. Never publish it. |
| `--warning-remaining-seconds`, `--critical-remaining-seconds` | | `challengePeriod()` / 2, / 4 | Deadline escalation thresholds. |
| `--blocked-warning-seconds`, `--critical-blocked-seconds` | | 120, 1800 | Escalation of a blocked obligation. |
| `--settlement-overdue-seconds` | | 3600 | Warning when a request's settlement is this late. |
| `--indexer-divergence-seconds`, `--indexer-divergence-polls`, `--indexer-lag-warning-blocks` | | 600, 3, 64 | Divergence heuristic for indexers without block metadata; lag warning. |
| `--stale-poll-seconds`, `--startup-grace-seconds` | | 300, 300 | Liveness and first-poll grace. |
| `--observe-interval-seconds` | | 15 | Sender balance and indexer root observations. |
| `--min-sender-balance-wei` | | 600,000 gas x `--max-fee-per-gas-wei`, at most `--tx-fee-cap-wei` | Balance warning threshold. |

For the AWS deployment, [the bounded signer sidecar](../docker/aws/signer/README.md)
provides the signer RPC on a private container network, and
[the Docker guide](../docker/aws/README.md) passes these settings. The sidecar
requires an explicit `ZKAPI_CHALLENGE_CHAIN_ID` of 1 (Mainnet) or 11155111
(Sepolia) and accepts only zero-value, canonically encoded defeat
(`0xda0ce43d`), raise (`0xdd0064ba`) and leaf-retirement (`0xe41f4c31`) calls
to that chain's configured vault; a defeat or raise must carry protocol
version 2, that chain, that vault and a 256-byte proof. It checks a live
simulation, preserves the daemon's nonce, and signs EIP-1559 (type 2)
transactions with the fees the daemon proposes, within its own fee and tip
caps and transaction fee cap. It refuses with a structured reason
(`fee_out_of_bounds`, `base_fee_above_max_fee`, `insufficient_balance`,
`tx_fee_above_cap`, and the retirement refusals below) before anything is
broadcast, or with `upstream_tx_fee_cap` when its node refuses the transaction
fee. Its dedicated private key belongs only in the signer's environment. Keep
its port unpublished; the public API reverse proxy must never route to it.

The server, browser/client proving keys, verifier, and daemon must all use the
same deployment and circuit setup. A release build loads only the ceremony
keys (`mpc-1`) pinned in `zkapi-proof`; the daemon of a single-party vault
(the drill vault, or one deployed with `ALLOW_DEV_SETUP=1`) is built with the
`dev-setup` feature (the Docker image's `ALLOW_DEV_SETUP=1` build argument).

## Database access and startup

The daemon opens `--db-path` read-only and never writes to it. It requires the
schema, the append-only `request_evidence` table and the `deployment_binding`
row that `zkapi db init` writes, and refuses an older database with "run
`zkapi db init` first". At startup, before it polls, it checks:

- that the binding names the manifest's chain, vault, keys, challenge period,
  circuit, setup and verifying-key hashes, and that its own proof setup's
  verifying keys hash to the same values;
- the startup probes, over the RPC after an `eth_chainId` check: the vault's
  `CONCESSION_ESCAPE_VERSION()` is 1 and `ROOT_HISTORY_WINDOW()` 86400, its
  `proofAdapter()` is the manifest's, the adapter's `CIRCUIT_ID_HASH()`,
  `REQUEST_VK_HASH()` and `WITHDRAWAL_VK_HASH()` equal the local values, and
  the runtime code hashes of the vault, adapter and Poseidon library equal the
  manifest's;
- the vault's `challengePeriod()` equals the manifest's and the binding's;
- the timing checks: the settlement window + 2 x poll + 600 seconds is at
  most half of `challengePeriod()`, and the settlement window + the raise lead
  + 4 x poll + 1,200 seconds is at most `challengePeriod()`.

A mismatch exits non-zero: every escape could otherwise read as nothing due
and go through. An unreachable RPC is retried every 5 seconds without polling.
Start the indexer, run `zkapi db init`, start this daemon, then the API
server, and give every deployment its own database. If the API server crashed
in the middle of a write, evidence reads can fail (`evidence_db_error`) until
the API server restarts and recovers the database.

## Evidence and decisions

Each poll reads, for every pending escape, `pendingWithdrawals(noteId)` (6
words) and `pendingConcessions(noteId)` (3 words) at the same block: the
escaped nullifier `N`, the successor nullifier `N⁺`, the state balance `B`, the
concession `c` and the deadline. Its evidence is the server's
`request_evidence` table: every request proof the server reserved, written in
the reservation's transaction and never deleted. Each candidate row is
verified locally with the request verifying key, and its nullifier and
deployment fields are checked against the vault. Lease rows are read only to
learn what is owed.

The decision, in this order:

1. **Defeat.** If any verified row exists at `N⁺`, whatever its lease status
   (a reservation counts, even one the server refused to deliver because the
   escape had consumed the nullifier), send
   `challengeEscapeWithdrawal(noteId, inputs, proof)` with the oldest such row.
   It needs neither the indexer nor the live root.
2. **Raise.** Otherwise, once the amount owed at `N`, Ω, is final, or at
   `deadline − --raise-lead-seconds` at the latest: if `min(Ω, solvency bound, B)`
   exceeds `c` by at least `--raise-min-units`, send
   `raiseEscapeConcession(noteId, inputs, proof, Ω)` with the row at `N` that
   has the largest solvency bound.
3. Otherwise nothing is due (`nothing_due`). This is the honest outcome.
4. After a raise, the daemon keeps watching for evidence at `N⁺` until the
   deadline.

Ω is read from the server's records of the request at `N`:

| Record at `N` | Ω |
| --- | --- |
| Signed (`Finalized`) | its `charge_applied` |
| Settled but unsigned (`exit_deferred`, `ExitedUnsigned`, or `Reserved` with a settled charge) | its settled charge |
| `Reserved`, possibly delivered (a key issued and not known undelivered, an unreadable lease row, or a lease cancelled with a delivered key), not settled by `deadline − --raise-lead-seconds` | its solvency bound |
| `Reserved` and never issued or never delivered; a reservation without a lease row; `ClearanceReserved`; no record | 0 |

A request that may have been delivered and is not settled yet is
`awaiting_settlement` until it settles or the raise lead arrives. Rows at
`N⁺` that do not verify defeat nothing: they never hold back the raise at
`N`, but block the obligation as `evidence_invalid` (critical at once), and
count as a possible missed defeat if the escape is paid out. A database read
failure is `evidence_db_error`, critical at once; neither is ever treated as
"no evidence".

An honest owner escaping from its newest state is never defeated: only the
owner can make a request proof at `N⁺`, and its wallet makes none once it
starts to exit. A defeat therefore means the owner escaped from a stale
device or backup; the note returns to active and the owner exits from the
newer state.

## The nonce lane

The daemon uses one sender and one nonce lane. A same-nonce replacement may
change only fees (and, for a retirement, siblings), with one exception: a
**defeat may replace an unmined raise** on the same nonce, when evidence at
`N⁺` appears while the raise is pending. A raise never replaces a defeat. The
call and its digest are persisted with every attempt before it is sent, so
the transition survives a restart. A raise that lands first does not block
the defeat, which goes on the next nonce; a raise that mines after a defeat
reverts harmlessly. Once a defeat lands, the note's pending raises are
dropped, and a raise that became moot releases its nonce if nothing was
broadcast on it.

## Building and sending a transaction

Below, a *challenge* is any of the daemon's three calls: a defeat, a raise or
a leaf retirement. Each poll verifies the RPC chain ID. Before sending, the daemon checks the
on-chain pending escape and its deadline, the evidence row's proof and its
deployment binding (its state key must be the vault's), and the complete call
with `eth_call`. It never rewrites a historical public root: request evidence
is valid at any root. A defeat's gas limit is 600,000 and a raise's 450,000,
each raised to the estimate plus 20% when that is higher; a leaf retirement's
is its estimate plus 20%, about 7.2M.

A leaf retirement needs the indexer's path for the note at the vault's live
root. A path whose siblings do not hash to it is `indexer_path_behind` (a
warning that escalates with time) when the indexer's view is consistent with
the vault at its block, and otherwise `indexer_invalid_response`, critical at
once; a stale path is never sent.

Every send carries both `maxFeePerGas` and `maxPriorityFeePerGas`, so the daemon
needs a signer that accepts them (the bundled signer from this release). The
first bid is twice the base fee plus the priority fee, within the limits below
and the [transaction fee ceiling](#transaction-fee-ceiling). The pending
transaction at the head of the sender's queue is replaced on the
same nonce when it is not mined after `--fee-bump-after-blocks`, when the base
fee rises above its fee cap, when it or a challenge queued behind it becomes
critical, or, for a leaf retirement, when the vault root moved since it was
built (the replacement then carries fresh siblings). A replacement raises the tip by 10% (rounded up) and
the fee cap by `--fee-bump-percent`, and at least to twice the base fee plus the
tip; geth and reth accept a replacement only when both rise by at least 10%.
Fees on a nonce never decrease, with one exception: a nonce that no attempt
holds (the RPC knows none of its hashes and the pending count has not passed it)
is re-sent at its earlier fees, lowered to the current caps, ceiling and balance
where they exceed them, which is logged at warn level. The call, note, request
inputs, proof and raise amount are fixed per nonce (a persisted digest is
compared on every send), except for the defeat that replaces a raise.

Because both fees must rise by 10%, the caps allow a limited number of
replacements on a nonce: about seven when the tip cap is twice the first tip.
Two of them are kept for the critical threshold. The caps here are the daemon's
tip cap and its effective fee cap, min(fee cap, ceiling / gas limit). Until an
obligation (or one queued behind it) is critical, bids stay within 100/121 of
both caps, that is 10/11 twice, and only go higher when the base fee needs it.
When only those two are left, the pending challenge is kept and reported as
blocked by `fee_reserve_held`, with the detail `the remaining fee headroom is
reserved for the critical threshold`. It is not replaced again before the
critical threshold (`challengePeriod()` / 4 before the deadline by default)
unless the base fee rises above it, so a market that needs a higher tip delays
its inclusion until then. Like an exhausted cap, the hold therefore warns after
`--blocked-warning-seconds` and turns critical after
`--critical-blocked-seconds`. The limit that holds it is 100/121 of the tip cap
and of the effective fee cap. Raising both caps (the signer's first, each
service restarted with its new settings, as in
[When no valid bid remains](#when-no-valid-bid-remains)) lets the next poll
replace the challenge once 100/121 of the new caps is at least 10% above both
of its fees. A 10% raise is enough for a bid at
that limit. A bid placed higher while the base fee needed it cannot be replaced
once the base fee falls back: from 10/11 of the caps it is held, and from the
caps themselves it reports `fee_cap_reached`, `tip_cap_reached` or, when the
ceiling limits the effective fee cap, `tx_fee_cap_reached` (then
`fee_reserve_held` after a smaller raise). It needs just over 21% or 33% more
on both caps (1.21 or 1.1 x 1.21 times them). The effective fee cap follows
the fee cap only up to the ceiling / gas limit,
`sender.tx_fee_cap_max_fee_per_gas_wei` on `/status`; to raise it further, also
raise the node's `--rpc.txfeecap` and
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` for the signer and the daemon. Without such a
change, the challenge is replaced at the critical threshold. A critical
obligation bids 10/11 of both caps, then the caps themselves. A pending bid that
the base fee has risen above may spend the reserve earlier, since it cannot be
included otherwise. Stale-root replacements do not spend the reserve either:
when only the reserve is left, a pending challenge with outdated siblings is
kept, and if it reverts the daemon resubmits on a new nonce after the
confirmation depth. With the tip cap at twice the first tip, about five
replacements come before the critical threshold; a higher tip cap leaves room
for more, within the signer's tip cap (10 gwei by default, 5 times the default
priority fee). The daemon does not read the signer's fee or tip cap: a bid
above either is refused with `fee_out_of_bounds`, reported as
`signer_refused` (critical at once), instead of being lowered to the signer's
cap. Keep the daemon's caps at or below the signer's, and raise the signer's
first.

Simulation reverts are classified: `NotPendingWithdrawal()` and
`ReplayedNullifier()` mean the escape was already resolved
(`resolved_unconfirmed`, checked again next poll); `NotARaise()` means the
concession already covers the raise (`raised`, read again next poll);
`ChallengeExpired()` and other reverts are reported as `simulation_reverted`;
`NotSuccessorEvidence()`, `NotStateEvidence()` and `InvalidProof()` mean the
evidence does not fit the vault's escape or verifier (`evidence_invalid`,
critical at once).
A leaf retirement reverts `StaleRoot()` (`0x607447de`) when an unrelated
deposit or retirement changes the root first; it is blocked as
`indexer_path_behind` and rebuilt from a fresh path. Anyone can cause such a
race at their own gas cost, and a reverted retirement still pays most of its
gas, so fund the sender for reverted attempts. Defeats and raises do no
Merkle work and never revert on a root change. The bundled signer does not
forward revert data from its simulation, so through it these all appear as
transient simulation failures and are retried.

Private or MEV-protection relays may hide pending transactions from
`eth_getTransactionByHash` and may delay, refuse or drop same-nonce
replacements. The daemon then sees nonces as held by unknown attempts and keeps
re-bidding at the replacement pace. Prefer a full-node RPC, and verify a relay's
pending visibility and replacement behaviour on Sepolia first.

## Transaction fee ceiling

geth and reth refuse `eth_sendRawTransaction` before the transaction reaches
their pool when its gas limit x `maxFeePerGas` exceeds `--rpc.txfeecap`, 1 ETH
by default. Every bid (the first, each replacement and re-send, and the critical
bids) is therefore bounded by a transaction fee ceiling divided by the exact gas
limit it is sent with. The ceiling is the lowest of `--tx-fee-cap-wei` /
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (default 1 ETH), the signer's
`tx_fee_cap_wei`, which the bundled signer reports in `zkapi_signerStatus` (read
every `--observe-interval-seconds`) and in its `tx_fee_above_cap` refusals, and
a bound learned from the node's own refusals (`upstream_tx_fee_cap`, below). A
signer that reports none leaves the daemon's own value. At 1 ETH the ceiling
allows about 1,666 gwei for a 600,000-gas defeat, about 2,222 gwei for a
450,000-gas raise, and about 138.9 gwei for a 7.2M-gas leaf retirement,
whatever the fee cap. Set both
variables to the RPC fee cap of the node behind the signer; in
[the Docker deployment](../docker/aws/README.md#challenge-signer-and-daemon) the
daemon reads it from `deployment.env` and the signer from `signer.env`. Raising
the caps beyond that needs the node's `--rpc.txfeecap` raised together with both
variables.

`/status` warns when the daemon's and the signer's values differ, and when the
latest gas limit (at least 600,000) x `--max-fee-per-gas-wei` exceeds the
ceiling: that part of the fee cap is
never used. It shows the ceiling in force as `sender.effective_tx_fee_cap_wei`,
the signer's value as `sender.signer_tx_fee_cap_wei` (with
`sender.signer_status_detail` when it cannot be read), the bound learned from
the node as `sender.node_tx_fee_cap_bound_wei`, and the highest fee per gas the
ceiling allows at the latest gas limit as
`sender.tx_fee_cap_max_fee_per_gas_wei`.

## When no valid bid remains

The obligation reports:

- `base_fee_above_fee_cap`: the base fee exceeds the daemon's fee cap; nothing
  is sent.
- `tx_fee_cap_reached`: the base fee exceeds the most the transaction fee
  ceiling allows per gas, or the ceiling keeps the pending challenge's max fee
  from rising by the 10% a replacement needs (reported even when the tip cap is
  reached too). Nothing is sent, the pending challenge stays in the pool, and an
  alarm shows the ceiling, the fee per gas it allows and the base fee. A
  challenge that a daemon without the ceiling bid above it is kept and observed
  in the same way while a node may hold it. Once the RPC knows none of its
  hashes, no send on its nonce had an unknown outcome, and the pending count has
  not passed the nonce, it is re-sent within the ceiling, provided its
  obligation is still pending and a bid within the ceiling is includable before
  the deadline. A nonce that such a daemon locked at a refused bid, with
  candidate hashes no node knows, is otherwise not recovered automatically, and
  it blocks later notes until it is consumed. If the escape was finalized or
  replaced before the upgrade, the nonce is reported as `unmined nonce N of a
  completed or replaced note M requires signer intervention`. If the deadline
  passes first (for example while the base fee stays above the ceiling), the
  missed obligation is first reported as blocked by `nonce_blocked` (alarm
  `note M missed (nonce_blocked)`), with the detail `expired obligation retains
  unmined reserved nonce N, which an attempt may hold; resolve it at the
  signer` and its bid in the obligation's `max_fee_per_gas_wei`. Only once the
  escape is finalized is the nonce reported as `unmined nonce N of a completed
  or replaced note M requires signer intervention`. The daemon cannot tell those
  hashes from a broadcast transaction; see
  [Recovery and verification](#recovery-and-verification).
- `fee_reserve_held`: the pending challenge spent the replacements allowed
  before the critical threshold (see
  [Building and sending a transaction](#building-and-sending-a-transaction)).
- `fee_cap_reached` or `tip_cap_reached`: no valid replacement within the caps.
- `insufficient_balance`: the fee cap is also limited to balance / gas.

Raise the signer's caps in `signer.env` and restart the signer first, then raise
the daemon's caps (never above the signer's) and restart the daemon; it then
replaces its pending challenge. Each service reads its settings only at
startup. In the Docker deployment a container reads its environment files
only when it is created, so recreate it
(`docker compose up -d --no-deps signer`, then `challenger`):
`docker compose restart` keeps the old values. For `tx_fee_cap_reached`, raise
the ceiling as described above, starting with the node's RPC fee cap; raising
only the fee cap changes nothing. Fund the sender for every transaction that may be pending at
once plus reverted attempts: each needs gas limit x fee cap (600,000 gas for a
defeat, 450,000 for a raise, about 7.2M for a leaf retirement), but never more
than the ceiling. Size it for `⌈m/2⌉` defeats per note (a user holding `m`
archived states can force that many, each about 375,000 gas), at most 64
concurrent escapes, and a 20% margin. Status warns when the balance cannot
cover the outstanding obligations at the proposed fee cap, or is below
`--min-sender-balance-wei`. There is no spending budget beyond the
per-transaction caps, the ceiling and the sender balance. The
[signer README](../docker/aws/signer/README.md#fee-spike-runbook) has the fee
spike runbook.

Signer errors other than `broadcast_ambiguous` mean nothing was broadcast. This
includes `tx_fee_above_cap` (refused before any upstream call) and
`upstream_tx_fee_cap` (the node refused the broadcast before its pool). A
`broadcast_ambiguous` error carries the candidate transaction hash, which the
daemon keeps. A transport error or a timeout (the send waits up to 95 seconds)
is treated as possibly broadcast: the next send on that nonce must outbid the
highest fees that may be in a pool, by at least 10% on both, and is paced like a
replacement. The other errors roll the attempt back. Refusals report their own
reason:

- `base_fee_above_max_fee`: the base fee rose above the bid before the signer
  checked it; the next poll bids from the new base fee.
- `tx_fee_above_cap`: the bid exceeded the signer's transaction fee cap. The
  daemon learns that cap from the refusal (its `tx_fee_cap_wei`, or
  `max_fee_per_gas_allowed` x `gas_limit`) and stays within it from the next
  bid. Give the signer and the daemon the same value.
- `upstream_tx_fee_cap`: the signer's node refused the transaction fee, because
  its RPC fee cap is below the ceiling. This is critical at once. The node never
  reports its cap, so the daemon lowers the ceiling to 10/11 of the lowest
  transaction fee it refused (`sender.node_tx_fee_cap_bound_wei`). The refused
  fee is the refusal's `gas_limit` x `max_fee_per_gas`, each taken from the
  refused bid when the signer omits it. A product that leaves no bound, such
  as zero, is ignored like a zero `tx_fee_cap_wei`, and the refused bid's own
  gas limit x `maxFeePerGas` is used instead. Each refusal lowers the next bid
  by at least 9% until the node accepts one, usually within a few polls. The
  bound stays above 10/11 of the node's cap, so at most about 9% of that cap
  goes unused. It lasts until the daemon restarts, with a
  `/status` warning that names the refused fee and the remedy. Lower
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` for both services to the node's cap and
  restart both with the new value (in the Docker deployment, recreate both,
  as above), or raise the node's cap and restart the daemon, which clears the
  bound.
- `insufficient_balance`, and `signer_refused` for any other refusal.

A nonce on which no attempt was broadcast is released, as long as neither the
latest nor the pending transaction count has passed it. That applies when every
attempt on it was refused, failed before the signer broadcast it
(`simulation_failed`, `upstream_*`, `base_fee_unavailable`), or never reached
the signer (connection refused). The release happens at once, or when the plan
cannot send, at the deadline, at retirement, or once the nonce is detached.
Later notes then use it. A nonce reserved by a daemon from an earlier release
without an attempt record is never released this way.

## Missed defeats, missed raises and leaf retirement

When an escape the daemon tracked is paid out, it records a miss:

- a **missed defeat** when verified evidence at `N⁺` existed before the
  deadline (`escapes_finalized_with_successor_evidence_total`);
- a **missed raise** when more than the concession was owed at finalization
  (`missed_raises_total`).

Both count in `missed_total`, log `MISSED escape deadline` at error level with
`missed="defeat"` or `missed="raise"`, and stay a critical alarm
(`last_missed`) for an hour. A miss means the daemon was down, blocked, or out
of funds or fee headroom through the whole window; find the cause before the
next deadline.

After a missed defeat, with `--retire-on-miss` (the default), the obligation
turns to `retiring_leaf` and the daemon calls
`retireClosedLeaf(noteId, siblings)` with the indexer's path at the live root.
That bounds the operator's loss: the API server admits requests only at the
current root, so once the leaf is retired it refuses every request built on
the note, including from the owner's newer state. The obligation stays a
warning until the retirement mines; a zero leaf means it is done. Set
`ZKAPI_CHALLENGE_RETIRE_ON_MISS` to the same value for the signer sidecar,
which refuses every retirement when it is `false`.

### The signer's retirement budget

A leaf retirement costs about 6M gas, far more than a defeat or a raise, so
the bundled signer bounds what a compromised daemon host could spend on it:

- it signs `retireClosedLeaf` only while `ZKAPI_CHALLENGE_RETIRE_ON_MISS` is
  on (`retirement_disabled` otherwise), and only for a note whose escape
  finalized within `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS` (default
  50,400), read from the vault's `EscapeWithdrawalFinalized` logs
  (`retirement_not_after_escape` for a note closed by a mutual close or an
  expiry claim);
- `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY` (default 2; 0 refuses all) counts
  retirement nonces per rolling 24 hours, not notes. Fee replacements and
  re-sends on a counted nonce are free; a further one is refused with
  `retirement_budget_exhausted` before any upstream call;
- the same note on a new nonce takes a new unit, and is refused with
  `retirement_in_flight` (data `retirement_nonce`) while the sender's latest
  transaction count has not passed its earlier counted nonces. Nothing is
  broadcast and no budget is taken.

One missed defeat takes one unit, plus one for each re-send after a root race.
Retirement gas is therefore at most the budget x the signer's maximum gas x
its fee cap per day, whether the retirements succeed or revert. The daemon
reports every signer refusal as `signer_refused`, critical at once. The
reason is on the signer's `challenge_refused` audit line, and each has its
own fix:

| Reason | Cause | Fix |
| --- | --- | --- |
| `retirement_budget_exhausted` | The rolling day's budget is spent, usually by re-sends after root races | Raise `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY` in `signer.env` and recreate the signer |
| `retirement_not_after_escape` | No `EscapeWithdrawalFinalized` of the note within the lookback. After an outage longer than the lookback (about seven days) the restarted challenger meets this for an escape that finalized while it was down | Raise `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS` past the escape's finalization and recreate the signer. For a note no escape closed (a mutual close or an expiry claim), the daemon misbehaves |
| `retirement_in_flight` | A retirement of the note on a new nonce while an earlier counted nonce may still mine | The daemon misbehaves, or a lagging upstream answered the nonce count; it clears once the earlier nonce mines |
| `retirement_disabled` | `ZKAPI_CHALLENGE_RETIRE_ON_MISS` differs between `deployment.env` and `signer.env` | Set the same value in both and recreate the signer |

Until the retirement mines, the loss bound of a missed defeat (design §7.4,
service from the owner's newest state) keeps running. `zkapi_signerStatus`
and the signer's `/health` report `max_retirements_per_day`,
`retirements_last_24h` (nonces), `retirement_refusals` and
`last_retirement_refusal_at`. The window is kept in memory, so a signer
restart resets it. The signer's worst-case send makes seven sequential
upstream calls, about 56 seconds, within the daemon's 95-second send timeout.
See [the signer README](../docker/aws/signer/README.md).

## Recovery and verification

The checkpoint records the deployment and sender, next scan block, block hash,
pending nullifiers and deadlines, reserved transaction nonces, every candidate
transaction hash with the latest attempt's fees and gas limit, the evidence
digest, the missed-deadline count and the nullifiers of the misses it counted.
It is written before each send, with
atomic replacement after syncing the file. Older checkpoints load unchanged;
older binaries ignore the new fields. Never delete it: it holds reserved nonces.
The service refuses checkpoints from another chain, vault or starting block.
Scans are bounded to 1,000 blocks. A checkpoint block that has another hash on
two reads causes replay from the deployment block. A null or hash-less answer
for it, as from a load-balanced backend that has not reached the block, fails
the poll and is retried instead. Pending entries are reconciled against the
current vault state before submission.

Returned transaction hashes suppress duplicate submissions while the RPC still
knows the unmined transaction; confirmed nonce consumption allows an outstanding
withdrawal to refresh its path and retry. Dropped or orphaned transactions are
resubmitted on their reserved nonce once the RPC no longer knows their hashes.
Ambiguous send errors retain the nonce across restart. Obligations are retired
only after the pending escape also disappears at the configured confirmation
depth, preventing a tip reorg from silently losing the obligation.

When a tracked escape is gone at the confirmation depth after its deadline
and a defeat or a raise was due, the daemon reads how the escape ended before
retiring it. A note that is not closed was not paid out. For a closed note,
`challengedNullifiers(nullifier)` tells, or, when that read fails, the
escape's `EscapeWithdrawalChallenged` or `EscapeWithdrawalFinalized` log. The
daemon searches for that log from a block no later than the escape's end (its
event's block, or a block where it was read pending, once that block is
confirmed) up to the confirmed block, 1,000 blocks per request and at most 8
requests per poll, resuming after a restart. A closed note with no logged
defeat is taken as paid out. Here "paid out" means finalized: a finalized
escape whose destination rejected the payout was credited to
`escapePayoutCredits(destination)` instead, which changes nothing for the
challenger. A payout is recorded as a missed defeat or raise before the
obligation retires (or turns to `retiring_leaf`). While the evidence database cannot be read, the obligation stays
tracked, blocked by `evidence_db_error`, and the poll fails. An obligation
queued behind an unresolved nonce, which the poll loop does not reach, is read
the same way: a payout is recorded as a missed deadline when found, and an
escape a defeat ended is shown resolved (severity ok); the obligation and its
nonce retire once the queue reaches it.

Nonce reconciliation runs before checking a withdrawal's deadline, evidence or
continued existence. A reserved nonce consumed in the latest block no longer
blocks other notes, even when the original send returned no hash and its
challenge has expired. Its ownership remains in the checkpoint until consumption
reaches the configured confirmation depth; a tip reorg therefore cannot silently
forget the reservation. A reverted transaction is eligible for a fresh nonce
after that confirmation depth. If a withdrawal disappears or a replayed event
replaces its nullifier, the checkpoint retains its outstanding nonce separately
until confirmed consumption.

An **unmined** nonce whose withdrawal has expired or been replaced is released
when nothing was broadcast on it (see
[When no valid bid remains](#when-no-valid-bid-remains)). Otherwise it still
prevents new allocations, because a transaction signed for it may still be
pending: it has a candidate hash, a send's outcome was unknown, or a daemon from
an earlier release reserved it without a record. While the expired escape is
still pending, its obligation is blocked by `nonce_blocked` (`expired obligation
retains unmined reserved nonce N, which an attempt may hold; resolve it at the
signer`). Once the escape is finalized or replaced, the detached nonce is
reported as critical (`unmined nonce N of a completed or replaced note M
requires signer intervention`). The daemon does not reuse the nonce for another
note or send a cancellation, and the bounded signer does not expose cancellation
calls. Look up the candidate hashes on `/status` (`detached_nonces`, or the
obligation's `transaction_hash` and `superseded_hashes`) on a full node: a
pending one mines or reverts by itself, and the queue then continues. Only when
no node knows any of them and the nonce stays unmined, consume the nonce with
the sender's key outside the sidecar, for example with a zero-value transfer
from the sender to itself at exactly that nonce. Each detached nonce on
`/status` also shows the latest recorded bid (`max_fee_per_gas_wei`,
`max_priority_fee_per_gas_wei`, and `gas_limit`, which records from earlier
releases lack). When gas limit x
`maxFeePerGas` exceeds the node's RPC fee cap, the node refused that bid before
its pool, although a signer from an earlier release reported the refusal as
possibly broadcast: this is the usual cause of a nonce that no node knows, left
by a daemon that bid above the transaction fee ceiling. This restriction is
distinct from an expired obligation whose nonce has already mined; that
obligation cannot starve the remaining queue.

The checkpoint records each attempt's call (defeat, raise or retirement) with
its evidence row and raise amount. A checkpoint from a daemon of the legacy
circuit is refused: it belongs to another vault.

## Escape completeness

The event scan reads `EscapeWithdrawalInitiated`, `EscapeConcessionRecorded`,
`EscapeConcessionRaised` and `EscapeWithdrawalChallenged`, and can miss an
escape when the RPC's `eth_getLogs` lags its head. Every poll therefore also
reads the indexer's internal `GET /v1/escapes/pending` list. Only its note IDs
count: for each listed note that the checkpoint does not track under the
listed nullifier, the daemon reads the vault's `pendingWithdrawals(noteId)` and
`pendingConcessions(noteId)` and tracks the escape the vault holds, whatever
the list says. Escapes change no leaf, so the indexer's root check does not
cover the list at all: a listed nullifier, deadline or concession is a hint,
and an entry can outlive its escape when the indexer's logs missed how it
ended. A listed nullifier that differs from the vault's is shown as
`indexer.pending_escapes_disagreement` on `/status`, is logged at warn level,
and warns after `--blocked-warning-seconds`; if it persists, resync the
indexer.

Per poll the daemon reads the vault for at most 64 listed notes it does not
track. Each poll starts where the previous one stopped and wraps around, so
every listed note due for a read is read within ceil(n / 64) polls. A listed
note that the checkpoint does not track and whose escape the vault does not
hold, a dead entry, is still read on every poll until reads 60 seconds apart
have found none: the indexer's head view can be ahead of the daemon's RPC, so
a fresh escape can read as absent at first. After that it is read again only
every 16 listings (polls that read the list), so dead entries cannot crowd out
the escapes listed after them. A later escape of that note that the event scan
misses is still tracked within about 16 polls, or at once when the list names
its new nullifier. A dead entry means that the list lags the vault, or that the
indexer's log source missed how that escape ended (for example, a dropped
finalization), in which case the indexer keeps the entry until a resync. The
note is shown in `indexer.pending_escapes_disagreement` as `N listed note(s)
with no pending escape in the vault: note ID listed with nullifier 0x…`, and
the same warning to resync the indexer is raised, once two conditions hold:

- reads `--blocked-warning-seconds` apart have found no escape;
- a list served at a block between two of those reads still names the note:
  at or above the daemon's RPC head at the poll after the first read, and at
  or below its head at a later read that finds no escape.

A list served below the first read may only lag the vault, and one served
beyond the daemon's head may hold an escape that its RPC does not show yet;
neither is reported. A stalled indexer's dead entry therefore stays unreported
until its list passes the first read; watch the indexer's own `/health`
(`stale`) and `head_age_seconds` for that. A list served without
`block_number` is judged on time alone. The daemon reads such a note again as
soon as that period has passed and a listing can complete the report, so the
report waits for a confirming read. A note the checkpoint
tracks is never reported this way, because its vault record is read on every
poll. The read position and the dead entries are kept in memory only: after a
restart every listed note is read again within ceil(n / 64) polls, and a
report waits another warning period. The check in
[the Docker guide](../docker/aws/README.md#indexer-resync), step 1, also finds
dead entries, through another RPC; resync an indexer that lists any. An
indexer without the endpoint shows a permanent `unsupported` warning, and an
unavailable list warns after `--blocked-warning-seconds`.

The daemon also reads `pendingWithdrawals(noteId)` and `pendingConcessions(noteId)`
for every tracked note on every poll. When the vault holds a different escape
(the owner escaped again after a defeat, or a replayed event tracked an older
one), it tracks the
vault's escape and logs `the vault holds a different escape than the one
tracked for this note; tracking the vault's` at warn level. The old
obligation's nonce stays reserved until it is consumed, or is released when
nothing was broadcast on it.

## Status, health and alerting

The status listener serves three internal routes, all with
`Cache-Control: no-store`:

- `GET /livez`: 200 `{"status":"alive"}` while the poll loop started or finished
  an iteration within `--stale-poll-seconds`, or within `--startup-grace-seconds`
  of start; otherwise 503 `{"status":"stale"}`. Use it for container
  healthchecks only.
- `GET /health`: 503 when anything is critical, otherwise 200 (`ok` or
  `warning`), with `{status, generated_at, poll_age_seconds, obligations,
  critical_obligations, alarms}`. Alert on any answer other than 200, and on
  no answer at all: a stopped or crash-looping daemon reports nothing itself,
  so also watch that its process or container is running.
- `GET /status`: the full snapshot, schema `zkapi-challenged-status/v2`: overall
  `status` and `alarms`, the thresholds in force, chain head and scan progress,
  poll timing, sender balance and nonces, the fee caps and the transaction fee
  ceiling (`tx_fee_cap_wei`, `signer_tx_fee_cap_wei`,
  `node_tx_fee_cap_bound_wei`, `effective_tx_fee_cap_wei`,
  `challenge_gas_limit`, `tx_fee_cap_max_fee_per_gas_wei`), indexer state,
  every obligation, detached nonces with their latest recorded bid,
  `missed_total`, `escapes_finalized_with_successor_evidence_total`,
  `missed_raises_total` and `last_missed`. Wei values are decimal strings. It contains
  no client request IDs.

Remaining time and severity are recomputed at request time from the absolute
deadlines and the latest block timestamp, so escalation continues while polls
stall. Each obligation has a `state`:

| State | Meaning | Severity |
| --- | --- | --- |
| `unevaluated` | Tracked, not evaluated since the daemon started | by remaining time |
| `nothing_due` | No verified evidence at `N⁺`, and the concession covers what is owed at `N` | ok, unless blocked |
| `awaiting_settlement` | What is owed at `N` is not final; the raise is decided once it settles, or at the raise lead | warning once the settlement is `--settlement-overdue-seconds` late, unless blocked |
| `ready` | A defeat or a raise is due and not pending | by remaining time |
| `submitted` | A defeat, raise or retirement is pending on the obligation's nonce | by remaining time |
| `mined_unconfirmed` | A defeat's nonce was consumed while the escape is still pending (it reverted) | by remaining time |
| `raised` | The concession covers what is owed after a raise; the escape is watched for evidence at `N⁺` until its deadline | ok, unless blocked |
| `resolved_unconfirmed` | The escape is gone at the latest block, not yet at confirmation depth | by remaining time while a defeat or raise was due, else ok |
| `missed` | The deadline passed while a defeat or a raise was due | critical |
| `expired_nothing_due` | The deadline passed and nothing was due | ok |
| `retiring_leaf` | After a missed defeat, the closed note's leaf is being retired | at least warning |

By remaining time, an obligation warns within `--warning-remaining-seconds`
and is critical within `--critical-remaining-seconds`. A blocked obligation is
critical at once when blocked by `evidence_invalid`, `evidence_db_error`,
`indexer_invalid_response`, `indexer_diverged`, `signer_refused` or
`upstream_tx_fee_cap`; other blocked reasons (`indexer_unavailable`,
`indexer_path_behind`, `rpc_error`, `simulation_reverted`, `send_ambiguous`,
`base_fee_above_fee_cap`, `base_fee_above_max_fee`, `fee_cap_reached`,
`tip_cap_reached`, `fee_reserve_held`, `tx_fee_cap_reached`,
`tx_fee_above_cap`, `insufficient_balance`, `nonce_conflict`,
`nonce_blocked`) warn after `--blocked-warning-seconds` and turn critical
after `--critical-blocked-seconds`. Each obligation also shows its `evidence`
kind (`successor`, `settled`, `unsettled`, `never_delivered`,
`reserved_without_lease`, `clearance`, `unknown`, `corrupt`, `unavailable` or
`leaf`) and, once known, what is owed.

Stale polls, no successful poll after the startup grace, no new head block for
600 seconds, an event scan 300 blocks behind, a diverged indexer and an unmined
detached nonce are also critical. An obligation blocked by
`tx_fee_cap_reached` also raises a warning with the ceiling, the fee per gas it
allows at the latest gas limit and the base fee, and a bound learned from
`upstream_tx_fee_cap` refusals warns with the refused fee until the daemon
restarts. State changes are logged as
`challenge obligation status changed` at info, warn or error level, and critical
items are logged again every 300 seconds. A deadline that passes while a
defeat or a raise was due logs `MISSED escape deadline` once and increments
`missed_total` (see
[Missed defeats, missed raises and leaf retirement](#missed-defeats-missed-raises-and-leaf-retirement)). Whether the escape was still pending at its deadline
is read at the head block (`pendingWithdrawals` at the head's number), not at
`latest`: behind a load-balanced RPC, a backend behind the head could still show
an escape that a defeat mined just before the deadline ended. A backend
without the head block fails that read, and the next poll reads again. An
escape with a defeat or raise due that the daemon finds paid out past its
deadline at confirmation depth is also recorded as missed. That includes one it first sees
after the payout (for example after downtime longer than the challenge period)
and one queued behind an unresolved nonce; see
[Recovery and verification](#recovery-and-verification). Each
escape's miss is counted once, keyed by its nullifier, also across replays and
restarts. The latest miss (`last_missed`) stays a critical alarm on `/status`
and `/health` for an hour after it was recorded. The window cannot be extended: page a human at
the warning threshold.

Never route the status listener through a public proxy; it tells an attacker
when challenges are blocked.

## Indexer divergence

Defeats and raises need no indexer. A diverged indexer still blocks leaf
retirements, which need its path at the live root, weakens escape
completeness (its pending-escapes list), stops the API server's admission
(`root_unavailable`), and leaves deposits and clients without a deposit-time
path or an exit RPC without Merkle paths. The daemon compares the indexer's
`/v1/tree/root` with the vault's `currentRoot()`. When the indexer reports a
block hash, it reads `currentRoot()` at that block (EIP-1898): equal roots mean
the indexer is only lagging, different roots mean it diverged. Older indexers
without block metadata fall back to a heuristic: a mismatch lasting
`--indexer-divergence-seconds` over `--indexer-divergence-polls` polls. An
indexer `/health` status of `diverged` also counts. Divergence is critical
and logs
`indexer mirror diverged from vault currentRoot; challenges cannot be built until the indexer is resynced`.

Symptoms: indexer `/health` 503 with `diverged`, or `syncing`, `stale` or
`rebuilding` for longer than a replay takes; obligations blocked by
`indexer_diverged` or, persistently, `indexer_path_behind`; clients failing
with `indexer_root_lag`. Waiting never repairs a divergence. Compare the
indexer's root with the vault through an independent RPC, then resync it as
described in [the Docker guide](../docker/aws/README.md#indexer-resync). A
replay takes about (head − deployment block) / 1000 log requests at 100 ms
each plus verification; start it well before the nearest deadline that needs
a retirement.

The indexer verifies only its root and next note ID, and escape events change
no leaf, so escape events its RPC's `eth_getLogs` dropped leave its `/health`
`ok`. A later event of the note that the indexer applies without having seen
its escape counts in `missed_re_escape_count` and
`zkapi_indexer_missed_re_escapes_total` (logged at error level for a
finalization). The daemon reports a listed note whose escape the vault does
not hold in `indexer.pending_escapes_disagreement` (see
[Escape completeness](#escape-completeness)), and the daily dead-entry check in
the Docker guide finds it too. If that count rises, a dead entry appears, or
`indexer.pending_escapes_disagreement` persists, fix or replace the indexer
RPC's log index, then resync. Meanwhile the daemon follows the vault's escape
for every note it tracks.

## Availability

Keep the API server, database, checkpoint, signer and sender funding available
throughout every challenge window, and the indexer for leaf retirements and
escape completeness. The API server's reservations write the request evidence
the daemon defeats and raises with, and its settlement fixes what is owed; an
outage of its settler delays raises up to the raise lead, after which an
unsettled request is raised to its bound. The API's
`GET /v2/nullifiers/{nullifier}` and `GET /v2/requests/{id}` are how an owner
recovers a signed successor, and `GET /v2/nullifiers/{nullifier}/evidence`
serves the wallets' stale-device check. RPC and signing latency, confirmation
depth, and any restart time must fit within the vault's challenge window, and
the challenger must be healthy before the first deposit.
