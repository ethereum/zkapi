# Native ETH protocol API

The browser SDK sends prompt-free proof authorizations to `zkapi-serverd`.
Inference runs directly against the issued provider key. This is the API of
circuit `zkapi-v2-concession-v2` (vault revision 4, leaf-bound exits); [openapi.yaml](openapi.yaml)
has the schemas.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and deployment summary, always HTTP 200: `status` `ok`, or `degraded` (still serving) while the indexer disagrees with the vault or cannot be read, or no vault root read is recent; the request-root state (`request_root_grace_seconds`, `vault_root_age_seconds`, `indexer_root`: `agrees`, `disagrees`, `unavailable`, `unchecked` or `not_configured`) and `circuit_id`, `setup_id`, `exit_concession`, `leaf_bound_exit`, `vault_revision` and `settlement_window_seconds` |
| GET | `/metrics` | Operator route (the reference gateway does not proxy it): Prometheus text of the request-root state: `zkapi_indexer_root_disagreement`, `zkapi_indexer_root_disagreements_total`, `zkapi_indexer_root_unavailable`, `zkapi_vault_root_stale`, `zkapi_vault_root_age_seconds`, `zkapi_vault_root_block`, `zkapi_request_root_window_roots` |
| GET | `/v1/attestation` | Public signing keys and protocol pins, with the same statement fields |
| GET | `/v2/auth` | Validate the configured Sepolia shared password without side effects |
| GET | `/v2/billing/quote` | Pinned finalized native ETH billing quote |
| POST | `/v2/openrouter/leases` | Verify proof and reserve a bounded runtime key |
| GET | `/v2/openrouter/leases/{client_request_id}` | Non-secret lease status and settlement deadline |
| POST | `/v2/openrouter/leases/{client_request_id}` | Retire and settle the exact lease |
| POST | `/v2/openrouter/leases/{client_request_id}/expire` | Authoritative recovery of an expired or superseded unaccepted request |
| POST | `/v2/withdraw/clearance` | Mutual-close Schnorr clearance for a nullifier whose note ownership a kind-2 proof shows |
| GET | `/v2/requests/{client_request_id}` | Recover signed settlement |
| GET | `/v2/nullifiers/{nullifier}` | Recover by nullifier; clients also check it before discarding a transmitted request |
| GET | `/v2/nullifiers/{nullifier}/evidence` | The request proof the server reserved at a nullifier, for a wallet's stale-device check |

When public `/health` reports `testnet_password_required: true`, all `/v2/*`
routes require `X-ZKAPI-Testnet-Password`. Missing or incorrect passwords return
HTTP 401 with `error_code: "testnet_password_required"` before request parsing.
See [Sepolia shared password](testnet-auth.md) for the complete access,
transport and credential-lifecycle contract. Mainnet is unaffected.

Recovery answers are authoritative only when the server could read its store.
`GET /v2/requests/{client_request_id}` and `GET /v2/nullifiers/{nullifier}`
mean "unknown" only with HTTP 200 `{"status":"not_found","nullifier_status":"unknown"}`,
and `POST .../expire` attests non-acceptance only with HTTP 200
`expired_unaccepted` or `superseded_unaccepted`. A store that cannot be read
(an I/O error, a corrupt page, a lock held past the busy timeout) returns HTTP
500 `error_code: "database_error"` with `retriable: true` on these routes, on
lease status and retirement, and on a lease retry: retry later, and never read
it as unknown, unaccepted or not found. Lease status returns 404 only for a
lease the store does not hold (an empty body), or, with
`error_code: "lease_record_unreadable"` and `retriable: false`, for a lease
row the store holds but cannot decode. That row never heals by itself, and
lease retirement and a lease retry that need it answer the same; `/expire`
answers `409 lease_pending` while the lease's reservation is held, and
recovery reports the nullifier `reserved` without a settlement deadline.
A pending lease in that state is not settled, not even at its settlement
deadline, and its nullifier reads `reserved`, until the operator restores its
saved request (`zkapi settlement reopen --saved-request`), or repairs by hand
another column that cannot be decoded (see
[Restoring an unreadable pending lease](native-eth-billing.md#restoring-an-unreadable-pending-lease)).
In either 404 case, read `GET /v2/nullifiers/{request_nullifier}`, which stays
authoritative.

Recovery reports `nullifier_status` `reserved`, `exit_deferred`,
`exited_unsigned`, `finalized`, `clearance_reserved` or `unknown`, and carries
`request_response` only once the successor is signed. A lease reads
`finalized` as soon as its charge is settled, so poll recovery until
`nullifier_status` is `finalized`. `exit_deferred` means an exit consumed the
nullifier on chain first: the successor is signed only if that exit is
defeated, and `exited_unsigned` means it never will be. Once the nullifier is
published on chain (consumed or challenged in the vault, or named by a vault
event as an exit's nullifier or successor nullifier), recovery returns the
status only, without `request_response` or `settlement_deadline`. The server
reads publication from the vault's `usedNullifiers` and `challengedNullifiers`,
then its indexer's `/v1/nullifiers/{N}/published`; when that table cannot be
read or answers 503 (an indexer bootstrapped from state lacks the earlier
events), or no indexer is configured, it scans the vault's
`EscapeConcessionRecorded` logs from an hour before the reservation, over at
most 50,000 blocks. When it still cannot tell, it answers retriable
`503 chain_read_unavailable`, which clients treat as an unreachable server.

`GET /v2/nullifiers/{nullifier}/evidence` answers `200 {public_inputs, proof}`
with the earliest request the server reserved at the nullifier,
`404 {"status":"not_found"}` when it holds none, `410 published` once the
nullifier is published (it never serves a public nullifier's evidence), and
`503 chain_read_unavailable` when it cannot tell; with an indexer configured
it does not fall back to the log scan. Before an escape, a wallet asks it for
its state's successor nullifier, and refuses to escape (`device_not_newest`)
when the answer is a proof that verifies locally; it ignores any other answer.

The reference gateway in `docker/aws` also applies coarse per-source limits to
`POST /v2/*` requests. A throttled request never reaches the server: it
returns HTTP 429 with `Retry-After: 5` and
`{"status":"error","client_request_id":"","error_code":"gateway_rate_limited",...,"retriable":true,"retry_after_seconds":5}`.
Retry the exact request after the delay; it is no reason to discard a journal
or prepared withdrawal. See
[request limits](../docker/aws/README.md#request-limits).

A lease uses `ApiRequestV2`: client request ID, canonical prompt-free payload,
payload hash, public inputs and `{backend: "groth16_bn254", proof: "base64..."}`.
The authorization payload includes mode/version and its frozen `billing_quote`.
The server recomputes payload/request binding, validates the native quote and
verifies the proof. Proof bytes contain eight canonical 32-byte coordinates
(256 bytes total). The request public inputs and their order are those of the
earlier circuit; the circuit ID and keys are `zkapi-v2-concession-v2`'s.

Admission (O5') accepts a request whose `active_root` is the vault's latest
`currentRoot()`, read by the server at the latest block hash, or a root the
server read from the vault that the vault replaced no more than
`--request-root-grace-seconds` ago (`ZKAPI_REQUEST_ROOT_GRACE_SECONDS`,
default 60, 0 to 600; 0 accepts only the latest root). Any other root answers
retriable `409 stale_root` with the latest root in `latest_root`. Only roots
read from the vault enter that window; when a recorded block hash is no longer
canonical, the server keeps only the latest root. Without a successful vault
read within `--root-max-staleness-seconds` (default 60) every request answers
retriable `503 root_unavailable`. The indexer is a health signal only: a
disagreement between its root and `currentRoot()` at its block hash is a
warning, the `zkapi_indexer_root_disagreement` metric and a `degraded`
`/health`, never a refusal. `stale_root` applies to requests only; clearance
has its own errors (below). With
`--request-limit-max-usd-micros`, a request whose lease budget exceeds that
ceiling is refused before anything is reserved (`400 request_limit_exceeded`).
Every reservation also stores an append-only copy of the request's public
inputs and proof (`request_evidence`), the challenger's evidence.

The runtime key is returned once. Retry/recovery must preserve the exact saved
request and journal, including quote and proof. A native gwei solvency bound is
converted to the provider's USD budget using the frozen quote. Settlement uses
actual provider usage converted back to gwei, then verifies/installs a signed
next balance. An unavailable receipt must not be treated as zero usage.

Settlement always fixes a charge, and the next balance is signed at the
anchor `Poseidon("zkapi.v2c.anchor", request_nullifier)` unless an exit
consumed the nullifier first (see above). Usage is clamped to
the proof-bound limit before conversion, and settlement never re-validates the
frozen quote against the server's current price settings. A lease whose key
never reached the client settles at zero. A delivered lease whose usage is
still unavailable at its write-once `settlement_deadline` settles at
`solvency_bound` and is recorded for operator review. Lease status and
recovery responses carry `settlement_deadline` until then; a finalized lease
reports `charge_basis` (`measured`, `clamped`, `worst_case`, `unissued` or
`operator_conceded`), which the signed payload repeats. A fallback payload adds
`settlement_reason` (`settlement_deadline`, `unsettleable` or
`operator_conceded`). Status `cancelled` marks a corrupt server record that is
never signed unless the operator repairs it and reopens the lease
(`zkapi settlement reopen`), which verifies its saved request first. Each
clamped, deadline, unsettleable, deletion-pending, corrupt-binding or reopened
settlement is recorded for operator review with the reason `usage_clamped`,
`deadline_worst_case`, `unsettleable_worst_case`,
`finalized_before_key_deletion`, `binding_corrupt` or `binding_reopened`. See
[settlement terminality](native-eth-billing.md#settlement-terminality) and
[operator review](native-eth-billing.md#operator-review).

OA-org issuance includes verifier-backed station/org evidence checked by the
browser's independently pinned verifier. Directly managed keys use durable
disable, grace, usage capture and confirmed deletion before settlement; a
lease still unsettled at its deadline is finalized first and its key is
deleted in the background. The provider's aggregate usage delay remains an
operator assumption for direct mode.

## Clearance

`POST /v2/withdraw/clearance` takes `ClearanceRequestV2C`,
`{withdrawal_nullifier, ownership_proof: {public_inputs, proof}}`, and refuses
unknown fields. The ownership proof is a kind-2 withdrawal proof for the same
nullifier: `public_inputs` is `WithdrawalPublicInputsV2C` (the 16 statement
inputs as 18 JSON fields: `note_leaf`, and `note_id`, `deposit_amount` and
`expiry_ts`, which the statement packs into `note_fields`; `destination` as 20
byte values; `active_root` is refused) with `kind: 2`, a zero destination,
`conceded: 0`, `next_nullifier: 0`, and a `valid_until` no earlier than now and
at most 3,600 seconds ahead; `proof` is
`{backend: "groth16_bn254", proof: "base64..."}`. The vault refuses kind 2
everywhere, so the proof cannot start an escape. A client never sends a request
proof from a state after sending its ownership proof, and sends at most one
live ownership proof per state.

The server requires the matching nullifier, kind and zero fields, its own
deployment and both signing keys, and a valid proof. It then reads the
vault's `noteRecord(note_id)` at `latest`, fresh for every clearance and never
cached: the stored leaf must equal the proof's `note_leaf` and the note must be
`Active`. No root is involved; `--clearance-root-window-seconds` and
`ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS` were removed in vault revision 4 and fail
startup ("removed in vault revision 4: clearance checks the note leaf; delete
this setting"). A request proof is never accepted. Errors:

| Status | `error_code` | Meaning |
| --- | --- | --- |
| 400 | `clearance_ownership_required` | No `ownership_proof`; nothing was reserved; not retriable |
| 400 | `invalid_proof` | The proof does not verify |
| 400 | `invalid_request` | A body that does not parse, or a nullifier, kind, zero field, validity window or signing-key mismatch |
| 400 | `protocol_mismatch` | Another protocol version, chain or vault |
| 409 | `note_leaf_mismatch` | The vault's stored leaf for `note_id` is not the proof's `note_leaf` (a wrong leaf, or an unknown or retired note); not retriable |
| 409 | `note_not_active` | The note has a pending escape or is closed (its leaf still stored); not retriable |
| 409 | `nullifier_used` | The nullifier already authorized a request |
| 500 | `internal_error` | Retriable; for example a failed `noteRecord` read |
| 503 | `capacity_exhausted` | Ownership-proof verification capacity is busy; retry the same body |

A clearance reservation is permanent and its signature has no expiry; asking
again with a valid proof signs again. The server never logs or stores
ownership proofs. This circuit has no proof-less clearance:
`--allow-legacy-clearance` refuses startup, and public `/health` reports
`clearance_ownership_proof_required: true`.

## Indexer

The indexer provides `/v1/tree/root`, `/v1/tree/snapshot`,
`/v1/tree/notes/{note_id}/path` and `/v1/tree/next-note-id`, for request-proof
paths; deposits and exits need none. The `/v1/tree/notes/{note_id}/zero-path`
and `/v1/tree/roots/{root}` routes of vault revision 3 are removed (`404`).
Each response comes from one head view verified against
the vault's `currentRoot()` and `nextNoteId()` and carries that view's `root`,
`block_number` and `block_hash`; `/v1/tree/root` answers
`{root, next_note_id, block_number, block_hash}`.
Without a verified view, these routes return `503` with `Retry-After: 5` and
the constant body
`{"status":"unavailable","error_code":"indexer_unavailable",...,"retriable":true,"retry_after_seconds":5}`.
A path parameter that is not a canonical field element answers
`400 invalid_request`.

`/health` (`200` only when `ok`; it reports `state_note_count`, the notes of
the served view read from state at a bootstrap, in place of the former
`known_root_count`), `/metrics`, `/v1/notes/{note_id}/deposit`,
`/v1/nullifiers/{nullifier}/published` and `/v1/escapes/pending` are internal;
`/v1/notes/{note_id}/deposit` is outside `/v1/tree/`, so the reference gateway
does not expose it.
`/v1/notes/{note_id}/deposit` answers
`{note_id, leaf, status, deposit, block_number, block_hash}`, where `deposit`
is the note's `NoteDeposited` preimage `{commitment, amount, expiry_ts}` (the
arguments of `claimExpired` and `effectiveExpiry`; `null` for a note from
before a state bootstrap) and `status` a hint (`noteRecord` is
authoritative); `404 unknown_note` for a note the view has not seen.
`/v1/nullifiers/{nullifier}/published` answers
`{nullifier, published, block_number, block_hash}`: whether a vault event
named the nullifier as an exit's nullifier or successor nullifier. A view
bootstrapped from state answers only for a nullifier its table holds and
`503` for any other, never a false "not published". serverd reads it before
serving recovery or evidence. `/v1/escapes/pending` lists
`{note_id, withdrawal_nullifier, challenge_deadline, final_balance, next_nullifier, state_balance, conceded}`
for each open escape in the same view. Escapes change no leaf, so the root
check does not cover the list: each entry is the last one applied from the
vault's logs, a hint. Consumers must read `pendingWithdrawals(noteId)` and
`pendingConcessions(noteId)` from the vault.

The indexer's checkpoint is version 4, bound to one chain, vault and circuit,
with each note's leaf and deposit preimage; a version-3 checkpoint (a
revision-3 vault) is refused at startup with an instruction to restart with
`--resync`, and versions 1 and 2 are archived and replayed from the
deployment block, as is any checkpoint after `--resync` or a
`<cursor>.resync` file. `--bootstrap-from-state` (off by default; recommended
for a new deployment) builds the mirror from the vault's state instead
(`noteLeaves` pages of 2,048, `nextNoteId()` and `currentRoot()` at one block
hash), and only when there is no checkpoint (a first start or `--resync`) and
on automatic rebuilds. On a vault that already has notes it loses their
deposit preimages, the escapes and the published nullifiers from before that
block (`deposit: null`, a nonzero `state_note_count`). The
indexer refuses a vault whose `LEAF_BOUND_EXIT_VERSION()` is not 1. On-chain mutual
close, escape and expiry recovery use the native vault ABI through the browser
SDK.
