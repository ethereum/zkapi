# Native ETH protocol API

The browser SDK sends prompt-free proof authorizations to `zkapi-serverd`.
Inference runs directly against the issued provider key.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and deployment summary |
| GET | `/v1/attestation` | Public signing keys and protocol pins |
| GET | `/v2/auth` | Validate the configured Sepolia shared password without side effects |
| GET | `/v2/billing/quote` | Pinned finalized native ETH billing quote |
| GET | `/v2/time` | Non-cacheable server clock for new `request_time` values (additive) |
| POST | `/v2/openrouter/leases` | Verify proof and reserve a bounded runtime key |
| GET | `/v2/openrouter/leases/{client_request_id}` | Non-secret lease status |
| POST | `/v2/openrouter/leases/{client_request_id}` | Retire and settle the exact lease |
| POST | `/v2/openrouter/leases/{client_request_id}/expire` | Authoritative recovery of an expired or superseded unaccepted request |
| POST | `/v2/withdraw/clearance` | Mutual-close Schnorr clearance |
| GET | `/v2/requests/{client_request_id}` | Recover signed settlement |
| GET | `/v2/nullifiers/{nullifier}` | Recover by nullifier |

When public `/health` reports `testnet_password_required: true`, all `/v2/*`
routes require `X-ZKAPI-Testnet-Password`. Missing or incorrect passwords return
HTTP 401 with `error_code: "testnet_password_required"` before request parsing.
See [Sepolia shared password](testnet-auth.md) for the complete access,
transport and credential-lifecycle contract. Mainnet is unaffected.

A lease uses `ApiRequestV2`: client request ID, canonical prompt-free payload,
payload hash, public inputs and `{backend: "groth16_bn254", proof: "base64..."}`.
The authorization payload includes mode/version and its frozen `billing_quote`.
The server recomputes payload/request binding, validates the native quote and
verifies the proof. Proof bytes contain eight canonical 32-byte coordinates
(256 bytes total). Public inputs, proof coordinates and circuit ID are unchanged.

## Server time (`GET /v2/time`)

An additive, read-only, state-free endpoint. It reads no request, wallet or
nullifier state, creates none and returns no identifiers:

```json
{"server_time_ms":1793966400000,"protocol_version":2,"chain_id":1,
 "max_request_age_seconds":300,"max_future_skew_seconds":30}
```

Responses carry `Cache-Control: no-store`; GET/HEAD only (other methods 405).
Ungated deployments add the same simple `Access-Control-Allow-Origin: *`
GET/HEAD policy as `/health`; a Sepolia password gate keeps it behind the
password and its single outer CORS policy. Admission is unchanged: the server
still accepts `request_time` in `[server_now - 300 s, server_now + 30 s]` on its
own clock. Existing request and proof formats, routes, bodies and admission
bounds are unchanged; old clients are unaffected. One additive recovery
semantic: `/expire` also acknowledges an exact, unreserved request as
`expired_unaccepted` once its `request_time` is past the age window (see
[native ETH billing](native-eth-billing.md)). A future `request_time` alone
never does.

New SDKs anchor a sample to the monotonic clock as a lower bound (the response
time is assumed to be its arrival time), reject samples slower than 5 s or that
straddle a wall/monotonic discontinuity, resample after 30 s for new request
timestamps and after a detected wall/monotonic discontinuity (an OS suspend or a clock change larger than the 2-second tolerance), and keep samples in
memory per deployment only. Only HTTP 404/405 (an older server) selects the
legacy device clock; 401/403, 5xx, malformed JSON, a different `chain_id` and
transport failures never downgrade. Browser-clock protection therefore requires
this endpoint. Roll out the server first, then clients.

Exact `/expire` handshakes and signed-receipt installation never need this
endpoint: they validate saved quotes structurally and rely on the server
acknowledgement or signed receipt. Re-admitting an issued key after an
interrupted operation still requires a bounded clock check before use.

The runtime key is returned once. Retry/recovery must preserve the exact saved
request and journal, including quote and proof. A native gwei solvency bound is
converted to the provider's USD budget using the frozen quote. Settlement uses
actual provider usage converted back to gwei, then verifies/installs a signed
next balance. An unavailable receipt must not be treated as zero usage.

OA-org issuance includes verifier-backed station/org evidence checked by the
browser's independently pinned verifier. Directly managed keys use durable
disable, grace, usage capture and confirmed deletion before settlement. The
provider's aggregate usage delay remains an operator assumption for direct mode.

The indexer provides `/v1/tree/root`, `/v1/tree/snapshot`,
`/v1/tree/notes/{note_id}/path`, `/v1/tree/notes/{note_id}/zero-path`, and
`/v1/tree/next-note-id`; see its route source for the
full endpoint set. On-chain mutual close, escape and expiry recovery use the
native vault ABI through the browser SDK.
