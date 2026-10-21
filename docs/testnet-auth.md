# Sepolia shared password

The protocol server can require one shared password on Sepolia (chain ID
`11155111`). This is an additional service access gate, independent of note
proofs and provider credentials. Configure only the Sepolia server process with
`ZKAPI_TESTNET_PASSWORD`; an unset variable leaves the service ungated. Empty,
invalid, or non-Sepolia configurations fail startup before opening the database.
The password must contain 16–1024 visible ASCII characters without whitespace;
generate a random password and distribute it privately. Do not reuse an OA-org,
OpenRouter, signing, or personal account credential.

The public `GET /health` response reports `chain_id` and
`testnet_password_required`. Clients validate a supplied password with
`GET /v2/auth` and header `X-ZKAPI-Testnet-Password`; success returns
`{"authenticated":true}`. Send this header to the configured Sepolia protocol
server for every `/v2/*` call, including quotes, lease status/retirement,
settlement recovery, expiry recovery and withdrawal clearance. Never send it
to an RPC, indexer, verifier, OA org, provider, or another network. Clients
must not follow cross-origin redirects with this header.

Missing or incorrect credentials return HTTP `401` and:

```json
{"error_code":"testnet_password_required","error":"Sepolia password required or invalid","retriable":false}
```

Authentication runs before body parsing, proof verification, database reads or
provider activity. Duplicate password headers are rejected. The server compares
fixed-length SHA3-256 digests in constant time, keeps raw passwords out of its
configuration/debug representation, and removes the request header before
handlers run. Password failures contain no request identifiers or submitted
values. Clients should keep prepared proofs/journals when authentication fails;
unlocking with a replacement password does not require a new proof.

`GET`/`HEAD` health and attestation, CORS preflight, public manifests/proving
artifacts and the separate public indexer remain accessible. All other server
routes, including operator dashboards and unknown future routes, are gated.
Gate-enabled API responses and authentication failures use `Cache-Control:
no-store`. Browser preflight permits the password header and JSON content type
without cookies. Mainnet's protocol access policy is unchanged; supplying this
server environment variable on Mainnet is a startup error.

Put the password only in the root-owned mode-0600 Sepolia `server.env`, never
in public `config.json`, deployment metadata, a Docker image or CLI arguments.
Keep TLS at the public edge and disable API caching. An upstream proxy must
forward `X-ZKAPI-Testnet-Password`, `Origin`, `Access-Control-Request-Method`,
and `Access-Control-Request-Headers`, allow OPTIONS/GET/POST, and preserve CORS
and no-store response headers. Do not add password headers to access logs or
enable request-header debug dumps. The bundled gateway already forwards `/v2/`
and the request headers to the server. Its per-source `POST` limits run before
the password check, so a throttled request receives
`429 gateway_rate_limited`, not `401`. Only the server container receives
`server.env`.

Rotate the password by replacing this one environment value and recreating the
server with its existing data, seeds, vault, oracle and proof pins. No database
migration or contract change is needed. Every new API call then requires the
replacement password; already-issued provider keys retain their existing
bounded expiry. The same password is shared by everyone, so it adds no unique
user identity or account cookie, but it proves membership in this test group.
It does not conceal public blockchain activity or change the private-note
protocol's existing metadata tradeoffs. Public funding and the vault's
on-chain escape path cannot be password-gated by this server.

Before enabling the gate, distribute compatible clients and the password.
After rollout, verify public health/attestation/indexer access, unauthenticated
and wrong-password 401 responses, browser preflight, and authenticated
`/v2/auth` and billing quote requests at both the origin and public HTTPS edge.
Read-only authentication checks do not establish paid inference or settlement.
