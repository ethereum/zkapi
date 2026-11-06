# Fixed-price tickets

Tickets are an explicit, optional billing mode next to metered leases. A
metered lease charges the measured usage of its key after the key is retired,
so a wallet holds one lease (and one key) at a time. A ticket charges a fixed
price when it is bought: the purchase returns the runtime key together with
the signed successor state, the wallet installs that successor at once, and
the next ticket can be bought, and its request sent, while earlier keys are
still serving requests.

Tickets mirror the OA org's own ticketing: a tier (Instant, Thinking,
Premium & Image, ...) costs a number of OA inference tickets and buys a key
with that tier's spending allowance and lifetime. A model's tier is the OA
ticket count `/chat/model-tickets` assigns to it.

## What a ticket buys and costs

The protocol server sells the tiers of its ticket catalog
(`--ticket-catalog FILE`, environment `ZKAPI_TICKET_CATALOG`), served at
`GET /v2/tickets`:

```json
{
  "version": 1,
  "key_source": "oa_org",
  "tiers": [
    {"tier_id": 1, "tier_name": "Instant", "oa_tickets": 1,
     "price_micro_usd": 140000, "credit_limit_micro_usd": 250000,
     "duration_seconds": 600}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `tier_id`, `tier_name` | The OA tier mirrored |
| `oa_tickets` | The OA ticket count of the tier; unique in a catalog |
| `price_micro_usd` | The fixed price of one ticket |
| `credit_limit_micro_usd` | The key's spending allowance at the provider |
| `duration_seconds` | The key's lifetime, a whole number of minutes |

The price is fixed in USD and paid in gwei at the purchase's frozen ETH/USD
quote: `price_units = ceil(price_micro_usd * 10^9 * 10^8 / (answer * 10^6))`,
the conversion of every native charge. The purchase authorization (the
proof's payload, mode `zkapi_fixed_price_ticket`, version 1) states the tier's
complete terms, `price_units` and the quote. Its hash is bound into the
request proof, so the server cannot charge another price or sell other terms
for it, and the wallet refuses a successor that does
(`invalid_successor`). The proof's solvency bound is
`max(price_units, request_charge_cap)`, and the signed successor charges
exactly `price_units`, whatever the key is later used for.

[`docker/aws/ticket-catalog.example.json`](../docker/aws/ticket-catalog.example.json)
mirrors the staging OA tiers at the OA ticket-pack price ($7 for 50 tickets,
$0.14 per ticket). The allowance and lifetime are the operator's choice; the
OA relay caps both (`ZKAPI_MAX_CREDIT_USD`, `ZKAPI_MAX_DURATION_MINUTES`),
and a tier above those caps is refused at purchase and settles at zero.

## Server behavior

Tickets need the OA org key source (`--oa-org-url`): the org replays one key
per upstream request ID, which lets an exact retry receive the same paid key
again without the server storing it. Startup refuses a catalog without it, a
credit limit above `--request-limit-max-usd-micros`, or a tier duration that
does not fit the settlement timing check against the vault's challenge
period.

`POST /v2/openrouter/leases` with a ticket authorization:

1. Admission checks the request as for any lease (root, freshness, proof,
   quote), then that the terms are on sale now exactly, that `price_units` is
   the conversion at the bound quote and that the solvency bound covers it.
   Otherwise `400 ticket_terms_mismatch` or `invalid_request`, and nothing
   is reserved.
2. The nullifier is reserved with a provisioning row frozen to the tier's
   duration and allowance; the OA key is requested (`may_have_issued` first).
3. Only while the vault reports the nullifier unused, one transaction commits
   the charge `price_units` (basis `ticket`) and marks the key delivered.
   Before it, the key is undelivered and the lease would settle at zero;
   after it, nothing changes the charge.
4. The successor is signed and returned with the key: `request_response`
   (settlement payload type `zkapi_ticket_settlement`, repeating the terms,
   `price_units` and quote) and `ticket` beside the usual lease fields.

Nothing waits for inference, key expiry, disable or usage receipts. The
settlement sweep never measures a ticket.

| Situation | Result |
| --- | --- |
| Exact retry of a paid ticket (lost reply, restart) | The stored successor and the same key, replayed by the org (the key hash must match); no second charge. After the key expired: `409 ticket_key_expired`; recover the successor |
| Ambiguous org failure before the charge | Retriable error; the exact retry asks the org again for the same key |
| Crash or vault-read failure after activation, before the charge | The key is undelivered; the exact retry delivers it and charges once; otherwise it settles at zero by its deadline |
| Org policy rejection | `400 oa_key_policy_rejected`; zero-charge successor by recovery |
| Undelivered ticket settled at zero, then retried | `409 ticket_unissued`; recover the zero-charge successor; no key |
| Signing fails after the charge | Retriable error; the retry signs and returns the same charge |
| An exit consumed the nullifier | `409 nullifier_used`, no key; the challenger raises the exit to the price |
| A spent state (same nullifier) or a changed body | `409 replay` |

Recovery (`GET /v2/requests/{id}`, `GET /v2/nullifiers/{n}`), lease status and
the challenger treat a ticket as an ordinary settled lease: its charge is final
as soon as it is bought.

## Wallet (zkapi-walletd) and clientd

`zkapi-walletd` sells tickets to its local client through:

- `GET /oa/v1/tickets`: the server's catalog and the local inventory (no keys);
- `POST /oa/v1/ticket {"terms": {...}, "purchase_id": "..."}`: hand out one
  ticket of exactly these terms, buying one only when the inventory holds no
  ready one;
- `POST /oa/v1/ticket/release {"client_request_id", "purchase_id", "consume"}`;
- `POST /oa/v1/tickets/release-all`: return an earlier client run's claims.

Each purchase holds the wallet only while it proves, posts and installs (a
few seconds); inference never holds it. A checked purchase reply is written
to the private inventory (`ticket-inventory.json`, mode 0600) as
*provisional* before its successor is installed, and becomes *ready* only once
the wallet has verified (S1–S6 and the fixed price and terms) and installed
it. A crash before the install replays the saved request first; after it,
the request archive shows the install. A successor the wallet refuses leaves
the ticket *refused*: its key is erased, never handed out, and no other
ticket is bought until the wallet is recovered. Purchase IDs are idempotent:
a retry after a lost local reply returns the same ticket and never buys
again. A key that fails OA verification is *rejected* and erased. A consumed
or expired claim is kept, without its key, for a day.

`zkapi-clientd config --billing-mode ticket` switches the local API to
tickets (`--billing-mode metered` switches back; the default is metered). Each
completion buys one ticket of the tier its model's OA ticket count selects
and runs its inference outside the request slot, so up to `concurrency`
requests run at once. A ticket serves one request: once the request was sent
(whatever its outcome) the ticket is consumed. A ticket whose key was never
used goes back to the inventory. A model without a matching tier answers
`model_ticket_tier_unavailable`; a repriced tier is selected again once
(`ticket_terms_changed`).

## Privacy

The purchase is the same prompt-free, proof-authorized request as a lease:
the server learns the tier and that some valid note paid, not which. The key
is used directly with the provider. Keys are kept only in the wallet's private
inventory, never in the server's database, recovery responses or logs.

## Limitations

- The browser SDK does not sell tickets; it keeps metered leases.
- A ticket's unused allowance is not refunded; its price is fixed.
- Tickets need the OA org key source and its replay-safe issuance.
- The OA relay's per-key caps and hourly issuance budget bound the tiers.

## API schema

The machine-readable contract is in [openapi.yaml](openapi.yaml)
(`GET /v2/tickets`, `TicketAuthorization`, `TicketTerms`).
