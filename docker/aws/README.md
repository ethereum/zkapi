# Native ETH operator deployment

This image runs the native ETH API, indexer and escape challenger of circuit
`zkapi-v2-concession-v1` (vault revision 3) with the exact
`protocol/setup/v2-concession` artifacts, the multi-party ceremony setup
`mpc-1`. A release build loads only the pinned ceremony keys, so the daemons
refuse to start until G-SETUP has committed them, unless the image is built for
a [single-party setup](#single-party-setup); a vault of circuit
`zkapi-v2-note-bound-v1` keeps its own stack from the
`release/v2-note-bound` branch. Supply the matching vault/signing keys, the
deployment manifest and pinned native oracle configuration. A revision-3
vault is a new deployment beside the legacy one; the order of the move, the
daemon order and the legacy drain are in
[the concession-vault migration runbook](../../docs/migration-concession-vault.md).

Build on a Linux VM with Docker Engine and Compose, from the complete source
tree, including the in-repository `protocol/` source:

```sh
sudo install -d -m 0700 /etc/zkapi
sudo install -d -m 0700 -o 10001 -g 10001 /var/lib/zkapi
sudo docker compose -f docker/aws/compose.yml --profile challenge build server gateway signer
```

Create these root-owned, mode `0600` files without printing their contents:

| File | Contents |
| --- | --- |
| `/etc/zkapi/deployment.env` | Copy `deployment.env.example`, then supply vault address, chain, deployment block, gwei request cap, `ZKAPI_NATIVE_BILLING_RPC_URL`, `ZKAPI_NATIVE_PRICE_FEED_ADDRESS`, feed decimals and freshness policy. It also sets the lease settlement deadline, the indexer's confirmation depth and head-age limit, and the challenger's transaction fee cap (`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, below). |
| `/etc/zkapi/deployment.json` | Mode `0644`. The deployment manifest: the `trusted_deployment` profile (chain, vault, signing keys, `challenge_period`, `circuit_id`, `setup_id`, both verifying-key hashes, the adapter and Poseidon library addresses, the three runtime codehashes, `settlement_window_seconds`), written from the manifest that `scripts/expected-codehashes.mjs --finalize` produced from `Deploy.s.sol`'s provisional one, never from the `.pending` file (see [Contracts](../../docs/deployment.md#contracts)). Compose mounts it read-only into `db-init`, `server` and `challenger`. A `"deployment_status"` other than absent or `"deployed"` (a `not_deployed` placeholder, or a provisional `pending` or `simulated` manifest) is refused. |
| `/etc/zkapi/indexer.env` | `RPC_URL`, the chain's read RPC endpoint (requirements below). |
| `/etc/zkapi/server.env` | `ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` (required, below), and `ZKAPI_OPENROUTER_MANAGEMENT_KEY` for direct leases; alternatively set `OA_ORG_URL` in deployment metadata and `ZKAPI_OA_ORG_SHARED_SECRET` here. To switch an existing database between these key sources, follow [Changing the key source](../../docs/native-eth-billing.md#changing-the-key-source): the server refuses to start while leases or key deletions of the other source still need its credential (`ZKAPI_ALLOW_KEY_SOURCE_SWITCH=true` starts anyway and strands them). For private Sepolia access, also set `ZKAPI_TESTNET_PASSWORD` here only. |
| `/etc/zkapi/challenge.env` | `ZKAPI_CHALLENGE_RPC_URL=http://signer:8547`, `ZKAPI_CHALLENGE_SENDER` (the exclusive funded sender managed by the private sidecar), and the daemon's fee caps (below). |
| `/etc/zkapi/signer.env` | Copy [`signer.env.example`](signer.env.example): `ZKAPI_CHALLENGE_PRIVATE_KEY`, `ZKAPI_CHALLENGE_CHAIN_ID`, `ZKAPI_CHALLENGE_RPC_URL` (the upstream RPC for the chain), `ZKAPI_CHALLENGE_VAULT` (the configured vault), the fee cap and the transaction fee cap (below). Only the signer container receives this file. |

Also create `/etc/zkapi/config.json` with mode `0644`: this is the public client
manifest containing the contract, signing-key, circuit and proving-key
hash pins. The gateway mounts it read-only and serves exactly `/config.json`,
`/proofs/request.pk`, `/proofs/withdrawal.pk`, and `/proofs/manifest.json` as static
artifacts. Proving keys are copied into the gateway image from the same checkout
as the daemon image. Other files and directories are not served.

Compose reads these as environment files; quote values containing `$`, `#` or
other Compose env-file syntax appropriately. Keep credentials out of compose
command arguments and images. `docker compose config` expands secrets, so use
`config --quiet` for validation.

A container reads its environment files only when Compose creates it. After
editing one, recreate each service that reads it, for example
`sudo docker compose -f docker/aws/compose.yml --profile challenge up -d --no-deps --wait signer`;
`docker compose restart` keeps the old values. Leave an optional variable out
rather than setting it empty: `signer.env` treats an empty value as the
default, and so does the launcher for the settings it passes on, but the
daemons refuse an empty value for others at startup, for example
`ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS` and `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI`.
`ZKAPI_ALLOW_LEGACY_CLEARANCE=true` is refused: this circuit signs a clearance
only against a kind-2 ownership proof.

### Single-party setup

A vault deployed with `Deploy.s.sol`'s `ALLOW_DEV_SETUP=1` on the development
setup `dev` (see [Single-party setup](../../docs/deployment.md#single-party-setup):
whoever generated those keys can forge every proof) needs images built for it:

```sh
sudo ALLOW_DEV_SETUP=1 docker compose -f docker/aws/compose.yml --profile challenge build server gateway signer
```

Compose passes the value to both Dockerfiles. The daemons are then built with
`zkapi-proof`'s `dev-setup` feature and load
`/srv/zkapi/protocol/setup/v2-concession-dev` (the image's
`ZKAPI_PROOF_SETUP_DIR`), and the gateway serves that setup's proving keys.
Health and attestation then report `setup_id` `dev`, and `deployment.json`
must pin it. Build without the variable for a ceremony vault: a default image
refuses development keys.

### Signing seeds

`ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` are required. There is no default, and
an empty value counts as missing. Generate both directly into `server.env`:

```sh
sudo sh -c 'umask 077; printf "ZKAPI_STATE_SEED=0x%s\nZKAPI_CLEAR_SEED=0x%s\n" "$(openssl rand -hex 31)" "$(openssl rand -hex 31)" >> /etc/zkapi/server.env'
```

`zkapi serverd` and `zkapi signing-keys` refuse a seed that is zero or a multiple
of the Baby-JubJub subgroup order, any seed whose key is one of the published
development keys (seeds `0x1` and `0x2`, in any spelling and either role), a
secret within 2^128 of zero or of the subgroup order (which includes every seed
of 16 bytes or fewer), and one key used for both roles. Errors name the role,
never the seed. Print the public keys for the vault constructor
(`STATE_SIGNING_KEY_X/Y` and `CLEARANCE_SIGNING_KEY_X/Y` of `Deploy.s.sol`) with:

```sh
sudo docker compose -f docker/aws/compose.yml run --rm --no-deps --entrypoint zkapi server signing-keys
```

Before it opens `/data/server.db` for writes, the server checks that
`ZKAPI_NATIVE_BILLING_RPC_URL` serves `CHAIN_ID` (`eth_chainId`), then reads the
vault's `stateSigningKeyX/Y()`, `clearanceSigningKeyX/Y()` and
`challengePeriod()` at `latest`. It refuses to start unless both derived public
keys equal the vault's; the error says which role differs and whether the seeds
look swapped. The vault keys are immutable, so the fix is the seeds whose keys
were passed to the vault constructor. An unreachable RPC is tried five times,
1, 2, 4 and 8 seconds apart (each call waits up to 15 seconds); the server then
exits and Compose restarts it. The healthcheck allows 120 seconds for this.

`zkapi db init` (the `db-init` service) creates the database before any daemon
starts: its schema, the append-only `request_evidence` table and its triggers,
and a `deployment_binding` row from `deployment.json` (chain, vault, both public
keys, `challenge_period`, circuit, setup and both verifying-key hashes, which
must equal the keys in the proof setup directory), marked unverified. On its
first start the server checks that binding against the vault as above and runs
the startup probes: the vault's `CONCESSION_ESCAPE_VERSION()` is 1 and its
`ROOT_HISTORY_WINDOW()` 86400, its `proofAdapter()` is the manifest's adapter,
the adapter's `CIRCUIT_ID_HASH()`, `REQUEST_VK_HASH()` and `WITHDRAWAL_VK_HASH()`
equal this build's circuit and loaded keys, and the runtime codehashes of the
vault, the adapter and the Poseidon library equal the manifest's. Each fails
closed. It also refuses a lease TTL + grace + settlement deadline longer than
the manifest's `settlement_window_seconds`.

After a successful check the server records a verified `deployment_binding` row
(chain, vault, both public keys, `challengePeriod()`, circuit, setup and
verifying-key hashes) in its database. A restart on
that database with the same chain, vault and seeds starts without the RPC and
re-verifies in the background (from 1 second, doubling to 60). Only a definitive
contradiction, vault keys or `challengePeriod()` that differ from the record,
or a startup probe that finds another value, stops the server; an unavailable
or wrong-chain RPC is logged and retried. A database bound to another chain,
vault, circuit, setup or verifying key is refused before any RPC call, so use
one data directory per deployment. After a crash that leaves an unfinished
SQLite transaction, the server cannot read the binding read-only and runs the
RPC check again. The challenger refuses to start until this row exists.

Allow these calls on `ZKAPI_NATIVE_BILLING_RPC_URL`; it must also support the
`finalized` block tag:

| Call | Target | Block | Purpose |
| --- | --- | --- | --- |
| `eth_chainId` | | | Chain check before every vault read |
| `eth_call` `0x15fa2a9a`, `0x230e2a24` | vault | `latest` | `stateSigningKeyX()`, `stateSigningKeyY()` |
| `eth_call` `0xdc41d636`, `0x112cd6bc` | vault | `latest` | `clearanceSigningKeyX()`, `clearanceSigningKeyY()` |
| `eth_call` `0xf3f480d9` | vault | `latest` | `challengePeriod()` |
| `eth_call` `0xfdab463d` | vault | `latest` | `currentRoot()`: polled with the indexer root (admission accepts only a root both report, refreshed within `ZKAPI_ROOT_MAX_STALENESS_SECONDS`, default 60), for clearance ownership proofs, and the starting root |
| `eth_call` `0x5e00b426`, `0x1fe72de0`, `0xefc91e58` | vault | `latest` | Startup probes: `CONCESSION_ESCAPE_VERSION()`, `ROOT_HISTORY_WINDOW()`, `proofAdapter()` |
| `eth_call` `0xda0e8385`, `0xfe351488`, `0x7fcd0926` | adapter | `latest` | Startup probes: `CIRCUIT_ID_HASH()`, `REQUEST_VK_HASH()`, `WITHDRAWAL_VK_HASH()` |
| `eth_getCode` | vault, adapter, Poseidon library | `latest` | Startup probes: runtime codehashes |
| `eth_call` `0x6cda756a` | vault | `latest` | `challengedNullifiers(uint256)`, before serving request evidence or a recovered response |
| `eth_call` `0x4d1352fd` | vault | `latest` | `nativeAssetWeiPerUnit()` |
| `eth_call` `0xaad24061` | vault | `latest` | `usedNullifiers(uint256)` before key issuance, before signing a settled request's successor (an exit consuming it defers the signature), and before serving request evidence or a recovered response |
| `eth_call` `0x313ce567` | feed | `latest` | `decimals()` |
| `eth_call` `0xfeaf968c`, `0x9a6fc8f5` | feed | `finalized` | `latestRoundData()`, `getRoundData(uint80)` |

### Lease settlement deadline

Every lease row gets a write-once settlement deadline at creation: issuance +
`LEASE_TTL_SECONDS` + `SETTLEMENT_GRACE_SECONDS` +
`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS` (default 21600). A lease that may
have been delivered and is still unsettled then is finalized at its measured
usage or, failing that, at its proof's solvency bound, with an operator review
record. The server refuses to start unless TTL + grace + deadline + twice the
2-second settlement poll + 600 seconds is at most half the vault's
`challengePeriod()`, and unless the deadline is at least the grace + 900
seconds. See [native ETH billing](../../docs/native-eth-billing.md).

### Indexer RPC

`RPC_URL` in `indexer.env` must serve `eth_chainId`, `eth_getBlockByNumber`,
`eth_getBlockByHash`, `eth_getLogs` (logs carry `blockHash` and `logIndex`) and
`eth_call` by block hash with `requireCanonical` (EIP-1898), with state for at
least the last `INDEXER_CONFIRMATIONS` blocks; archive state is not required.
An RPC without EIP-1898 support keeps the indexer in `syncing` and logs
`RPC rejected block-hash eth_call (EIP-1898); indexer cannot verify vault state`.
Use one consistent endpoint rather than a load balancer whose replicas disagree
about the head, and a provider independent of the `rpc_url` packaged in client
manifests: `zkapi-clientd` corroborates deposits and withdrawals against this
indexer's tree, and that check is only as independent as the indexer's RPC. Keep
the host clock synchronized with NTP; the indexer answers 503 when the RPC head
block is older than `INDEXER_MAX_HEAD_AGE_SECS` (180).

The indexer commits its checkpoint `INDEXER_CONFIRMATIONS` blocks (12) below the
head and serves a head view verified against the vault's `currentRoot()` and
`nextNoteId()` at the head block. Its tree routes answer 503 with
`{"status":"unavailable","error_code":"indexer_unavailable",...}` and
`Retry-After: 5` until a view verifies, and again whenever it is stale, diverged
or rebuilding. The server and the challenger start without waiting for it.
When the indexer has no verified root at the server's start, the server starts
from the vault's `currentRoot()`, read over the native billing RPC, until the
indexer serves one.

### Challenge signer and daemon

The signer reads only `signer.env`; [its README](signer/README.md) documents
every variable, the fee model and its runbooks. In short:
`ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` is the highest `maxFeePerGas` it signs.
With `ZKAPI_CHALLENGE_CHAIN_ID=1` it refuses to start without one; Sepolia
defaults to 10 gwei. The tip cap `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`
defaults to the lower of the fee cap and 10 times the default tip (10 gwei with
the 1 gwei default tip). `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` is no longer
supported, and the signer refuses to start while it is present, even empty.
`ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY` (default 2) caps the nonces on which
it signs a leaf retirement per rolling 24 hours, and a note's retirement on a
new nonce waits until its earlier nonce is mined (`retirement_in_flight`). A
compromised challenger host can therefore spend at most that many retirements
(each up to `ZKAPI_CHALLENGE_MAX_GAS` x fee cap) of the float per day, whether
they retire a leaf or revert. Fee replacements on a counted nonce are free; a
further retirement is refused with `retirement_budget_exhausted` (the
challenger reports `signer_refused`), and defeats and raises are never
affected. One missed defeat takes one unit, plus one for each re-send after a
root race. The signer also follows the operator's retire-on-miss policy
(design §5.4): `ZKAPI_CHALLENGE_RETIRE_ON_MISS=false` in `signer.env` refuses
every retirement (`retirement_disabled`), and a retirement is signed only for a
note whose escape finalized within `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS`
(default 50,400; `retirement_not_after_escape` otherwise), never for one closed
by a mutual close or an expiry claim.

The node behind the signer refuses to relay a transaction whose gas limit x
`maxFeePerGas` exceeds its RPC fee cap, `--rpc.txfeecap`, which is 1 ETH by
default in geth and reth. `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (decimal wei, default
`1000000000000000000`, 1 ETH) caps gas limit x `maxFeePerGas` of every bid. Set
it to the upstream node's `--rpc.txfeecap`, with the same value in `signer.env`
for the signer and in `deployment.env` for the daemon (the signer reads only
`signer.env`). The signer refuses a costlier bid before any upstream call
(`tx_fee_above_cap`). The daemon bids within the lower of its own value and the
signer's, which `zkapi_signerStatus` reports, and its `/status` warns when the
two differ. The challenger sends three calls; their gas limits (from the
design estimates; re-measure on the deployed vault) and the highest bid each
allows at the default 1 ETH are:

| Call | Gas limit | Highest bid at 1 ETH |
| --- | --- | --- |
| Defeat (`challengeEscapeWithdrawal`) | 600,000, or the estimate plus 20% when higher | about 1,666 gwei |
| Raise (`raiseEscapeConcession`) | 450,000, or the estimate plus 20% when higher | about 2,222 gwei |
| Leaf retirement (`retireClosedLeaf`, after a missed defeat) | the estimate plus 20%, about 7.2M | about 138.9 gwei |

Defeats and raises are deadline-bound and fit any realistic fee cap at 1 ETH.
A leaf retirement has no deadline; to let it bid a fee cap above about 138.9
gwei, raise the node's `--rpc.txfeecap` and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
together in `signer.env` and `deployment.env` (2.4 ETH for a 300 gwei fee cap
at 8M gas), then recreate the signer and the challenger (above). A hosted
provider's cap usually cannot be raised. A value above the node's cap makes the
signer report `upstream_tx_fee_cap`, which the daemon treats as critical at
once. It then bids within 10/11 of the lowest refused fee until it restarts,
and its `/status` warns with that fee
([details](../../docs/challenge-service.md#when-no-valid-bid-remains)). The
signer also warns `tx_fee_cap_below_fee_cap` while `ZKAPI_CHALLENGE_MAX_GAS` x
its fee cap exceeds the ceiling; see
[Node transaction fee cap](signer/README.md#node-transaction-fee-cap).

Fund the sender with at least (N + K) x gas limit x the highest bid, that is the
fee cap or, when lower, the ceiling / gas limit. N is the number of
transactions that may be pending at once and K a budget of reverted attempts.
At a 100 gwei cap that is 0.06 ETH per defeat and about 0.72 ETH per leaf
retirement; size N for `ceil(m/2)` defeats per note (a user holding `m`
archived states can force that many), at most 64 concurrent escapes and a 20%
margin. The signer's status warns `balance_below_required` below its
`required_balance`, `ZKAPI_CHALLENGE_MAX_GAS` x its fee cap (1.2 ETH at 100
gwei and the default 12M gas): fund up to it, or lower
`ZKAPI_CHALLENGE_MAX_GAS` while keeping a margin above a leaf retirement, for
example 8M (0.8 ETH at 100 gwei). The signer refuses a larger gas limit with
`gas_limit_exceeds_cap`, which the challenger reports as `signer_refused`,
critical at once, until `ZKAPI_CHALLENGE_MAX_GAS` is raised.

`challenge.env` holds the daemon's own bounds, which it proposes to the signer
(its transaction fee cap is in `deployment.env`, above):

| Variable | Requirement |
| --- | --- |
| `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` | Required. At most the signer's `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`. |
| `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` | Required. At most the signer's tip cap and this daemon's fee cap, and at least twice the priority fee, so that replacements have room to rise. Two replacements are kept for the critical threshold; a higher tip cap leaves more before it, within the signer's tip cap (10 gwei by default, 5 times the default priority fee; raise the signer's first). The daemon does not read the signer's fee or tip cap, so a cap above the signer's makes escalated bids fail with `fee_out_of_bounds` (`signer_refused`, critical at once) instead of bidding at the signer's cap. A pending challenge that used the others is reported as `fee_reserve_held`, which escalates like any blocked obligation. Raising both caps lifts it once 100/121 of the new caps is 10% above both of its fees, and the fee cap counts only up to the ceiling / gas limit (see [challenge operation](../../docs/challenge-service.md#building-and-sending-a-transaction)). |
| `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` | Optional tip of a first attempt; default 2 gwei. |

The challenger also reads from `deployment.env` (see
[`deployment.env.example`](deployment.env.example)):

| Variable | Requirement |
| --- | --- |
| `ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS` | Default 21600 (Mainnet and Sepolia); 1800 for the drill. An escape whose charge is still unsettled is raised to its proof's solvency bound at its deadline minus this. Startup refuses unless `LEASE_TTL_SECONDS + SETTLEMENT_GRACE_SECONDS + ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS` + this + 4 x 2 + 1200 is at most `challengePeriod()`. |
| `ZKAPI_CHALLENGE_RAISE_MIN_UNITS` | Optional; default 0. The smallest raise, in gwei, worth its gas. |
| `ZKAPI_CHALLENGE_RETIRE_ON_MISS` | Optional; default `true`. After a missed defeat, retire the closed note's leaf with `retireClosedLeaf` (about 7.2M gas), within the signer's `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY`. Set the same value in `signer.env`: the signer refuses retirements when it is `false`, and signs one only for a note an escape finalized within its `ZKAPI_CHALLENGE_RETIREMENT_LOOKBACK_BLOCKS`. |

The launcher passes the server's settlement window (`LEASE_TTL_SECONDS +
SETTLEMENT_GRACE_SECONDS + ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`, which
may not exceed the manifest's `settlement_window_seconds`) and the mounted
manifest to the challenger. At startup it checks the manifest against the vault:
`CONCESSION_ESCAPE_VERSION() == 1`, `ROOT_HISTORY_WINDOW() == 86400`, the
adapter's circuit and verifying-key hashes, the three runtime codehashes and
`challengePeriod()`, and the timing checks above. It retries a failed RPC read
and exits on a mismatch.

The launcher binds the daemon's status listener to `127.0.0.1:3002` inside the
container. The Compose healthcheck reads its `/livez`; never publish the port or
route it through the gateway, because its status shows when challenges are
blocked. The daemon opens `/data/server.db` read-only and needs the schema and
`deployment_binding` row `zkapi db init` writes: it refuses an older database
with "run `zkapi db init` first". See
[challenge operation](../../docs/challenge-service.md).

## Starting the deployment

Start in this order: the indexer, `zkapi db init` (the one-shot `db-init`
service), the challenger, the API, then the gateway that publishes it. The
challenger must be healthy before the first deposit.

```sh
sudo docker compose -f docker/aws/compose.yml --profile challenge config --quiet
sudo docker compose -f docker/aws/compose.yml up -d --wait indexer
sudo docker compose -f docker/aws/compose.yml run --rm db-init
sudo docker compose -f docker/aws/compose.yml --profile challenge up -d --wait challenger
sudo docker compose -f docker/aws/compose.yml up -d --wait server
sudo docker compose -f docker/aws/compose.yml up -d --wait gateway
sudo docker compose -f docker/aws/compose.yml --profile challenge ps
```

`up` starts the services it names and the ones they depend on, never the ones
that depend on them: nothing else starts the gateway, the only service that
publishes `ZKAPI_HTTP_PORT`, so the acceptance checks below need its line.

`db-init` is idempotent for the same deployment and refuses a database bound to
anything else; `server` and `challenger` also wait for it to complete.

`--wait` also waits for the indexer, whose healthcheck allows 900 seconds for a
full replay from `DEPLOY_BLOCK`; it turns healthy as soon as the replay verifies.

The challenge profile is explicit so image building and local startup checks
can run before a signer is available. Without it, `up` never starts the
challenger or the signer; such a deployment does not have escape-challenge
protection. The
challenger requires RPC `eth_sendTransaction`; an ordinary public RPC
cannot act as its signer. The included restricted signer sidecar requires an explicit supported chain
(1 or 11155111) and accepts only the challenger's defeat, raise and
leaf-retirement calls to its
configured vault. Its chain must match the RPC, public manifest and daemon. Never publish its RPC port.
Keep the funded sender exclusive to this daemon and deployment. Keep the API
running whenever the challenger runs: its settlement produces the challenge
evidence, and users recover their signed state from it after a challenge.

The default HTTP origin binds `127.0.0.1:8080`. For an EC2 origin behind
CloudFront, set `ZKAPI_HTTP_BIND=0.0.0.0` and `ZKAPI_HTTP_PORT=80` for Compose,
restrict inbound port 80 in the EC2 security group to the AWS-managed prefix
list `com.amazonaws.global.cloudfront.origin-facing`, and provide HTTPS at the
public edge. The request limits below trust the last `X-Forwarded-For` element
only because CloudFront writes it; a client that can reach the origin directly
can choose its own limit key. Set CloudFront caching disabled and forward all
query strings, required request headers, and methods for API/indexer paths. No
daemon or signer port should be exposed by the VM security group. Neither
SQLite data nor the operator dashboard is served by the gateway.

For password-gated Sepolia, forward `X-ZKAPI-Testnet-Password`, `Origin`, and
both `Access-Control-Request-*` headers through CloudFront. Preserve no-store
and CORS response headers and allow OPTIONS. The gate runs in the API process;
neither an alternate proxy route nor a direct daemon connection bypasses it.
See [access configuration and rotation](../../docs/testnet-auth.md). Never log
the password header or place the password in the public client manifest.

Optional Compose settings are `ZKAPI_IMAGE_TAG`, `ZKAPI_CONFIG_DIR`,
`ZKAPI_DATA_DIR`, `ZKAPI_HTTP_BIND` and `ZKAPI_HTTP_PORT`. Persist these settings
in the operator's root-owned Compose environment file and use the same settings
on each deployment command.

## Request limits

The gateway caps POST requests per network source before they reach the API:

| Zone | Route | Rate | Burst |
| --- | --- | --- | --- |
| `zkapi_clearance` | `POST /v2/withdraw/clearance` | 10 per second | 100 |
| `zkapi_lease` | `POST /v2/openrouter/leases` | 20 per second | 200 |
| `zkapi_v2_post` | every other `POST /v2/...` (lease retirement and expiry) | 20 per second | 200 |

GET, HEAD and OPTIONS requests, recovery reads, quotes, tree paths, health,
attestation and static files are never counted. These are coarse flood ceilings,
not per-user quotas. A browser host sends its users' protocol calls through one
same-origin rewrite or privacy proxy, so the gateway sees one source for all of
that host's users; size the limits for the largest host's aggregate peak,
including a burst of withdrawals during a migration. Per-user and volumetric
protection belongs at the host's edge or in AWS WAF rate-based rules. IPv6
clients can rotate addresses within their own range.

The source is the last `X-Forwarded-For` element when it looks like an IP
address (hex digits, dots and colons, at most 45 characters), otherwise the TCP
peer. CloudFront appends the address it received the request
from, so behind CloudFront this is the viewer (or the host's egress). The
pattern is anchored and its match time is linear in the header length.

A throttled request never reaches the API. The gateway answers `429` with
`Retry-After: 5`, `Cache-Control: no-store`, and an API error body:
`{"status":"error","client_request_id":"","error_code":"gateway_rate_limited","error_message":"...","retriable":true,"retry_after_seconds":5}`.
Retry the same request unchanged after the delay; nothing was processed or
reserved. The API's own errors, including its 429s, pass through unchanged.
The clients' exit rules count a 429 during an exit as an unreachable server,
and cannot tell an honest 429 from a forged one: a throttled clearance request
turns the withdrawal into an escape conceding nothing. Size the clearance
limit so that honest bursts, such as a wave of withdrawals during a migration,
are never throttled. The legacy builds of the `release/v2-note-bound` line
behave as that line's copy of this guide describes.

To change a limit, edit `nginx.conf` and rebuild and restart the gateway:

```sh
sudo docker compose -f docker/aws/compose.yml build gateway
sudo docker compose -f docker/aws/compose.yml up -d --no-deps --wait gateway
```

The gateway logs nothing per request. Each throttled request writes one line
with its status and zone only, for example
`{"event":"gateway_rate_limited","status":429,"zone":"zkapi_clearance"}`, with no
address or path.

## Monitoring

None of these checks is configured for you. Run them from the VM and alert on
the conditions listed. For the second project of a VM that runs two deployments,
add `-p` and `--env-file` as described under Upgrades, and use that project's
data directory and HTTP port.

```sh
dc() { sudo docker compose -f docker/aws/compose.yml --profile challenge "$@"; }
# Containers: each service's state and healthcheck (the challenger's reads /livez).
dc ps --all
# Challenger: 200 is ok or warning; 503 means a critical obligation or stale
# polling (/status has the detail); a failed exec means the daemon is not running.
dc exec -T challenger curl -sS -w '\n%{http_code}\n' http://127.0.0.1:3002/health
dc exec -T challenger curl -sS http://127.0.0.1:3002/status
# Indexer: 200 only while a verified view is served.
dc exec -T indexer curl -sS -w '\n%{http_code}\n' http://127.0.0.1:3001/health
dc exec -T indexer curl -sS http://127.0.0.1:3001/metrics
# Signer: fee policy, balance and warnings.
dc exec -T challenger curl -sS -X POST http://signer:8547 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"zkapi_signerStatus","params":[]}'
# API, on the gateway's ZKAPI_HTTP_PORT (8080 by default): the statement served.
curl -fsS http://127.0.0.1:8080/health | jq '{circuit_id, setup_id, exit_concession, settlement_window_seconds}'
# Settlement: pending leases, deadlines and open reviews, and the settled
# leases whose signature an exit defers (counts.exit_deferred) or ended
# (counts.exited_unsigned) (operator-only route).
dc exec -T server curl -fsS 'http://127.0.0.1:3000/v1/dashboard/settlement?limit=50'
```

On a password-gated Sepolia server the dashboard route needs the password header,
for example
`dc exec -T server sh -c 'printf "X-ZKAPI-Testnet-Password: %s\n" "$ZKAPI_TESTNET_PASSWORD" | curl -fsS -H @- http://127.0.0.1:3000/v1/dashboard/settlement'`.

Alert on:

- challenger `/health` answering anything but 200, including no answer at all,
  and the challenger container not running or not healthy in `dc ps --all`. A
  stopped, restarting or crash-looping challenger (for example one that exits
  on a deployment-binding mismatch and is restarted by Compose) reports
  nothing itself: the `exec` fails, and none of its other signals below can
  fire;
- any `critical` entry in the challenger's `/status` `alarms` (it then answers
  503 on `/health`): a missed defeat (an escape paid out although verified
  request evidence at its successor nullifier existed before its deadline) or
  a missed raise (an escape paid out with a concession below what the server
  was owed); the latest miss stays critical for an hour; an obligation ready
  to defeat or raise whose deadline is within a quarter of `challengePeriod()`; an obligation blocked by
  `evidence_invalid`, `evidence_db_error`, `indexer_invalid_response`,
  `indexer_diverged`, `signer_refused` or `upstream_tx_fee_cap`, or by any
  other reason (including `fee_reserve_held`) for 1800 seconds; stale polls; a
  diverged indexer; or an unmined nonce that needs signer intervention;
- challenger `/status` warnings naming the transaction fee ceiling (an
  obligation blocked by `tx_fee_cap_reached`), a signer `tx_fee_cap_wei` that
  differs from the daemon's, a transaction fee the signer's node refused
  (`upstream_tx_fee_cap`), a fee cap above the ceiling, or an indexer
  pending-escapes list that disagrees with the vault;
- the challenger log lines `MISSED escape deadline` (with `missed="defeat"`
  or `missed="raise"`), `escape paid out after a missed defeat; retiring the
  closed note's leaf`, `indexer mirror diverged from vault currentRoot`, and
  `challenge obligation status changed` at error level, and a rising
  `missed_total`, `escapes_finalized_with_successor_evidence_total` or
  `missed_raises_total` in `/status`. A `retiring_leaf` obligation is a warning
  until its `retireClosedLeaf` mines; it needs the indexer's path for the
  note;
- indexer `/health` not 200 for more than two minutes (outside a planned replay),
  an increase in its `divergence_count`, `rebuild_count` or
  `missed_re_escape_count` (`zkapi_indexer_divergences_total`,
  `zkapi_indexer_rebuilds_total`, `zkapi_indexer_missed_re_escapes_total`), and
  a `head_age_seconds` near `INDEXER_MAX_HEAD_AGE_SECS`; also its ERROR log
  lines, such as `indexer mirror diverged from vault state; tree endpoints
  return 503` and `escape finalized that the indexer never saw initiated`. A
  missed re-escape means that the indexer RPC's `eth_getLogs` dropped a
  challenge and re-escape of a note, or that a reorganization below the
  checkpoint replaced an escape: check that RPC's log completeness, then resync
  (below). Each is counted once per escape, logged at warn level for a
  defeat or a raise (`event="raised"`, `missed_re_escape_raised_count`) and at
  error level for a finalization, and the counts restart with the indexer. Page on `event="finalized"` (`missed_re_escape_finalized_count`):
  the vault finalized that escape (it paid the destination or credited the
  payout to it), so also confirm that the challenger tracked it;
- the indexer's `root` differing from `currentRoot()` read at its `served_block`
  through a different RPC than the indexer's own, and a note that its
  `/v1/escapes/pending` lists while the vault holds no escape for it (both
  checks are under Indexer resync, step 1; run them daily). The challenger also
  reports such a dead entry, as the pending-escapes warning above, once reads
  `--blocked-warning-seconds` apart find no escape for it and a list served
  after the first such read still names it; the daily check stays an
  independent cross-check through another RPC, and the indexer `/health` and
  `head_age_seconds` checks above catch a stalled list;
- `settlement required operator review` in the server log, and a nonzero
  `open_reviews` in `/v1/dashboard/settlement`;
- `unreadable OpenRouter lease row cannot be settled` in the server log (logged
  at every settlement tick, naming the row's `client_request_id`): that pending
  lease is not settled, not even at its settlement deadline, and its nullifier
  stays reserved until you repair the row: restore a saved request that cannot
  be read, or repair any other corrupt column by hand; see
  [Restoring an unreadable pending lease](../../docs/native-eth-billing.md#restoring-an-unreadable-pending-lease);
- the vault's owner, treasury, escape and payout events: any
  `OwnershipTransferStarted` you did not send, `TreasuryChangeScheduled`,
  `Paused`, `Unpaused`, `TreasuryPaymentDeferred`, `EscapePayoutDeferred`,
  `EscapeConcessionRaised` and `ClosedLeafRetired` (see the migration
  runbook's [Operations runbooks](../../docs/migration-concession-vault.md#operations-runbooks),
  Pause, Treasury arrears, Escape payout credits, and Missed defeat or raise).
  `EscapePayoutDeferred` means an escape closed without paying its
  destination. The browser SDK reports an escape it started as credited and
  offers its users the claim, and `zkapi-clientd` shows the claim for its own
  escapes, but an escape started elsewhere reaches its owner only through
  you: announce the credit as that runbook says;
- a non-empty `warnings` list from `zkapi_signerStatus` (`base_fee_above_cap`,
  `base_fee_near_cap`, `balance_below_required`, `tx_fee_cap_below_fee_cap`;
  the challenger bids no higher than the ceiling / gas limit, so the last
  means only that a leaf retirement may not bid the full fee cap; see the
  signer README, Deploying with a concession-exit vault, step 2),
  signer `/health` failures, and signer audit lines
  `"event":"challenge_refused"` with reason `base_fee_above_max_fee`,
  `insufficient_balance`, `tx_fee_above_cap`, `upstream_tx_fee_cap` or
  `broadcast_ambiguous`;
- sustained `root_unavailable` refusals, or the server log line `the indexer
  root and the vault's currentRoot() disagree`: the indexer lags or diverges, or
  the RPC fails, and no request is admitted;
- a growing `counts.exit_deferred` or `counts.exited_unsigned` on the settlement
  dashboard, or the server log lines `exit_deferred` and `ExitedUnsigned`: exits
  consumed requests' nullifiers before their successors were signed;
- sustained `gateway_rate_limited` lines in the gateway log, per zone.

Acknowledge a settlement review after handling it, with the host's `sqlite3`.
The table is a log keyed by `review_id`: one lease can have several rows, such
as its cancellation, its reopening and its final settlement. Acknowledging by
`client_request_id` would also acknowledge a later `binding_reopened` row, or
the new `binding_corrupt` row of a re-cancellation. Run writes as the
container's user 10001, so that no root-owned journal file can be left behind:

```sh
sudo sqlite3 -readonly /var/lib/zkapi/server.db \
  "SELECT review_id, client_request_id, reason, charge_basis, charge_applied, solvency_bound, detail FROM settlement_reviews WHERE acknowledged_at IS NULL;"
sudo setpriv --reuid=10001 --regid=10001 --clear-groups sqlite3 /var/lib/zkapi/server.db \
  "UPDATE settlement_reviews SET acknowledged_at = strftime('%s','now') WHERE review_id = REPLACE_WITH_REVIEW_ID;"
```

A `binding_corrupt` review leaves its owner's request unsettled: the server
grants no mutual-close clearance for the reserved nullifier, so the owner's
client escapes once the request's settlement time has passed, conceding the
state's bound, the most the challenger could raise to. Reopening the lease
lets the owner install the real successor and pay only its charge instead.
Reopen it before the note expires. With `ID` set to the
review's `client_request_id`, first wait until the lease row's status is
`cancelled`. Check the row itself: the dashboard's `pending` list holds at most
`limit` leases, ordered by deadline, so a lease missing from it may still be
pending.

```sh
sudo sqlite3 -readonly /var/lib/zkapi/server.db \
  "SELECT client_request_id, status FROM openrouter_leases WHERE client_request_id = '$ID';"
```

Then reopen it:

```sh
dc stop server
dc run --rm --no-deps --entrypoint zkapi server settlement reopen \
  --db-path /data/server.db --client-request-id "$ID"
dc start server
```

The challenger may keep running; it only reads the database. The command
verifies the lease's saved request against its proof with the image's proof
setup (`ZKAPI_PROOF_SETUP_DIR` when `deployment.env` sets it). It changes
nothing while it refuses, and each refusal names the field and its repair:

- If it names `openrouter_leases.api_request_json`, the saved request is the
  corrupt side: run it again with the authentic request, from a backup of the
  server database or from its owner, on standard input
  (`dc run -T --rm --no-deps --entrypoint zkapi server settlement reopen --db-path /data/server.db --client-request-id "$ID" --saved-request - < request.json`).
- If it names another field, follow the repair it names, usually `--rebind`.
  A `Finalized` reservation, a reservation kept under another nullifier, and a
  corrupt `nullifiers.api_request_binding` together with a corrupt saved
  request each need a hand repair of the database instead (see
  [Reopening a cancelled lease](../../docs/native-eth-billing.md#reopening-a-cancelled-lease)).
  A `ClearanceReserved` refusal needs nothing: that owner exits by mutual close.

Add `--zero-charge` to concede the request's charge; a lease reopened earlier
whose binding is found corrupt again is repaired and conceded with
`--zero-charge --rebind`. The restarted server verifies the lease again before
it signs. Once the query above, with the `client_request_id` the command
printed (`--rebind` may have corrected it), shows `finalized`, acknowledge each
of the lease's `binding_reopened` reviews: a later `--zero-charge` concession
adds one. Each reopening or concession itself acknowledges the lease's open
`binding_corrupt` reviews. See
[Reopening a cancelled lease](../../docs/native-eth-billing.md#reopening-a-cancelled-lease).

A pending lease whose saved request cannot be read (one cause of the log line
above, or of `lease_record_unreadable` on its status) is restored with the
same command, `-T` after `run` and `--saved-request - < request.json`, without
waiting for a cancellation: it keeps its status and the command prints
`"result": "restored"`. If the row's saved request can be read, the command
refuses it, and if the row stays undecodable after the restoration, the
command fails with a database error and changes nothing: either way another
column is corrupt and needs a hand repair. See
[Restoring an unreadable pending lease](../../docs/native-eth-billing.md#restoring-an-unreadable-pending-lease).

Back up the server database regularly with sqlite3's online backup; the server
keeps running:

```sh
sudo install -d -m 700 /var/backups/zkapi
sudo sqlite3 -readonly /var/lib/zkapi/server.db ".backup /var/backups/zkapi/server-$(date +%F).db"
```

## Indexer resync

Resync when the indexer reports `diverged`, when its root disagrees with the
vault, when it lists a note that the vault holds no escape for (step 1), when
the challenger reports `indexer_diverged`, or when the challenger's `/status`
keeps showing `indexer.pending_escapes_disagreement`. The indexer verifies only
its root and next note ID, so a listing left stale by a dropped challenge and
re-escape is otherwise corrected only by the note's next challenge or
finalization, and a note left listed by a dropped finalization, or by a
challenge and a close or claim that were both dropped, only by a resync. The
challenger reports such a dead entry in `indexer.pending_escapes_disagreement`,
with a warning, once reads `--blocked-warning-seconds` apart find no escape for
it and a list served after the first such read still names it (a list that may
only lag the vault is not reported). Once reads 60 seconds apart have found
none, it reads that note only every 16 polls, so dead entries do not hold up
its checks of the other listed escapes. Waiting never repairs a divergence. The indexer rebuilds
automatically after a detected divergence or a reorganization below its
checkpoint, at most once per 300 seconds; a resync forces an immediate rebuild
from `DEPLOY_BLOCK`.

1. Compare the indexer with the vault, reading the vault through an RPC other
   than the indexer's (set `VAULT` to the vault address and `CHECK_RPC_URL` to
   that RPC):

   ```sh
   H=$(sudo docker compose -f docker/aws/compose.yml exec -T indexer curl -sS http://127.0.0.1:3001/health)
   echo "$H" | jq '{status, reason, served_block, root, next_note_id, lag_blocks, head_age_seconds, last_error}'
   B=$(echo "$H" | jq -r .served_block)
   cast to-dec "$(echo "$H" | jq -r .root)"
   cast to-dec "$(cast call "$VAULT" 'currentRoot()' --block "$B" --rpc-url "$CHECK_RPC_URL")"
   cast call "$VAULT" 'nextNoteId()(uint32)' --block "$B" --rpc-url "$CHECK_RPC_URL"
   ```

   Then check that the vault holds an escape for every note the indexer lists
   as pending, at the block of that list. Any output is a dead entry:

   ```sh
   L=$(sudo docker compose -f docker/aws/compose.yml exec -T indexer curl -fsS http://127.0.0.1:3001/v1/escapes/pending)
   LB=$(echo "$L" | jq -r .block_number)
   for i in $(echo "$L" | jq -r '.escapes[].note_id'); do
     exists=$(cast call --json "$VAULT" 'pendingWithdrawals(uint32)(bool,uint256,uint256,uint128,address,uint64)' "$i" --block "$LB" --rpc-url "$CHECK_RPC_URL" | jq -r '.[0]')
     [ "$exists" = true ] || echo "note $i is listed, but the vault holds no escape for it at block $LB"
   done
   ```

2. Request a resync and restart. The indexer archives its checkpoint as
   `indexer.cursor.resync-<unix_ms>.bak`, deletes the request file and replays
   from `DEPLOY_BLOCK`; its tree routes answer 503 until the replay verifies.

   ```sh
   sudo touch "${ZKAPI_DATA_DIR:-/var/lib/zkapi}/indexer.cursor.resync"
   sudo docker compose -f docker/aws/compose.yml restart indexer
   ```

   A plain restart is enough here because no environment file changed; after
   an edit to `indexer.env` or `deployment.env`, recreate the indexer instead
   (`up -d --no-deps indexer`).

   A directly launched `zkapi-indexerd` or `zkapi indexer` can be restarted with
   `--resync` instead; remove the flag afterwards, or every restart resyncs.

3. Watch `/health` until `status` is `ok`, then repeat step 1. If it does not
   converge, check the RPC requirements above; switch `RPC_URL` to a consistent
   endpoint if replicas disagree.

A replay costs about (head − `DEPLOY_BLOCK`) / 1000 `eth_getLogs` calls, paced at
one per 100 ms, plus verification. Start it at least twice that long before the
nearest pending challenge deadline. Never edit the checkpoint or SQLite files by
hand, beyond the documented `sqlite3` statements (acknowledging settlement
reviews under Monitoring, and, on a legacy stack only, the receipt journal
missing remediation of that line's migration guide) and the hand repairs that
[Reopening a cancelled lease](../../docs/native-eth-billing.md#reopening-a-cancelled-lease)
names for refusals the reopen command cannot repair, which are database
surgery outside these runbooks; never delete `challenges.json`, and never point
two indexers at one checkpoint (the second refuses: `another indexer holds this
checkpoint`).

## Upgrades and running two deployments

Upgrade a deployment in place by rebuilding from the new release with a new
`ZKAPI_IMAGE_TAG`, so the previous images stay available for rollback. Back up
`/var/lib/zkapi` while the services are stopped. The move from a legacy
vault to a revision-3 vault is not an in-place upgrade: it is a new
deployment, as below, run in the order of
[the concession-vault migration runbook](../../docs/migration-concession-vault.md).
To roll the indexer back to an earlier image, move `indexer.cursor` aside first
so that the earlier indexer replays from `DEPLOY_BLOCK`; that replay is the
only rollback path. An indexer of this release archives a checkpoint of an
earlier format (`indexer.cursor.v1-<unix_ms>.bak` or `.v2-<unix_ms>.bak`) and
replays; such a file may be a diverged mirror and nothing here can check it
against the vault: keep it for forensics and never restore it.

A redeployed vault is a new deployment: new public manifest and hostname, a new
signer key and exclusive sender, and a fresh data directory (database, indexer
checkpoint and challenge checkpoint). The database refuses a second vault, and a
checkpoint is bound to its chain and vault. Never repoint a signer or challenger
at another vault while its vault still has active notes or pending escapes;
keep both stacks running until the old vault is drained.

Prefer a separate VM for each deployment. On one VM, run the deployment being
drained as a second Compose project with its own configuration directory, data
directory and HTTP port, for example `/etc/zkapi-legacy/compose.env`:

```sh
ZKAPI_CONFIG_DIR=/etc/zkapi-legacy
ZKAPI_DATA_DIR=/var/lib/zkapi-legacy
ZKAPI_HTTP_BIND=0.0.0.0
ZKAPI_HTTP_PORT=8081
ZKAPI_IMAGE_TAG=REPLACE_WITH_RELEASE_TAG
```

Pass `-p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env` on every command
for that project, for example
`sudo docker compose -p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env -f docker/aws/compose.yml --profile challenge ps`.
To move an existing deployment into that project, stop all of its services,
move `/etc/zkapi` and `/var/lib/zkapi` to the new paths with `mv` (keeping
ownership and the SQLite lock file with its database), start it under the new
project name, and point its CloudFront origin at the new port. The newer
deployment then uses the default paths and project. The two projects never
share a data directory, signer key, sender or hostname. Images are shared by
name and tag across projects, and the gateway image contains the checkout's
`nginx.conf`: when one project needs a change the other must not get, such as
the drained deployment's deposit cutoff, build it from its own checkout under
its own `ZKAPI_IMAGE_TAG`.

## Acceptance checks

```sh
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/v1/attestation
curl --fail http://127.0.0.1:8080/v1/tree/root
sudo docker compose -f docker/aws/compose.yml --profile challenge ps
sudo docker compose -f docker/aws/compose.yml --profile challenge exec -T challenger curl -sS http://127.0.0.1:3002/status
sudo docker compose -f docker/aws/compose.yml logs --tail=50 server challenger
```

Verify that health and attestation report protocol 2, the selected chain, the
configured vault, `circuit_id` `zkapi-v2-concession-v1`, `setup_id` `mpc-1`
(`dev` for a [single-party](#single-party-setup) image),
`exit_concession` 1 and the deployment's `settlement_window_seconds`. Confirm
the server log lines `server signing keys match the vault's immutable keys` and
`the vault, adapter and Poseidon library match the deployment manifest`, and
compare the
attestation keys with the vault's getters as numbers (the attestation omits
leading zeros):

```sh
for getter in stateSigningKeyX stateSigningKeyY clearanceSigningKeyX clearanceSigningKeyY; do
  cast to-dec "$(cast call "$VAULT" "$getter()" --rpc-url "$CHECK_RPC_URL")"
done
curl -fsS http://127.0.0.1:8080/v1/attestation \
  | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
  | while read -r value; do cast to-dec "$value"; done
```

Compare the indexer root and next note ID with the vault as under Indexer
resync. Verify that `/v1/dashboard/settlement`, `/v1/dashboard/recent`,
`/v1/dashboard/events` and `/v1/escapes/pending` return 404 through the public
origin and HTTPS edge. Optionally probe the request limit: an empty body is
rejected by the API before anything is reserved, so this shows about 100 API
errors followed by `429`.

```sh
for i in $(seq 1 120); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' -d '{}' \
    http://127.0.0.1:8080/v2/withdraw/clearance
done | sort | uniq -c
```

The API health endpoint measures process health; successful chain
synchronization and challenge transaction submission require the independent
checks above and the live test flow described in the deployment docs.

All services restart after a VM reboot when Docker is enabled. Database,
indexer checkpoint and challenge checkpoint live in `/var/lib/zkapi`; preserve and
back up that directory across image updates. The challenger shares the API's
SQLite database and must use the same host filesystem for SQLite locking. A
recreated image must use the same setup artifacts as the deployed verifier.

## Validation

Run the local SDK, Rust, Solidity, launcher, gateway and signer tests before
rollout. `node --test docker/aws/run-daemon.test.mjs docker/aws/nginx.test.mjs`
checks the launcher and the gateway configuration; with an `nginx` binary on
`PATH` (or `NGINX_BIN`) the gateway test also runs the configuration against a
stub API, and `ZKAPI_REQUIRE_NGINX=1` makes a missing binary a failure. Check the
built gateway image with
`sudo docker run --rm --user 101:101 --read-only --tmpfs /tmp --entrypoint nginx zkapi/gateway:${ZKAPI_IMAGE_TAG:-concession-v1} -t`.
Use a separately authorized native ETH lifecycle check for the intended network;
read-only health/quote checks alone do not establish paid inference, withdrawal
or live escape-challenge success. Preserve server data, checkpoints and signer
funding throughout any deployment change.
