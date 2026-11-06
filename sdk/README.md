# zkAPI browser SDK

`@openanonymity/zkapi-browser-sdk` owns the browser wallet, local proof worker,
private-note journal, short-lived key issuance and settlement, deposit/withdrawal
recovery, and public payment-history reconciliation. It has no UI,
model-catalog, or chat-storage dependency. The host owns chat and payment UI.

Install a reviewed immutable Git revision, or install its `npm pack` tarball.
No Rust compiler, setup ceremony, or npm publish step is needed to
consume this package. The public proving keys and WASM are included and hashed
in `sdk/assets/manifest.json`; these are public artifacts, not wallet secrets.

```js
import { configureBrowserSdk } from '@openanonymity/zkapi-browser-sdk';
import client from '@openanonymity/zkapi-browser-sdk/client';

configureBrowserSdk({
  configUrl: '/zkapi/browser-config.json',
  workerUrl: '/zkapi/assets/zkapiWasmWorker.js',
  // Optional: the host may preserve its explicit opt-in privacy proxy policy.
  transport: (url, init, hints) => hostTransport.fetch(url, init, hints)
});

// Initialize only when private payments are enabled. Importing creates no
// proof worker, network request, wallet connection, or wallet popup.
await client.init();
const unsubscribe = client.subscribe(snapshot => renderBalance(snapshot));
```

Configuration must precede the first initialization. The SDK runs only the
native ETH browser wallet; `mode: 'auto'` and `mode: 'daemon'` are unsupported.
The host config URL supplies the pinned network, vault, server signing keys,
proof hashes, and approved deployment manifest URLs. Runtime URL overrides
remain restricted to that allowlist. Configure the same-origin
`/zkapi-deployment/` rewrite for the chosen trusted deployment, as declared by
the bundled browser config. Private protocol and public manifest/config requests omit account credentials,
including through the same-origin deployment rewrite. An injected transport
receives `credentials: 'omit'` and the existing `{ preferProxy: true }` hint and
must preserve that credential policy. Chat account cookies must never accompany
private proof or key issuance requests.
Never include note secrets, key values, proof bodies, or wallet transactions
in host logs.

## Sepolia shared password

A Sepolia server can require a shared testnet password. Pass
`requestTestnetPassword: async ({ authenticate, signal }) => { ... }` to
`configureBrowserSdk`. Show a password form and call
`await authenticate(value, { signal: dialogAbortSignal })` on explicit submit.
Keep the form open for a rejected password; resolve the callback only after
validation succeeds. Reject on dismissal, and abort its validation request.
Neither the callback nor the SDK should log or persist the password.

Call `client.ensureTestnetAccess({ interactive: true, signal })` before the
host's Send gate, including when reusing a live provider key. Deposit and
access acquisition also enforce this inside the SDK. Read-only funding quotes
fail with `testnet_password_required` until authenticated; they never open a
dialog in background polling. Offer an explicit password action that calls
`ensureTestnetAccess({ interactive: true, changePassword: true })`. The boolean
`client.testnetAuthenticated` contains no credential. Reload clears access.

Cooperative withdrawal authenticates before wallet work and refuses to continue
if the selected private note changes while its password dialog is open.
Unilateral escape does not request the service password.

Public `/health` must report the configured Sepolia `chain_id` and boolean
`testnet_password_required`; missing or invalid discovery fails closed. The
password is validated at `/v2/auth`, then attached only to the configured
Sepolia protocol server's `/v2/` paths as `X-ZKAPI-Testnet-Password`. The host's
trusted same-origin deployment rewrite and opt-in transport retain their
normal roles. Transports must honor `redirect: 'error'` for these requests.
Account cookies remain omitted. RPC, indexer, proof downloads, account
endpoints and provider inference never receive this password. A 401 clears
the rejected credential without replaying a protocol operation; recovery
journals remain authoritative. Mainnet does no password discovery or prompting.

This SDK requires `proof_setup.circuit_id: "zkapi-v2-note-bound-v1"` in the
deployment manifest and matching `trusted_deployment.circuit_id` in the host
config. The vault's immutable verifier, proving keys, and signing-key pins must
match this circuit. Configuration mismatches are rejected before funding.

## External wallets and manual signing

`client.setWalletProvider(provider)` selects an instance-scoped EIP-1193
provider. The default is the browser's injected `globalThis.ethereum`;
`setWalletProvider(null)` restores that default. The SDK never replaces the
browser global. Install the host provider before `client.init()` when restoring
a saved external transaction. Changing providers during an asynchronous SDK
operation throws `wallet_provider_busy`; nested calls retain the same provider
through RPC reads, wallet prompts, journal commits, and receipt polling.
`client.walletProviderBusy` exposes this state. Providers may also expose
`hasPendingTransaction: true` to prevent switching away from an unresolved
durable request after its UI stops waiting. Re-selecting the same provider is
always a no-op.

A host can implement manual signing without a wallet extension: obtain the
user's public account address for `eth_requestAccounts`, use a fixed public RPC
for reads, and display the exact `eth_sendTransaction` payload for submission
with the user's own wallet. The connected address funds deposits and pays
withdrawal gas. By default it is also the destination of a newly prepared
withdrawal. To choose an independent payout address, call
`client.withdraw(mode, onStatus, { destination })`, where `mode` is `mutual` or
`escape`. The destination must be a nonzero Ethereum address, distinct from the
configured vault. The host must confirm the intended address
and network with the user. The SDK binds it into the durable proof; an explicit
different destination on a later call is rejected. Omitting the option when
resuming always retains the saved destination, even if the gas-paying account
changes. Concurrent withdrawals with different requested destinations cannot
share an action. Native deposits require the SDK's payable vault calldata
and its exact ETH value; a plain ETH transfer does not create a private note.

For durable manual signing, the provider implements
`acknowledgeTransaction(hash)`. The SDK then includes a `zkapiRecovery` field
alongside `method` and `params` in each send request. It contains only public
deployment and journal identities, never note secrets, private state, or proof
plans. Before displaying an executable payload, the provider must durably save
the transaction (including its exact nonce) and this context. It must preserve
them through UI dismissal and reload, verify a supplied hash matches the exact
chain, sender, target, value, nonce, and calldata, and retain that hash until
the SDK acknowledges it. Do not forward `zkapiRecovery` to a remote RPC service.

For a live request, return the verified hash to `request()`; the SDK acknowledges
after the existing deposit/withdrawal journal accepts it. After reload, call
`client.resumeExternalTransaction({ transaction, hash, context })`, where
`context` is the saved `zkapiRecovery`. This independently reads and checks the
transaction, validates the durable SDK claim and exact plan, and invokes the
same atomic journal methods. It does not confirm deposits or withdrawals by
itself. Continue using `recoverBrowserDeposit()`, `syncWithdrawal()`, and
`syncEscapeWithdrawals()` for the usual canonical-state and finality checks.
Resumption is idempotent when a previous journal write succeeded but host
acknowledgement was interrupted. The host owns the public pending-send record;
private wallet material and all settlement and payout decisions stay in the SDK.

To recover fee speed-ups while a transaction is still awaiting its receipt,
providers may implement `getVerifiedTransactionHashes(originalHash)`,
`beginTransactionReceiptWait(originalHash)`, and
`endTransactionReceiptWait(originalHash)`. Return only hashes independently
verified against the same original chain, sender, target, calldata, value and
nonce. The SDK checks each candidate's own receipt and acknowledges the hash
that actually mined; either the original or its replacement may win the nonce.
The host should add newly verified hashes to the active receipt consumer rather
than start a concurrent resume operation. Preserve that consumer's completed
hash through cross-tab acknowledgment, and make repeated acknowledgments of
completed transactions harmless to any newer pending transaction. These hooks
track receipt-only requests; browser deposit/withdrawal recovery remains journal-owned.

In the host build:

```js
import { build } from 'esbuild';
import { buildBrowserSdkAssets } from '@openanonymity/zkapi-browser-sdk/build';

await buildBrowserSdkAssets({
  outDir: 'dist/zkapi',
  publicPath: '/zkapi/',
  network: 'sepolia', // or 'mainnet'
  build
});
```

The helper emits `browser-config.json`, `assets/zkapiWasmWorker.js`,
`wasm/zkapi_browser_bg.wasm`, `proofs/request.pk`, `proofs/withdrawal.pk`, and
`sdk-assets.json`. It verifies all source artifact hashes and both proving-key
pins before returning. The host supplies its esbuild implementation, controls
its CSP/rewrites, and hashes these emitted assets in its deployment manifest.
Proof downloads are verified again inside the worker. No private credentials
are required to build either network.

The SDK uses IndexedDB, local/session storage, Web Locks, BroadcastChannel,
revision checks, and signed receipt validation to manage wallet state. Hosting
the same SDK on a different origin does not transfer browser wallet data. A model adapter must select one of
`CHAT_SPENDING_TIER_USD` (`1`, `2`, `3`, `4.5`, `6`) without disclosing the user's
exact balance. The SDK settles/rekeys when a selected cap changes; only actual
usage is charged. Expiry and withdrawal contract behavior are unchanged.

Run `npm run test:sdk` in this checkout. For an installed package, run
`node --test node_modules/@openanonymity/zkapi-browser-sdk/sdk/test/*.test.mjs`
from a host that provides esbuild as a development dependency. The tests use
local fixtures and do not connect a wallet or broadcast transactions.

## Native ETH deployments

Native ETH requires a trusted native vault and billing-server configuration.
Token manifests are unsupported and rejected before wallet mutation. Notes and
transaction journals are bound to the configured chain and vault.
Native manifests pin `billing_asset: "native_eth"`, `billing_unit: "gwei"`,
`native_asset_wei_per_unit: "1000000000"`, a null `billing_token_address`,
`rpc_url`, `native_price_feed_address`, `native_price_feed_decimals: 8`, and
`native_price_max_age_seconds`. The browser config must pin the same values.
Protocol amounts are whole gwei, bounded by JavaScript's safe-integer range.
For a payable deposit, `msg.value` must equal the exact ledger
amount multiplied by one billion wei. Token minting, approvals and transfers are unsupported.
Withdrawals and all other protected calls retain zero transaction value.

`client.isNativeEthFunding` identifies native deployments.
`await client.quoteDepositUsd("10")` makes credential-free reads of the pinned
Chainlink feed at a finalized block, without connecting a wallet, preparing a
note, or signing. The finalized reference price can lag the latest block; the
quote exposes the feed's actual update time. Native deployment freshness pins
include the feed heartbeat plus a finality allowance (4,500 seconds for the
reviewed one-hour ETH/USD feeds), and any longer delay fails closed.
It returns `{ amount, ethAmount, depositWei, usdAmount, priceUpdatedAt, price,
chainId, contractAddress }`. Amount and wei fields are exact decimal strings;
`priceUpdatedAt` is Unix seconds. Persist this quote with the host's deposit
intent. The ETH principal remains fixed while a user funds the address; a
fresh quote must never silently change it. Native deposits accept up to nine
ETH decimal places. Recovery validates the exact saved calldata and payable
value against the durable deposit journal.

For a browser-controlled funding address, prepare the actual native deposit
before quoting its fee:

```js
const prepared = await client.prepareDepositQuote(quote.ethAmount, { from: fundingAddress });
// Simulate prepared.transaction using the host's public RPC. When the address
// is unfunded, override only that sender's balance, never contract storage.
// Show estimated fee, additional buffer and principal + reserved fee separately.
// Refresh the preparation and fee quote before the explicit Next action.
await client.deposit(quote.ethAmount, onStatus, { preparedOperationId: prepared.operationId });
```

`prepareDepositQuote` is available only for native ETH browser wallets. It
returns `{ operationId, commitment, amount, depositWei, chainId,
contractAddress, transaction: { from, to, data, value } }`; it never returns
note secrets, connects a wallet, claims a submission, signs, or broadcasts.
It stores the note secret in a separate durable `depositQuote` draft, which is
not a pending deposit or payment-history entry. Read-only polling and reload
cannot promote it. Same-amount refreshes retain the commitment and operation
identity while updating the Merkle append path. Changing the amount replaces
only the unused draft. An active note or unresolved deposit must be recovered
before another quote is prepared. After a proven pre-broadcast rejection, an
existing pending deposit can be requoted only when
`config.pending_deposit.funding_quote_available === true`. Its principal,
commitment and operation remain fixed. Claimed, signed and ambiguous
transactions are excluded; hosts must use this authoritative flag rather than
infer safety from the visible transaction hash. SDK storage keeps drafts
deployment-bound.

For an ambiguous funding-address deposit, an explicit user action may call
`await client.prepareDepositRetry(onStatus)` to review retry fees. This checks
for a mined deposit first and returns `status: "confirmed"` if recovered.
Otherwise it authorizes only an exact retry fee review, including a saved
`retry_exact` operation. It does not sign or submit. The funding-quote flag
then permits simulation of the saved calldata without
refreshing its Merkle path. After the quote is shown, a separate explicit Next
uses the same `preparedOperationId`. A pre-broadcast fee rejection keeps that
exact path for the next quote. Only finalized consumed-slot recovery permits
rebasing an uncertain old operation, and it records which ambiguity was
resolved while retaining the original claims for late recovery. Ordinary
MetaMask retry behavior remains unchanged.

An explicit deposit with `preparedOperationId` atomically promotes that exact
draft under the wallet's cross-tab lock. A stale operation or changed principal
fails before any submission. An ordinary deposit without the option (including
MetaMask) discards an unused draft. Refreshing a Merkle path never changes the
principal or commitment. The host must bind its displayed fee authorization to
the returned operation and commitment and enforce that ceiling again on the
actual transaction; a quote is not permission to sign. The actual transaction
continues to simulate the current vault state and may need a new quote/top-up
if network fees increase. Unsupported balance overrides must fail with a clear
estimation error rather than silently substituting a fixed reserve.

After native deposit confirmation, `client.snapshot().deposits` may include
`feeWei`, `fundingAddress`, `gasUsed`, `effectiveGasPrice`,
`receiptBlockNumber`, and `receiptBlockHash`. These fields are stored with the
existing public deposit history, including across reload or note closure.
`feeWei` is mined `gasUsed * effectiveGasPrice`, not the maximum gas limit or
fee quote. The SDK verifies the receipt event, exact mined transaction and
canonical block before recording it. Deposit recovery checks saved transaction
hashes for that same evidence before clearing its journal. Missing or historical
fee evidence leaves these fields absent; hosts must show unavailable rather
than zero. The public funding-address balance is read separately: it may include
previous funds and is not necessarily only this deposit's unused fee buffer.

`client.formatBillingAmount(units)` returns decimal ETH on native deployments;
`client.formatMoney(units)` uses the current verified quote, returning `—`
when none is fresh. Normal wallet refreshes attempt a public price refresh at
most once per minute; `refreshEthUsdPrice({ signal })` explicitly refreshes it.
`creditsPerUsd` is only a display conversion on native deployments, may be
fractional, and is `NaN` without a fresh quote. It is not an integer billing
scale and must not be used to construct a payment or proof.

For inference, the server's public `/v2/billing/quote` is checked against the
pinned feed's exact round in finalized chain state. New issuance accepts only
the latest finalized round. The complete quote is bound into the
prompt-free authorization payload before generating its proof. Fixed USD
model tiers round upward to whole gwei; the provider's USD limit rounds down
to microdollars. The saved request, issued key, and settlement all retain that
same quote, even if ETH's price subsequently changes. A quote that expires or
is superseded before acceptance can be discarded only after the read-only
`POST /v2/openrouter/leases/{id}/expire` endpoint confirms that exact saved
request expired or was superseded without acceptance under the server’s
issuance lock. The response must match the saved request ID, nullifier, and
payload hash. Local wall-clock expiry, a changed market price, or a missing
nullifier alone never clears a proof.

New request timestamps, new-quote freshness, issued-lease validity, active-key
reuse and checkout use the deployment's `GET /v2/time` clock
(`services/zkapiServerClock.mjs`), never a global `Date.now` override.
`nowMs()` is authoritative and resamples a suspect, aged or discontinuous
anchor; `authorizationNowMs()` is the strict synchronous check and fails closed
(`Infinity`) after a detected wall/monotonic discontinuity (an OS suspend or a clock change larger than the 2-second tolerance); `estimateMs()` serves only
display and settlement timers. The prover is preloaded before `request_time` is
chosen. After asynchronous verification the lease is rechecked against a fresh
sample before installation; failure keeps the exact journal and starts no
second authorization. Only 404/405 selects the legacy device clock. A
`request_time` freshness rejection asks `/expire`; only an exactly bound
server acknowledgement (`expired_unaccepted` or `superseded_unaccepted`)
clears the journal. The exact `/expire` handshake
and signed-receipt installation check the saved quote structurally only and
never query `/v2/time`; they work with a failed endpoint and any device clock. Wallet balances continue to display their
current USD value independently of a running key's frozen conversion.

## Default deployments

The packaged mainnet and Sepolia configurations use
`https://zkapi-mainnet.openanonymity.ai` and
`https://zkapi-sepolia.openanonymity.ai`. Each profile pins its native ETH vault,
signing keys, proof artifacts, and circuit hashes. Hosts may supply reviewed
explicit profiles as described above.

The runtime checks that active notes, pending deposits, leases, and unfinished
recovery state match the selected deployment. Preserve wallet state and recovery
journals with their matching configuration.
