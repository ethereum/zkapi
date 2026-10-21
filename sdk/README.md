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
  configUrl: '/zkapi/v2c/browser-config.json',
  workerUrl: '/zkapi/v2c/assets/zkapiWasmWorker.js',
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

### Exit-only mode

Initialization never waits on the operator or on the pinned RPC, because every
exit starts with it:

- The wallet configures itself from the build-pinned `trusted_deployment`. The
  operator's deployment manifest is fetched with a 20-second limit and must
  equal those pins. When it is missing, slow, untrusted or different, the
  wallet runs in exit-only mode: withdrawals work, and deposits and new chats
  fail with the codes below until the manifest matches again. Each deposit or
  chat attempt fetches the manifest once more.
- The pinned RPC's native-vault and deployment checks run in the background.
  Deposits and chats wait for them; exits do not.
- A request journal left by a closed tab is recovered after initialization,
  within 120 seconds. A withdrawal started in the same tab stops that recovery
  and any private key still being issued.
- A failed initialization is not kept: the next `init()` starts again.

`snapshot().config.service` reports the mode: `{ available, exits: true, code,
message, detail }`. Show `message` while `available` is false.

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
Unilateral escape requests the service password only when it must check a
private request this device already sent from the current note state.

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

This SDK requires `proof_setup.circuit_id: "zkapi-v2-concession-v1"` in the
deployment manifest and matching `trusted_deployment.circuit_id` in the host
config, a vault with the concession exit (`trusted_deployment.exit_concession:
1`, vault revision 3), and a `trusted_deployment.setup_id` equal to the setup
the bundled WebAssembly is built for (`browser_setup_id()`, also
`setupId` in `sdk/assets/manifest.json`). The vault's immutable verifier,
proving keys, and signing-key pins must match this circuit. Configuration
mismatches are rejected before funding; a profile with
`deployment_status: "not_deployed"` is a placeholder and is refused with
`deployment_not_deployed`. Notes in a `zkapi-v2-note-bound-v1` vault exit
through the legacy build of this SDK, served at its own path
([Two builds on one origin](#two-builds-on-one-origin)).

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
`client.withdraw(mode, onStatus, { destination })`. [Exits](#exits) describes
`mode` and the `concede` option. The destination must be a nonzero Ethereum
address, distinct from the configured vault. An escape's destination cannot
change after initiation. Finalization pushes the payout with at most 100,000
gas. A destination that rejects it or needs more gas is only credited in the
vault (`escapePayoutCredits`, `EscapePayoutDeferred`) until someone calls
`claimEscapePayout(destination)`. The SDK then reports that escape as
credited, not returned, and offers the claim (see
[Credited escape payouts](#credited-escape-payouts)). Steer users to a
destination that accepts a plain ETH transfer within 100,000 gas, such as an
ordinary account. `client.checkEscapeDestination(destination)` simulates the
vault's push to it. The host must confirm the intended address
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

A sponsored withdrawal (`fees: 'payout'`, [Paying the fee from the
payout](#paying-the-fee-from-the-payout)) never calls `eth_sendTransaction`,
so `zkapiRecovery`, `acknowledgeTransaction` and the hooks below are not
involved: the provider receives only `personal_sign` requests, each for the
32 raw bytes of a user operation hash (an EIP-191 signature from the
connected account, which must be the owner of the plan's transit account),
and the SDK's own journal owns the resumption. A manual signer shows the
hash, signs it with the owner key and returns the 65-byte signature. The
wallet-paid fallbacks of that section (`selfBundle`, `fees: 'wallet'`,
`sweepTransit`, `claimGaslessCredit`) go through the ordinary
`eth_sendTransaction` path described here.

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
  outDir: 'dist/zkapi/v2c',
  publicPath: '/zkapi/v2c/', // the default
  network: 'sepolia', // or 'mainnet'
  build
});
```

The helper emits `browser-config.json`, `assets/zkapiWasmWorker.js`,
`wasm/zkapi_browser_bg.wasm`, `proofs/request.pk`, `proofs/withdrawal.pk`,
`proofs/request.vk`, and `sdk-assets.json` (schema 2: `circuitId`, `setupId`,
`sourceRevision`, `publicPath` and the emitted hashes). It verifies all source
artifact hashes, the WebAssembly's own circuit and setup, and the profile's
proving- and verifying-key pins before writing anything. It refuses a
placeholder profile (`deployment_not_deployed`), a profile of another circuit
(`incompatible_proof_circuit`) or setup (`setup_mismatch`), and a profile
without `exit_concession: 1` (`exit_concession_required`). A single-party
(`dev`) bundle builds for any network whose profile pins `dev`, mainnet
included: such a vault was deployed with `ALLOW_DEV_SETUP=1` and trusts its
setup's generator not to forge proofs. Both shipped profiles are
`not_deployed` placeholders until their vaults exist.
The default `publicPath` is `/zkapi/v2c/`: proving keys are fetched with
`cache: 'force-cache'`, so new keys need URLs the legacy build never used.
The host supplies its esbuild implementation, controls its CSP/rewrites, and
hashes these emitted assets in its deployment manifest. Proof downloads are
verified again inside the worker; every key download must carry its SHA-256
pin. No private credentials are required to build either network.

### Building and checking the WebAssembly

Maintainers build the bundle with `scripts/build-browser-client.sh --setup
dev|mpc-1`. `mpc-1` is the production bundle, which loads only the ceremony
keys pinned in `zkapi-proof`; `dev` loads only the development keys of
`protocol/setup/v2-concession-dev` (CI, tests and the drill vault). The script
copies the setup's `request.pk`, `withdrawal.pk` and `request.vk` into
`sdk/assets/proofs/` and rewrites `sdk/assets/manifest.json` with the hashes,
the setup's VK keccak256 values and `sourceRevision`, the commit the bundle
was built from (the WebAssembly sources must be committed first). The build is
reproducible: `rust-toolchain.toml` pins rustc 1.99.0, the script requires
wasm-bindgen-cli 0.2.117, uses `Cargo.lock` as is, and remaps every absolute
build path. `npm run verify:wasm` rebuilds into a temporary directory and
fails unless every `sdk/wasm/` file matches the manifest byte for byte;
`npm run verify:assets` checks the committed hashes without Rust.

The SDK uses IndexedDB, local/session storage, Web Locks, BroadcastChannel,
revision checks, and signed receipt validation to manage wallet state. Hosting
the same SDK on a different origin does not transfer browser wallet data. A model adapter must select one of
`CHAT_SPENDING_TIER_USD` (`1`, `2`, `3`, `4.5`, `6`) without disclosing the user's
exact balance. The SDK settles/rekeys when a selected cap changes; only actual
usage is charged. No new chat starts once a note is close to its expiry
(`note_near_expiry`; see [Exits](#exits)). The balance is then withdrawn.

Run `npm run test:sdk` in this checkout. For an installed package, run
`node --test node_modules/@openanonymity/zkapi-browser-sdk/sdk/test/*.test.mjs`
from a host that provides esbuild as a development dependency. The tests use
local fixtures and do not connect a wallet or broadcast transactions.

## Transmitted requests

A proved request leaves the device when it is sent. Every request and
withdrawal at one note state shares that state's nullifier. The SDK therefore
keeps an append-only archive of transmitted requests in the existing IndexedDB
`archives` store, as records `request_journal` and `request_evidence`. The
database version stays 3, so older builds keep opening it. The archive record
and the write-ahead journal are committed in one transaction before the
request is sent. A journal leaves the wallet only in the same write that
installs a verified next state or records its outcome in the archive. A server
error string alone never discards it.

A `stale_root` reply is first checked against the pinned vault RPC: the same
request is retried while the vault still has the proof's root. Only then is
the server's own nullifier record consulted. An archived request keeps its
full journal, including the private rerandomization, while its note state is
current, so a receipt the server finalizes later still installs. A record is
resolved only when the next state is installed or the note closes. Resolved
records are compacted (no proof, payload or rerandomization) and pruned to the
newest 256 per deployment. No host action is needed. In-flight journals from
older builds migrate on the first read.

Each note state is bounded:

- At most 16 of its unresolved requests count toward a per-state cap.
- Past the cap, the oldest discarded requests are evicted, if their nullifier
  read `unknown` or `clearance_reserved` at least 20 minutes after their
  request time.
- Eviction only takes a record out of the cap. An `evicted` record keeps its
  journal, still keeps its state unresolved for the exit rules below, and
  still installs a later receipt.
- A state keeps at most 64 unresolved records, evicted ones included. Beyond
  that, a new chat fails with `request_archive_limit` before proving, and
  nothing is evicted or discarded.

At that ceiling, chats at the state resume only if the server settles one of
its requests: the receipt still installs and resolves every record there. A
request the server never accepted never settles (for example, a quote that
expired before acceptance). Waiting does not help, so the balance has to be
withdrawn. An escape from that state concedes at most that state's request
bound ([Exits](#exits)). Reaching the ceiling takes at least 64 failed chats at
one state, spread over at least an hour.

Each record keeps its newest eight server observations. Of its older ones it
keeps at most one: the newest that is a receipt claim or a reading that ends
one (both below). Trimming therefore never changes whether a claim stands.

"Newest" and "after" mean save order, never the device clock. The store stamps
every observation it saves with a sequence number (`seq`) inside its write
transaction, above every one already saved. A clock that ran fast or stepped
back therefore cannot make an older reading outrank one saved after it. Each
observation's `at` is the device time of its save, and it only decides
eviction (above). Observations saved by an older build have no `seq`. They
order before every stamped one, by `at` among themselves. An older build open
in another tab drops the stamps of each record it writes.

`GET /v2/nullifiers/{nullifier}` reads the state's nullifier as one of:

- `unknown`, `reserved`, `finalized` or `clearance_reserved`;
- `exit_deferred` or `exited_unsigned`: an exit consumed the reserved
  nullifier on chain, and the server signs a successor only if that exit is
  defeated.

`unavailable` records a failed read. A `finalized` reading that carried a
receipt is marked `receipt`, and it names the receipt's `client_request_id`
when it has one. A receipt that `GET /v2/requests/{id}` returns and this
browser cannot apply is saved as such a `finalized` observation too.

A receipt that installs resolves every record at its state. Such an
observation at the current state is therefore a receipt claim: the server says
the nullifier was finalized with a receipt this browser could not apply. The
claim stands until a reading saved after it reports the nullifier `unknown` or
`clearance_reserved`, also when that reading was saved with another request at
the same state. A failed read, `reserved`, or `finalized` without a receipt
leaves it standing.

`unaccepted` records that `POST /v2/openrouter/leases/{id}/expire` answered
`expired_unaccepted` or `superseded_unaccepted` for that one request. That
answer only echoes identifiers the wallet sent, so it is never treated as a
nullifier reading. It never makes a record evictable and never corroborates a
discard. The exit rules decide on fresh readings, so a saved observation never
allows a withdrawal by itself.

Two dispositions end a request without installing its successor:

- `invalid_successor`: the server returned a signed successor at the state
  that fails this wallet's checks (nullifier, payload hash, next anchor or
  signature). It is terminal. The state stays where it is, and no new chat
  starts from it (`invalid_successor`). Only an exit remains, conceding at most
  `min(reported charge, bound_at_state)`.
- `late_successor`: a verified successor that arrived after an exit proof at
  its state was released. It is held, with its journal, until the exit lock is
  released (below), and then installs. For exit decisions it is settled
  (terminal, design §6.4): it never makes its state unresolved.

## Exits

This SDK runs only against a concession vault. The build-pinned
`trusted_deployment` must declare:

- `vault_revision: 3`;
- `exit_concession: 1`;
- `clearance_ownership_proof: "required"`: the server takes an ownership
  proof with every mutual-close clearance.

Initialization refuses any other profile. An escape names the note's current
state and its successor state. It concedes an amount `c` of at most
`bound_at_state`, the budget of the requests sent from that state, and the
vault pays `B − c`. While the escape is pending, the operator can:

- raise the concession, up to that bound, by proving a request it settled at
  the state (`EscapeConcessionRaised`);
- defeat the escape, but only with a request at the successor state. That
  proves a newer device holds the note.

Two optional keys tune the timing:

- `settlement_window_seconds` (`W`, default 21905): the server's settlement
  window.
- `unsettled_request_escape_after_seconds`: a cap on how long an unresolved
  request delays an escape.

### Request rules

- One bound per state. The first request at a state writes `bound_at_state` in
  the same transaction as its journal, and later requests there use it.
- No request at a state from which an exit or ownership proof was released
  (`exit_locked`).
- No request once `now + W + 4500` seconds passes `must_initiate_by`
  (`note_near_expiry`). `must_initiate_by` is 12 hours before the note's local
  `expiry_ts`, or before a later `effectiveExpiry` when the exit RPC and the
  pinned RPC both report one. Withdraw such a note instead.
- A settled request's successor installs only after its nullifier, payload
  hash, next anchor and server signature are checked.

### Withdrawing

`client.withdraw(mode, onStatus, { destination, concede })` takes:

- `mode`: `'mutual'` asks for a cooperative close where the rules allow one,
  and the rules may turn it into an escape. `'escape'` exits unilaterally now.
- `concede`: `'zero'` (the default) or `'bound'`. It applies only to an escape
  forced before the state's settlement time `T` (below).

Every operator call made during an exit is limited to 20 seconds. A timeout, a
5xx, a 401 or a 429 counts as unreachable, and `Retry-After` is ignored. Every
other operator call ends after 90 seconds, so no call holds the wallet lock,
and an exit queued behind it in another tab, for longer. A
recovery pass re-reads every unresolved request and the state's nullifier,
installs a verified successor, and lasts at most 120 seconds. Nothing in an
exit waits past `must_initiate_by`. The decision then depends on the state:

1. **Fresh state** (no unresolved request): a mutual close. The wallet sends a
   kind-2 ownership proof with `POST /v2/withdraw/clearance`, then submits the
   kind-1 close.
   - `nullifier_used` makes the state unresolved (2). The answer is kept with
     the exit lock and the withdrawal-only marker, so a retry, also after a
     cancel, decides the same way and sends no second ownership proof.
   - Any other refusal, or an unreachable server, escapes with `c = 0`. A
     retry after such an answer escapes too: a lock sends one ownership proof.
   - A state has at most one live ownership proof, across locks (C3): after a
     cancel, a new mutual close sends the state's live proof again; within 5
     seconds of its expiry it refuses with `ownership_proof_wait`
     (`error.data.retry_after`, seconds); once it expired a new one is made.
   - `withdraw('escape')`, or a fresh state within an hour of
     `must_initiate_by`, also escapes with `c = 0`.
2. **Unresolved state**: take the newest unresolved request, with `created`
   its creation time. Then `T = min(min(settlement_deadline, created + W) +
   900, created + unsettled_request_escape_after_seconds, must_initiate_by)`.
   - Before `T`, `withdraw('mutual')` refuses with `request_settlement_pending`
     and `error.data.escape_at` (milliseconds).
   - Before `T`, `withdraw('escape')` escapes with `c = 0`, or with
     `c = bound_at_state` when called with `concede: 'bound'`.
   - At or after `T`, an escape concedes `bound_at_state`.
3. **Lost response**: the server finalized a request at the state with a
   signed response this browser cannot install although it passes S1, S2,
   S4 and S6 (`receipt_unrecoverable`, or `invalid_successor` for an
   overcharge, S3). The escape then concedes `min(charge, bound_at_state)` at
   once. A successor refused for its anchor (S4) is handled like a withheld
   one (2).

Before proving an escape, the wallet does the following:

1. It takes the Merkle path from the first source that works:
   - the deposit, saved at deposit time and checked against the
     `NoteDeposited` root, which the vault accepts for good;
   - the indexer, checked against the vault's current root;
   - a rebuild from the vault's logs, in adaptively sized chunks with every
     event's root checked. Ranges halve on an RPC limit and double again after
     four accepted ranges. The whole rebuild ends within 5 minutes
     (`tree_rebuild_timeout`).

   An escape's `withdraw` result names the source it used: `pathSource` is
   `deposit`, `indexer` or `rebuild`.

   The vault's root and logs are read through the user's exit RPC
   (`client.setExitRpcUrl(url)`, saved for this origin; `null` clears it)
   when one is set. Its first answer in each exit is `eth_chainId`: an exit
   RPC on another chain than the vault's is never read further, and the
   snapshot flags it (`exit_rpc_wrong_chain`). When no exit RPC is set, or
   it is on another chain or fails, they are read through the wallet
   provider, when it is on the vault's chain (each call bounded by the
   20-second call limit), and then through the pinned RPC.

   After the wallet's simulation refuses a proof's root (`unknown_root`), the
   proof is made again from the indexer or the rebuild, at any root except
   the refused one. If neither gives a path, the existing proof is submitted
   anyway, as for any other simulation refusal.
2. It asks the server for a request proof at the successor state
   (`GET /v2/nullifiers/{successor}/evidence`). A proof that verifies locally
   refuses the escape with `device_not_newest`: another device is newer. Any
   other answer, or none, is ignored.
3. It runs a last recovery pass. Advisory warnings never block the escape,
   for example when the RPC reports either nullifier as already challenged.
4. It records the proof in the exit lock before the proof is broadcast.
5. Just before the wallet sees the transaction, it runs one more recovery
   pass. A successor that arrives now is kept as `late_successor`.

The wallet provider's simulation (`eth_estimateGas`) of an escape or a close
only warns. When it refuses, the exit RPC's estimate is used if one is set
and on the vault's chain, otherwise a fixed limit of 1,000,000 gas, and the status message explains the
refusal; the wallet still asks the user to confirm. A refusal that a new proof
can cure (`proof_expired`, `unknown_root`) re-proves once first.

The **exit lock** starts with the first exit decision at a state and freezes
that state:

- No request proofs are made there. Only proofs of the lock's mode at the
  lock's state are allowed (`exit_lock_mode`, `exit_lock_state`).
- A prepared or cancelled exit keeps the lock until every kind-0 and kind-1
  proof it released is past its `valid_until` plus 900 seconds, both on this
  device's clock and at a finalized block, and none landed. Only then can
  chats resume, and a held `late_successor` installs. The note's status and
  the finalized block are read from the first of these that answers: the
  exit RPC when one is set and on the vault's chain; the wallet provider,
  during a withdrawal or a cancel, when it is on the vault's chain; the
  pinned RPC. A `Closed` reading releases the lock earlier only when it comes
  from the exit RPC. The wallet provider is read before the pinned RPC, so a
  pinned RPC that fails or misreports cannot keep a dead lock on its own.
- Every withdrawal first releases a lock whose proofs are all dead. A held
  `late_successor` then installs, and the decision starts again at the
  newest state, so an escape that never landed does not force another escape
  from the old state.
- When such a lock cannot be released yet while a `late_successor` waits
  (no RPC answered, the note reads as pending, or finality lags this
  device's clock), a withdrawal refuses with `exit_release_pending` instead
  of exiting from the older state, whose escape the operator could raise up
  to its last request's budget. `error.data` has `reason`, `status_source`,
  `releasable_after` and `must_initiate_by` (seconds). From
  `must_initiate_by` on, the exit goes ahead from the older state, conceding
  nothing: an honest operator raises it only to the held successor's charge.
- Escape and close proofs are valid for 3 hours. Ownership proofs are valid
  for 55 minutes: the server accepts at most an hour, and the margin absorbs a
  client clock up to five minutes fast. The SDK proves again after
  `proof_expired` or `unknown_root`.

#### Paying the fee from the payout

On a deployment whose profile pins the gasless contracts (`trusted_deployment.
gasless`: the canonical ERC-4337 EntryPoint v0.7.0, the withdrawal paymaster,
its account factory and the transit account creation code; `null` on the
shipped placeholders), a withdrawal can pay its network fee out of the payout
instead of from the connected account, so the payout address needs no ETH:

```js
await client.withdraw(mode, onStatus, {
  destination,            // the payout address Y; default: the connected account
  fees: 'payout',         // 'wallet' (the default) is today's path, unchanged
  feeCapWei: null,        // refuse a paymaster flat fee above this (wei)
  bundlerUrl: null,       // this call's bundler; default: setBundlerUrl, then the profile's
  allowExpensiveGas: false,
  selfBundle: false       // a funded wallet sends handleOps itself (see fallbacks)
});
```

The proof then names a transit account `S` as its destination: the CREATE2
address, from the pinned creation code, of (EntryPoint, vault, paymaster,
owner = the connected account, payee = `destination`). `S` has no storage and
no keys: it only forwards what it receives to the paymaster, which keeps a
measured gas charge and pushes the rest to the payee, so nobody can redirect
the payout. The vault call runs inside a user operation sent from `S`; the
connected account signs the operation's 32-byte hash with `personal_sign`
(an EIP-191 signature, the only wallet request this path makes) and never
sends a transaction. The SDK derives `S` locally and cross-checks it with
`factory.getAddress`; a mismatch is `gasless_unavailable`
(`error.data.reason: "gasless_deployment_mismatch"`), which disables only
this path, never deposits or wallet-paid exits.

Privacy: the connected account becomes the on-chain owner of `S` (it appears
in the account's creation data) and, by default, the payout address. A fresh
account, which needs no ETH, breaks the link to any funding history. The
reads of this path (the account's code and nonce, the paymaster's policy, the
dry run, the logs, the bundle receipt) go to the exit RPC when one is set and
on the vault's chain, then to the pinned RPC, never to the wallet provider,
so `S` and `Y` do not reach the wallet vendor; a host that wants the wallet
provider read as a last resort sets `client.gaslessReadsViaWallet = true`.
The bundler is not covered by that: `eth_sendUserOperation` and the
follow-up calls go straight from the browser to it (neither the read RPC
ladder nor the `transport` given to `configureBrowserSdk` carries them), and
by default it is the operator's (`gasless.bundler_url`). It sees the
operation before inclusion, with the note and its proof, the transit account
`S`, the owner and the payout address `Y` (in the account's creation data),
together with the browser's IP address and timing; for an escape it learns of
the exit before the chain does. On the wallet-paid path the vault call goes through the
wallet's RPC instead. For unlinkability from the operator, use a bundler the
user chooses (`client.setBundlerUrl(url)`, or a host transport through
`provider.zkapiBundler`). The status before signing and the quote's
`privacy` field say so too.

Before signing, `onStatus` shows the only statement the SDK can make: the
payout address receives at least `payout − maxCost − flatFee − owed`, where
`maxCost` is the sum of the operation's five gas fields (from the profile's
pinned policy, never from a bundler estimate, each within the paymaster's
floor and cap; `preVerificationGas` is the rule zkapi-clientd shares,
`clamp(max(A, ceil(1.1 × B), C), pvg_floor, pvg_cap)` on the operation as
built: A is ERC-7562 LIM-070's minimum at its worst, the calldata cost of
`handleOps` with a 65-byte signature and both fee fields at `2^128 − 1`, plus
50,000 and a 2,000 margin; B the standard bundler minimum, `21,000 + 18,300 +
4 per word + 4 / 16 per zero / non-zero byte` of the encoded operation; C
`21,000 + 16 × handleOps bytes + 10,000`; and a bundler estimate that asks for
more within the paymaster's cap is adopted before the prompt) times
`maxFeePerGas` (`min(2 × baseFee + tip, the paymaster's max-fee ceiling)`,
the tip itself capped by the paymaster's tip ceiling; refused with
`gas_above_paymaster_ceiling` only when `baseFee + tip` is above the max-fee
ceiling, the rule zkapi-clientd shares), `flatFee` the paymaster's flat fee (signed into the operation as
the cap the user accepted) and `owed` what `S` still owes from an earlier
sponsored escape. An escape initiation has no such floor: nothing is paid
when it starts, and its finalization is charged at its own fees when it is
sent (possibly days later), so before an escape is signed the status names
only the most this start can add to the debt (`initiationDebtMax = maxCost +
flatFee`) and an estimate at current fees (`amounts.estimatedReceived`, with
`amounts.minimumReceived` null); the floor is stated when the finalization
is signed. The payload `onStatus(message, { amounts })` carries them
as decimal wei strings. After settlement the statuses and the result carry
`amounts.chargedWei` (the measured charge), `owedPaidWei`, `paidOutWei` and
`receivedWei`, read from the paymaster's `Settled` event in the bundle
receipt. Every number is cross-checked against the paymaster's `quote`
(`gasless_policy_mismatch` otherwise). A payout below the fee is refused
(`payout_below_gas`); a fee above 25% of the payout (the profile's
`uneconomic_fraction_percent`) is refused with `gasless_uneconomic` unless
the host passes `allowExpensiveGas: true`. The rule is
`(maxCost + flatFee) × 100 / payout > uneconomic_fraction_percent`. With the
committed policy's default limits (about 1.5–1.8 million gas in all, more
with the account's creation), `maxCost` is those limits times `maxFeePerGas`,
and the default `maxSponsoredCost` of 0.05 ETH refuses every operation above
a `maxFeePerGas` of about 28 gwei (a base fee of about 13 gwei) with
`max_cost_above_policy`, whatever the payout (docs/deployment.md, fee
bounds). Within that bound, at a 10 gwei base fee and a 1 gwei tip
(`maxFeePerGas` 21 gwei), a close that creates `S` has a `maxCost` of about
0.035 ETH, so payouts under about 0.14 ETH (more with a flat fee) keep the
wallet path by default; the exact threshold for the current fees comes from
the quote below. `client.gaslessWithdrawalQuote(mode, { destination, feeCapWei,
allowExpensiveGas })` returns these numbers (`available`, `reason`,
`transitAccount`, `amounts`, `fees`, `gas`, `minimumReceivedWei`, which is
null for an escape, and `estimatedReceivedWei`, set only for one) without
proving or prompting, and `client.gaslessAvailability({ mode, destination })`
runs the pre-flight alone: the deployment check, the bundler (`eth_chainId`
when served, then `eth_supportedEntryPoints`), the paymaster's policy and
gas policy, the fees within its ceilings (`gas_above_paymaster_ceiling`), the
prefund of a draft operation of this kind against the policy
(`max_cost_above_policy`) and against the float (`paymaster_underfunded`),
the vault's pause and the attempts left for this state. Every one of these
refusals comes before a proof is requested, because the proof binds the
transit account; the same pre-flight runs inside `withdraw` and
`finalizeEscape`, and the snapshot's `gasless.max_cost_wei` carries the
prefund it priced.

The bundler: `client.setBundlerUrl(url)` saves the user's own (per origin,
HTTPS or loopback HTTP without credentials, `bundler_url_invalid` otherwise;
`null` clears it) and `client.getBundlerUrl()` reads it; without one the
profile's `gasless.bundler_url` (the operator's, which whitelists the
paymaster) is used; `provider.zkapiBundler` with `sendUserOperation`,
`getUserOperationReceipt`, `getUserOperationByHash` and
`estimateUserOperationGas` lets a host supply its own transport. The
operation is dry-run through the EntryPoint (`eth_call handleOps`) before
any prompt and again after signing, journaled in full before
`eth_sendUserOperation`, then followed by the bundler's receipt and by the
EntryPoint's `UserOperationEvent` logs. The tip is the bundler's own
suggestion when it offers one (`rundler_maxPriorityFeePerGas`, the standard
tier of `pimlico_getUserOperationGasPrice`, or a host transport's
`maxPriorityFeePerGas()`), else the read RPC's, always within the paymaster's
tip ceiling. A bundler that forgets the operation is replaced by the logs;
after five minutes unknown the identical bytes are sent again; a bundler that
refuses a send for its fee (on the first send as on a re-send; decided by
the refusal's wording, never for an `AA..` code nor ERC-7769's `-32507`
signature or `-32508` paymaster-balance refusals) gets the
operation signed again with both fee fields raised by 12.5% within the
ceilings (one more signature per raise, every hash journaled), and
`gasless_fee_bump_exhausted` once no raise of at least 10% fits under them;
the submission stops 60 seconds before the proof's `valid_until` and proves
again, but only once the operation already sent is included (which settles
the withdrawal), unknown to the bundler, or past `valid_until` on chain, and
the next run looks for the released hashes and nonce on chain before it
builds a replacement; a replacement of an operation already sent (a fee
raise, a rebuild) that cannot be prepared (its nonce moved, a dry run
refused it, or its prompt was canceled) first looks for the earlier
operation on chain, which then settles the withdrawal, and is otherwise
refused as sent (`error.userOpSent`, `withdrawalNeedsAction`, the earlier
operation still journaled); an inclusion the bundler names under its own
hash (`bundler_hash_mismatch`) is settled under the hash the EntryPoint
emitted for the account's operation; before every prompt the latest block's timestamp is checked against
the paymaster's time window, because the unsigned dry run's `AA24` masks
`AA32` (a close or escape stops with `gasless_op_expired` once the chain is
past `valid_until − 60 s`, and a finalization waits for a block at the
escape deadline; a close or escape whose signed dry run answers `AA32`
because the chain passed `valid_until` while the prompt was open is proved
again the same way, nothing having been sent); the inclusion search of a plan starts at the earliest block any of its
operations, released ones included, was tracked from. A reload resumes from the journal without a new signature,
and looks before it sends: the EntryPoint's logs for every hash the plan ever
sent (`userOpHashes` and the `staleUserOpHashes` of operations released
earlier), then the account's nonce (moved past the journaled one, the
inclusion is found by sender and nonce), and only then the identical bytes
again. A bundler that answers a send with `AA25`/`AA10` is checked against the
read RPC: an unmoved nonce or a still-absent account makes the refusal the
bundler's (`bundler_rejected` with `error.data.aa`), never a second prompt,
and a rebuild for a nonce or account that did move is attempted at most twice.
A journaled operation belongs to the client following it: another client of
the same runtime, or another tab within five minutes of the claim's last
sign of life (its claim, its last send, or the heartbeat the following
client writes on every poll while the operation is pending:
`userOpFollowedAt` on the plan, `finalizeUserOpFollowedAt` on a record), is
refused with `withdrawal_wallet_pending` (409, a `BrowserWalletHttpError`,
for `withdraw` and `finalizeEscape` alike), as on the wallet path, however
long the operation stays pending; a claim no one follows any more (the tab
gave up, crashed or reloaded, so its heartbeat stopped five minutes ago) is
taken over without a prompt. `finalizeEscape` resumes a journaled sponsored finalization
the same way, and looks for its own operation on chain first: a finalization
included while no one followed it settles as the record's own (its `Settled`
amounts), never as a third party's.
The background passes (`syncWithdrawal`, `syncEscapeWithdrawals`) settle a
sponsored record only from the paymaster's `Settled`/`PayoutCredited` in its
bundle receipt: a credited payout stays `paymasterCredited` until
`claimGaslessCredit` delivers it, and a sponsored escape a third party
finalized is reported with `fundsWaitingInTransit`/`transitBalanceWei` until
`finalizeEscape` (now a FORWARD), `collectTransitBalance` or `sweepTransit`
collects it.

Fallbacks keep the proof (it is bound to `S`): `bundler_unavailable` names
them in `error.data.fallbacks`. With `selfBundle: true` a funded connected
account sends `handleOps([op], beneficiary = itself)` through the ordinary
transaction path (the paymaster still pays and refunds the beneficiary).
`withdraw(mode, onStatus, { fees: 'wallet' })` on the prepared plan sends the
vault call from the wallet to `S` as today (its `destination` may be omitted,
or name the payout address `Y` of the sponsored attempt, or `S`; any other
address is refused as a different destination); the payout then waits in `S`
(`fundsWaitingInTransit: true` on the record) until
`client.sweepTransit(recordId, onStatus)` sends `factory.createAccount` (when
`S` has no code yet) and `S.sweep()`, two wallet-paid transactions by any
ETH-holding account; the paymaster deducts what `S` owes and pushes the rest.

Escapes: `withdraw('escape', …, { fees: 'payout' })` sponsors the initiation
only while the operator enables it (`escapes_disabled` otherwise, refused
before any proof). A direct escape refused this way binds no plan to `S`:
started again with `{ fees: 'wallet' }` it pays the connected account or the
destination, and its finalization is wallet-paid too (`finalizeEscape(…, {
fees: 'payout' })` refuses it with `gasless_plan_mismatch`). Only an escape
that continues a sponsored plan already proved for `S` (a sponsored mutual
request the exit rules turned into an escape, refused after its proof) is
started from the wallet to `S` with `{ fees: 'wallet' }` and can have its
finalization sponsored. An initiation pays nothing now: its charge is
recorded as `S`'s debt
(`initiationDebtWei` on the record) and deducted at finalization, together
with the finalization's own charge. `client.finalizeEscape(recordId,
onStatus, { fees })` defaults to `'payout'` for such a record, runs only
after the safety deadline, and goes straight to `collectTransitBalance` when
someone else finalized first. `client.collectTransitBalance(recordId,
onStatus)` is the sponsored forward of a balance sitting in `S` (after an
operation whose vault call reverted because the close was replayed, or an
escape a third party finalized); it needs the paymaster's own evidence
(`transit_not_stranded` otherwise: use `sweepTransit`). A payee that rejects
ETH is credited by the paymaster (`paymasterCredited: true`,
`paymasterCreditedWei` on the record; `client.paymasterCreditedPayouts` lists
them) and anyone delivers the credit with `client.claimGaslessCredit(payee,
onStatus)`, a wallet-paid transaction (its result names the `paymaster`
claimed from).

Recovery of an existing record does not depend on the current profile's
gasless pins. `sweepTransit`, `claimGaslessCredit` and `finalizeEscape(…,
{ fees: 'wallet' })` use the addresses journaled with the record (the
transit account, the factory, the paymaster, the EntryPoint, the owner and
the payee; the credit claim tries the paymasters of this browser's records
of that payee, then the pinned one), so they keep working once the operator
publishes `gasless: null` or pins another paymaster; before the sweep's
first prompt the journaled factory's `getAddress(owner, payee)` must name
the journaled `S` through the read RPC (`gasless_unavailable` with
`reason: 'gasless_deployment_mismatch'` otherwise). A sponsored operation
for such a record (`collectTransitBalance`, a sponsored `finalizeEscape`, a
new, re-sent or re-signed operation of a sponsored close or escape) needs
the current pins to name the record's paymaster and factory, and is refused
before any prompt with `gasless_record_not_pinned` otherwise (`error.data`:
`reason` `not_pinned` or `pins_mismatch`, `transitAccount`, `paymaster`,
`factory`, `pinnedPaymaster`, `pinnedFactory`, `alternatives`: the
wallet-paid calls that apply, led by `withdraw(mode, onStatus, { fees:
'wallet' })` while a prepared close or escape initiation has not left the
vault, since sweeping or finalizing needs the exit on chain first).

An operation sent before the pins went away is not sent again, but it never
blocks the wallet-paid path for good. Its inclusion is looked for through
the journaled EntryPoint (the read RPC only, no bundler): the background
passes (`syncWithdrawal`, `syncEscapeWithdrawals`) settle a close, escape
initiation, finalization or forward that landed. One not included within
the re-send window (five minutes from its last send) is released, with its
hashes kept for a late inclusion: a close or escape initiation by the
background sync, after which `withdraw(mode, onStatus, { fees: 'wallet' })`
proceeds, and a finalization by `finalizeEscape(recordId, onStatus, { fees:
'wallet' })`, which refuses with `user_op_pending` (`error.data`:
`userOpHash`, `retryAfterMs`) during the window, resolves to `{ status:
'finalizing', recordId, sponsored: true, transactionHash, userOpHash }`
without a prompt when the finalization landed and settled (the background
sync closes the record from its settlement), and otherwise releases it
(`finalizeUserOpPhase: 'released'`) and pays from the wallet. One that
landed but reverted (its vault call failed) is released too
(`finalizeUserOpPhase: 'reverted'`, its bundle transaction in
`finalizeUserOpRevertedTransactionHash`): the wallet then pays the
finalization, or, when a third party finalized the escape first, the call
resolves to `{ status: 'closed', recordId, finalizedByThirdParty: true,
fundsWaitingInTransit, transitAccount }` with the payout waiting in `S` for
`sweepTransit`. A forward in flight never blocks `sweepTransit`.

### Setting a balance aside

`client.parkPreparedWithdrawal()` sets a withdrawal-only balance aside so the
user can fund another one. Only a mutual close whose clearance the server
granted can be set aside: `snapshot().config.prepared_withdrawal.clearance_granted`
says so. Any other withdrawal-only balance (an ownership proof answered with
`nullifier_used`, a refusal or no answer, or a released escape proof) is
refused with `park_requires_clearance`. It must be withdrawn first, by the
exit rules above, so that it never depends on the operator once set aside.

`client.withdrawBackground(recordId)` later closes a set-aside balance with its
kept clearance. The close proof takes the deposit-time path first, then the
indexer at the vault's current root, then the vault's logs, and it re-proves
at another root after `unknown_root` like any exit. Each set-aside record in
`snapshot().withdrawals` carries `expiry` and `must_initiate_by` (milliseconds,
from the note's own `expiry_ts`) and `exit_deadline_near`, which is true within
7 days of `must_initiate_by`. Show it: a set-aside close that is not finished
before expiry is claimed by the treasury.

### Raised concessions and the payout

While an escape is pending, the operator may raise its concession
(`EscapeConcessionRaised`), and the status message reports a raise. A
challenge with a request at the successor state defeats the escape
(`device_not_newest`); the user should restore the newest backup or exit kit.

The withdrawal record carries `stateBalance`, `concededAtInit`,
`boundAtState`, `concededCurrent` (the vault's `pendingConcessions`) and
`validUntil`. Every finalization is checked: `finalizeEscape`, the background
sync, and a finalization by a third party. The payout must equal
`stateBalance − max(concededAtInit, raises)` and be at most
`stateBalance − concededAtInit`. The record then gets `concededFinal`.

- A payout below `stateBalance − boundAtState` sets
  `payoutAlert: "concession_exceeded_bound"`. Show it: the vault's accounting
  is final.
- When the raise logs cannot be read, a payout within those bounds is
  accepted.
- A credited payout reaches `closed` through the claim
  ([Credited escape payouts](#credited-escape-payouts)).

### Exit kit

`await client.exportExitKit(passphrase)` returns a JSON string with
`format: "zkapi-exit-kit-v1"`. It holds:

- the trusted deployment pins;
- the note's current state and secret;
- `bound_at_state` and `state_seq`;
- the deposit-time Merkle path.

The kit is encrypted with AES-256-GCM under a PBKDF2-SHA256 key (600,000
iterations, 16-byte salt). The passphrase needs at least 10 characters
(`exit_kit_passphrase_weak`). Offer the kit for download after every deposit,
and whenever `snapshot().config.exit.exit_kit.out_of_date` is true. A kit of an
older state stops working once a newer state exists: a request at that older
state's successor defeats its escape.

`openExitKit(kit, passphrase)` from
`@openanonymity/zkapi-browser-sdk/exit-kit` decrypts a kit
(`exit_kit_invalid`, `exit_kit_passphrase`). The companion's `exit-kit`
subcommand exits from a kit without this host.
`configureBrowserSdk({ provingKeysBaseUrlOverride })` lets an exit fetch the
withdrawal key from another origin when the host is gone. The URL must end
with `/`, and the build-pinned SHA-256 still applies.

### Deposit checks

Before every deposit, the SDK checks the deployment against
`trusted_deployment` twice: through the wallet provider that will sign, and
through the pinned RPC. It checks:

- the `keccak256` of the vault's, adapter's and Poseidon library's code
  (`vault_runtime_codehash`, `adapter_runtime_codehash`,
  `poseidon_runtime_codehash`);
- the vault's `proofAdapter()`;
- the signing keys;
- `challengePeriod`, `noteTtl` and `maxPauseDuration`;
- `CONCESSION_ESCAPE_VERSION` (1) and `ROOT_HISTORY_WINDOW` (86400);
- the adapter's `CIRCUIT_ID_HASH` and verifying-key hashes.

A mismatch refuses the deposit with `deployment_mismatch`, and
`error.data.mismatches` lists each `{ field, expected, actual, source }`. A
profile without these pins refuses deposits too (`deployment_unverifiable`).
Exits never depend on this check.

During a launch period, `trusted_deployment.canary` (`per_note_max_wei`,
`aggregate_max_wei`, `until`) caps deposits. A deposit over a cap fails with
`canary_cap_exceeded`, or with `canary_cap_unverified` when the vault balance
cannot be read.

### Snapshot and error codes

`snapshot().config` adds:

- `service` ([Exit-only mode](#exit-only-mode));
- `vault_revision` (3);
- `exit`, with times in milliseconds:
  - `must_initiate_by`, `near_expiry`, `bound_at_state`, `state_fresh`,
    `escape_at` and `device_not_newest`;
  - `lock` (`mode`, `since`, `released`, `exit_proofs_released`,
    `releasable_after`);
  - `exit_kit` (`state_seq`, `exported_seq`, `out_of_date`);
  - `exit_cost_warning`: `{ floor, cost, gas_price_wei }` (gwei ledger units)
    when the payout floor `current_balance − bound_at_state` is below three
    times an escape's estimated fee (620,000 gas at the last gas price the
    wallet provider reported), else `null`. The SDK reads the gas price after
    each deposit and at the start of each withdrawal, and both flows report
    the warning in a status message. It never blocks anything: the read ends
    within the 20-second call limit, a deposit waits for it at most that
    long, and a withdrawal does not wait for it at all (the warning appears
    when the read completes);
  - `deposit_path_saved`, `exit_rpc_url`, `exit_rpc_wrong_chain` and
    `exit_rpc_recommended`. `exit_rpc_wrong_chain` is true once the saved
    exit RPC answered on another chain than the vault's; exits then ignore
    it, so ask the user to correct it. `exit_rpc_recommended` is true when
    no deposit-time path is saved and no exit RPC is set: an escape's path
    would then come from the operator's indexer or the pinned RPC's logs, so
    ask the user to set an exit RPC or keep an exit kit from the depositing
    device;
- `unresolved_requests`, one entry per request at the selected state, with no
  proofs: `client_request_id`, `kind`, `disposition`, `class` (`terminal`,
  `resolved_unreserved`, `unresolved`), `created_at`, `server_status`,
  `server_status_at` and `escape_at`;
- `last_settlement` (`client_request_id`, `charge_applied`, `charge_basis`,
  `settlement_reason`, `installed_at`);
- `gasless` ([Paying the fee from the payout](#paying-the-fee-from-the-payout)):
  `supported` (the profile pins the gasless contracts), `bundler_url` (the
  effective one), `bundler_wrong_chain`, and from the last pre-flight
  `paymaster_deposit_wei`, `policy` (`max_sponsored_cost_wei`, `flat_fee_wei`,
  `min_escape_net_wei`, `escapes_enabled`, `sponsorship_paused`,
  `max_fee_ceiling_wei`, `priority_fee_ceiling_wei`), `attempts_left`,
  `max_cost_wei` (the prefund the pre-flight priced), `available` and
  `reason`;
- `prepared_withdrawal` gains `fee_payer` (`"wallet"` or `"payout"`),
  `payout` (Y; `destination` stays the transit account S for a sponsored
  plan), `transit` (`factory`, `paymaster`, `entryPoint`, `account`,
  `owner`, `payee`, `creationCodeKeccak`), `user_op_hash` and
  `user_op_phase` (`op_built` before the first `eth_sendUserOperation`,
  `op_submitted` after).

A sponsored withdrawal record (`snapshot().withdrawals[]`) carries
`feePayer`, `payout`, `transit`, `userOpHash`, `userOpHashes`,
`userOpSuccess`, `chargedWei`, `owedPaidWei`, `receivedWei`, `paidOutWei`,
`initiationDebtWei`, `fundsWaitingInTransit`, `transitBalanceWei`,
`paymasterCredited`, `paymasterCreditedWei`, `finalizeUserOpHash`,
`forwardUserOpHash`, `sweepTransactionHash`, `transitCreateTransactionHash`
and `creditClaimTransactionHash` (wei as decimal strings).

Receipts are installed against the proof-bound billing quote, never
re-validated against changed manifest price pins. A worst-case charge equal
to the proven bound is valid.

Each of these errors carries a `shortMessage` for display.

| Group | Codes |
| --- | --- |
| Wallet | `request_settlement_pending`, `device_not_newest`, `exit_locked`, `exit_lock_mode`, `exit_lock_state`, `exit_release_pending`, `note_near_expiry`, `invalid_successor`, `receipt_unrecoverable`, `receipt_response_missing`, `receipt_pending_install`, `request_archive_limit`, `withdrawal_submission_pending`, `park_requires_clearance` |
| Deposits | `deployment_mismatch`, `deployment_unverifiable`, `canary_cap_exceeded`, `canary_cap_unverified` |
| Exit-only mode (deposits and chats) | `deployment_manifest_unavailable`, `deployment_manifest_mismatch`, `deployment_manifest_untrusted`, `incompatible_proof_circuit`, `native_vault_unverified` |
| Vault reverts | `unknown_root`, `challenged_nullifier`, `superseded_state`, `proof_expired`, `wrong_withdrawal_kind`, `invalid_destination`, `vault_paused` |
| Exit kit | `exit_kit_invalid`, `exit_kit_passphrase`, `exit_kit_passphrase_weak` |
| Tree rebuild | `tree_logs_unavailable`, `tree_note_missing`, `tree_rebuild_timeout`, `tree_root_refused`, `wrong_network` (each with `error.data.exit_path_unavailable`) |
| Exit RPC | `exit_rpc_invalid`, `exit_rpc_unsaved` |
| Sponsored withdrawals (refused before any prompt) | `gasless_unavailable` (`error.data.reason`: `not_pinned`, `gasless_profile_invalid`, `gasless_deployment_mismatch`), `gasless_policy_mismatch`, `bundler_unavailable` (`error.data.fallbacks`), `bundler_wrong_chain`, `bundler_unsupported_entry_point`, `bundler_url_invalid`, `bundler_url_unsaved`, `sponsorship_paused`, `escapes_disabled`, `escape_already_sponsored`, `paymaster_underfunded`, `exits_paused` (`error.data.reopenAt`), `gas_above_paymaster_ceiling` (`error.data`, wei as bigints: `baseFeePerGas`, `maxPriorityFeePerGas`, `neededMaxFeePerGas` = base + tip, the amount compared with the ceiling, `wantedMaxFeePerGas` = 2 × base + tip, `maxFeeCeiling`), `max_cost_above_policy`, `payout_below_gas`, `gasless_uneconomic`, `gasless_attempts_exhausted`, `gasless_fee_above_cap`, `gasless_estimate_above_cap`, `gas_limit_out_of_range` (a gas field outside the paymaster's policy; `error.data`: `name`, `value`, `floor`, `cap`), `gasless_plan_mismatch`, `gasless_record_not_pinned` (`error.data.reason`: `not_pinned`, `pins_mismatch`; recover with `withdraw(mode, …, { fees: 'wallet' })` while the note has not left the vault, then with `sweepTransit`, `claimGaslessCredit` or `finalizeEscape(…, { fees: 'wallet' })`, as `error.data.alternatives` lists them), `wrong_owner_account` (`error.data.expected`), `entry_point_hash_mismatch` |
| Sponsored withdrawals (after a submission) | `signature_rejected` (also a bundler's ERC-7769 `-32507`), `paymaster_underfunded` (also a bundler's `-32508`: the float cannot cover every pending operation; neither code is re-signed), `escape_not_due` (a sponsored finalization the latest block has not reached the deadline for within three minutes; `error.data.validAfter`, `blockTimestamp`), `bundler_hash_mismatch` (a status, the chain decides), `bundler_rejected` (the bundler refused the send with AA25 or AA10 although the chain disagrees; `error.data`: `method`, `aa`, `rpcCode`, `rpcMessage`), `gasless_op_expired` (proved again), `gasless_op_pending` (journaled, checked in the background), `user_op_pending` (`finalizeEscape(…, { fees: 'wallet' })` while a sponsored finalization sent before the profile stopped pinning its paymaster may still land; `error.data.userOpHash`, `retryAfterMs`), `gasless_fee_bump_exhausted`, `gasless_op_reverted` (`error.data.reason`, the vault error; the record may hold `fundsWaitingInTransit`), `transit_funds_waiting` (a forward is sponsored), `transit_sweep_needed` (a status after a wallet-paid exit to `S`, which leaves the paymaster no evidence: only `sweepTransit` collects it), `transit_not_stranded`, `transit_balance_empty`; the EntryPoint's `AA..` reasons map to `sender_already_constructed` and `nonce_rejected` (handled silently), `signature_rejected`, `paymaster_underfunded`, `paymaster_time_window`, `paymaster_rejected` and the paymaster's own errors above |

## Credited escape payouts

`finalizeEscapeWithdrawal` closes the note and pays the treasury even when its push to the destination fails. The balance is
then added to `escapePayoutCredits(destination)`, and the receipt carries
`EscapePayoutDeferred(noteId, destination, amount)` before
`EscapeWithdrawalFinalized`. `EscapeWithdrawalFinalized` alone therefore does
not prove that the destination was paid.

The SDK reads that receipt wherever it finalizes an escape (`finalizeEscape`,
and the background check of a submitted finalization). When it carries the
vault's credit log for the note and destination, the withdrawal record gets
`payoutCredited: true`, `payoutVerified: false`, `creditedAmount` (vault units)
and `payoutCreditEvidence: "receipt"`. The status message says that the escape
closed but the destination did not accept the payout, which the vault holds for
it, and `finalizeEscape` also returns `payoutCredited: true`. Show such a
withdrawal as credited, never as returned. The fields survive finality, when
the record's recovery material is removed. An escape that another device or a
third party finalized has no receipt in this browser, and a receipt can also be
unreadable for a while. The SDK then reads
`escapePayoutCredits(destination)` at the block where the note reads Closed. A
nonzero credit marks the record credited, with
`payoutCreditEvidence: "vault_credit"` and `creditedAmount: null`, because that
credit can also hold other escapes' payouts to the same address. This is the
only reading that later evidence replaces: when this browser's own
finalization receipt is read and shows the push was paid, the record becomes
`payoutCredited: false`, `payoutVerified: true`. Receipt and claim evidence is
kept: a pass that cannot read the receipt again does not undo a proven push or
credit. If the note reads open again at or after the block where it was seen
Closed, a reorganization removed that close, and the SDK resets the record's
payout, credit and claim fields. `payoutVerified: true` means that a receipt
proved the push or, together with `payoutClaimed: true`, that the credit was
delivered (below). `client.creditedEscapePayouts` lists the credited records
not yet seen delivered.

Anyone can deliver a credit, also while the vault is paused.
`await client.claimEscapePayout(recordId, onStatus)` reads
`escapePayoutCredits(destination)` and sends `claimEscapePayout(destination)`
from the connected account. That account pays only gas; the vault pays the
destination all of its credits. Only an `EscapePayoutClaimed` log for that
destination proves the delivery. A claim pays the credits the vault holds when
it executes, so the SDK marks a credited record of that destination delivered
only when the record's `closeBlockNumber` (its finalization block, or a later
block where the note was first seen Closed) is lower than the claim's block. It
sets `payoutClaimed: true`, `payoutVerified: true`,
`payoutClaimEvidence: "claim_receipt"`, `payoutClaimTransactionHash`,
`payoutClaimBlockNumber` and `payoutClaimedAmount` on those records, and
returns `{ status: "claimed" }`. A record credited in the claim's block or later
keeps its credit, and a later claim delivers it. Credits leave the vault only
through such a claim. So a zero credit, read at a block where the note reads
Closed, means someone else already delivered it; the records whose note reads
Closed there are then marked the same way with
`payoutClaimEvidence: "credit_cleared"` and no transaction. While the
destination still rejects ETH, the claim fails its gas estimate with
`native_transfer_failed` before the wallet is asked to sign, and the credit
stays. Claims already sent from any credited record of that destination are
checked first. While one is still pending, the call returns
`{ status: "pending" }` instead of sending another, because the pending claim
also pays this record's credit. A manual signer's claim carries
`zkapiRecovery.kind: "escape-payout-claim"`; `resumeExternalTransaction`
accepts it, and the next `claimEscapePayout` checks it.
`client.readEscapePayoutCredit(destination)` reads the credit directly.

Before proving a new escape, the SDK simulates the vault's push: a plain
transfer of one vault unit from the vault to the destination. The call gets
the payout gas: 21,000 intrinsic gas, 100,000, and the 2,300 call stipend. A
revert or another EVM halt counts as a failed transfer (for example, geth's
`out of gas` or anvil's `EVM error OutOfGas`). The escape still proceeds,
because the payout is credited, but `onStatus` shows a warning first and the
result carries `destinationWarning`. A host can run the same check before the
user confirms the address:
`client.checkEscapeDestination(destination, { finalBalance })` returns
`{ destination, accepts, warning }`. `accepts` is `null` when the RPC cannot
tell, and such an unknown result never refuses an escape.

Withdrawal records written by earlier builds have no `payoutCredited` field and
keep their meaning. SDK builds before this one report a credited escape as
returned and offer no claim.

## Moving to a newly pinned deployment

The runtime holds one selected note per origin, and it lists and acts only on
its own deployment's withdrawal records. Exit an older deployment completely
before funding a note on a newly pinned one: withdraw its selected note and
finish or finalize every one of its withdrawals. Setting a withdrawal aside is
not an exit. A set-aside mutual close, a pending or challenged escape, a close
awaiting finality and a finalization in flight all stay bound to the older
deployment: only a runtime configured with that deployment's profile can
submit, finalize or restore them. Once a note on the new deployment is funded,
the older profile refuses to load in this browser (`This browser contains a
wallet for <id>`) until that note is withdrawn, while an older note that is
active again (a set-aside mutual close, or a challenged escape on a vault that
burns the nullifier) can be claimed at its expiry.

Hosts choose the profile before configuring the SDK, from
`readBrowserWalletHoldings()` in `@openanonymity/zkapi-browser-sdk/store`. It
reads the stored wallet once and returns
`[{ deploymentId, runtime, withdrawals: [{ recordId, noteId, mode, phase }] }]`:
the runtime slot's deployment while that slot holds durable state (`runtime:
true`; a note, journal, lease, pending deposit, deposit draft, prepared
withdrawal or unfinished late attempt), and every deployment with an open
withdrawal record (any record except a finalized close with no finalization in
flight). Configure an older deployment's profile while it is listed, and offer
its withdrawals; configure the newer profile only when it is not. When several
deployments are listed, the entry with `runtime: true` comes first and is the
only one that can load until its slot is empty. `browserWalletHoldings(snapshot)`,
`browserRuntimeHoldsState(runtime)` and `isOpenBrowserWithdrawal(record)` apply
the same rules to a `readBrowserWalletSnapshot()` the host already read. A
loaded runtime also reports what it cannot reach:
`snapshot().config.other_deployment_withdrawals` lists the open withdrawal
records of other deployments (`deployment_id`, `record_id`, `note_id`, `mode`,
`phase`; no note state). A host should not offer a deposit while it is
non-empty. The one exception is an escape on an older deployment that its
operator announced as stuck because its destination rejects ETH
([migration runbook](../docs/migration-concession-vault.md#phase-e-drain-and-retire-the-legacy-vault),
Phase E, step 3): when that deployment's entry has `runtime: false` and each
of its withdrawals is such an announced escape (`mode: "escape"`, matched by
`noteId`), the host may configure the newer profile and offer deposits, and
shows the owner that note ID and how to finalize it on chain. Never clear site
data to get past these checks.

A finalized escape whose payout the vault only credited
([Credited escape payouts](#credited-escape-payouts)) holds no note. It does
not keep its deployment listed and does not block a deposit elsewhere, but the
user still has a payout to claim there. `readBrowserWalletPayoutCredits()`
lists the unclaimed credits of every deployment as
`[{ deploymentId, recordId, noteId, chainId, contractAddress, destination,
creditedAmount }]`. `browserWalletPayoutCredits(snapshot)` and
`isUnclaimedPayoutCredit(record)` apply the same rule to a snapshot the host
already read. A loaded runtime reports other deployments' credits in
`snapshot().config.other_deployment_credits` (`deployment_id`, `record_id`,
`note_id`, `chain_id`, `contract_address`, `destination`, `credited_amount`).
This SDK's claim action needs that deployment's profile, which loads while
the runtime slot holds no other deployment's state. Anyone can also call
`claimEscapePayout(destination)` on that vault directly; the SDK recognises
that delivery from the zero credit the next time that profile's claim action
runs.

### Two builds on one origin

Notes in a `zkapi-v2-note-bound-v1` vault stay with the legacy build of this
SDK. A host serves it beside this one on the same origin:

- the legacy build at its existing `publicPath` (`/zkapi/`);
- this build at `/zkapi/v2c/`.

Both share IndexedDB `zkapi-browser-wallet-v1` (version 3) and its lock.
Neither rewrites the other deployment's records, and each runtime refuses a
runtime slot that holds the other's note. The host lists two package entries,
`zkapi-sdk-legacy` (the config-only re-cut of `release/v2-note-bound`, tagged
`v0.1.<n>`, whose profiles close deposits) and `zkapi-sdk` (tagged
`v0.2.<n>`), and each resolves its own WebAssembly, keys and worker. A small
loader calls `readBrowserWalletHoldings()` and `import()`s the legacy entry
while a legacy runtime holds an open note, and this one otherwise; a legacy
withdrawal still open while the slot is empty also needs the legacy build.
One SDK runs per page, so switching builds reloads the page.
[`examples/sample-host`](../examples/sample-host) builds both and holds that
loader. The operator's side of the move is in the
[migration runbook](../docs/migration-concession-vault.md#side-by-side-browser-builds).

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
nullifier alone never clears a proof. Wallet balances continue to display their
current USD value independently of a running key's frozen conversion.

## Default deployments

The packaged mainnet and Sepolia profiles name
`https://zkapi-mainnet.openanonymity.ai` and
`https://zkapi-sepolia.openanonymity.ai`. They stay `not_deployed`
placeholders until their concession vaults exist, and `buildBrowserSdkAssets`
refuses them with `deployment_not_deployed`. A deployed profile pins:

- its native ETH vault, signing keys, proof artifacts, circuit and setup;
- `vault_revision: 3`, `exit_concession: 1` and
  `clearance_ownership_proof: "required"`;
- the deployment pins of [Deposit checks](#deposit-checks).

Hosts may supply reviewed explicit profiles as described above.

The runtime checks that active notes, pending deposits, leases, and unfinished
recovery state match the selected deployment. Preserve wallet state and recovery
journals with their matching configuration.

## Closing a deployment to deposits

`trusted_deployment.deposits` (`"open"`, the default when absent, or
`"closed"`) is the browser half of a deposit cutoff for a deployment being
drained. Like the keys above it is read only from the build-pinned profile and
validated with it; any other value fails initialization. With `"closed"`:

- `quoteDepositUsd`, `prepareDepositQuote` and `deposit` refuse to start a new
  deposit with `409 deposits_closed`, before any chain read, note secret or
  wallet prompt. `snapshot().config.deposits` is `"closed"` (otherwise
  `"open"`), so the host can hide its deposit action.
- An unused `depositQuote` draft is discarded at initialization and on a
  refused attempt. It was never signed, and it would otherwise count as this
  deployment's wallet state.
- A deposit already started is never stranded. A pending deposit, signed or
  not, stays tracked, completable and recoverable for its original amount
  (`deposit`, `prepareDepositRetry`, `retryUnknownDeposit`,
  `retryDroppedDeposit`, `recoverBrowserDeposit`); only replacing it with a
  different amount is refused. Withdrawals, chats and recovery are unaffected.

The SDK builds a deposit's Merkle path from `/v1/tree/snapshot`, which
withdrawals also need, so a gateway that stops serving the deposit-only tree
routes does not stop browser deposits. Set this flag in every browser profile
of the drained deployment, legacy-exit builds included. Builds older than this
release ignore it and keep offering deposits.
