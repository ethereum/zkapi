import walletCodec from '../wallet.js';
import { isNativeEthFunding, validateNativeFunding, assertNativeVault, validateNativeQuote, readNativeQuote, nativeUnitsForUsd, nativeUsdMicros, nativeDepositValue, parseUnits, formatUnits, NATIVE_WEI_PER_UNIT } from './zkapiNativeEth.mjs';
import { beginBrowserSdkInitialization } from '../configure.js';
import browserWalletRuntime from './browserWalletRuntime.js';
import { ENTRY_POINT_ERRORS, contractEstimateError, contractRevertSelector } from './zkapiContractError.mjs';
import { EXIT_FALLBACK_GAS_LIMIT, bufferedGasLimit } from './zkapiGas.mjs';
import { normalizeWalletError, walletErrorMessage } from './zkapiWalletError.mjs';
import { backgroundWithdrawalClaims, isUnsubmittedParkedMutualWithdrawal } from './zkapiWithdrawalRecovery.mjs';
import { deriveExpiryRecords, readFinalizedExpiryClaims } from './zkapiExpiryHistory.mjs';
import { externalRecoveryContext, sameAddress, externalTransactionNonce, assertExternalTransaction,
    hasDurableTransactionHash } from './zkapiExternalTransactions.mjs';
import { matchEscapePayout } from './zkapiExitPolicy.mjs';
import { gaslessRecordFields, isGaslessWithdrawal } from './browserWalletStore.js';
import { gaslessDeploymentError, verifyGaslessDeployment } from './zkapiDeploymentCheck.mjs';
import {
    GASLESS_MESSAGES, GASLESS_TIMING, KIND, attemptsKey, availabilityVerdict, buildUserOperation,
    bumpFees, checkEstimate, decodeAddressWord, decodeBool, decodeGasPolicy, decodePolicy, decodeQuote, decodeWord, dryRunError,
    encodeAttempts, encodeBalanceOf, encodeCallCap, encodeCredits, encodeEscapeNotePlusOne, encodeGetAddress,
    encodeGetNonce, encodeGetUserOpHash, encodeHandleOps, encodeOwed, encodeQuote, encodeStranded, gasFields, gaslessAmounts,
    gaslessError, gaslessPins as gaslessPinsOf, handleOpsCalldataBytes, journalValue, maxCostWei, nonceKeyFor, packNonce, weiString,
    parseCollected, parseCreditClaimed, parsePayoutCredited, sameGasPolicy, selectFees, settlementOf, toBigInt, emittedUserOpHash,
    transitAccountAddress, transitInitCode, unpackNonce, userOpHash, userOperationFromJson, userOperationJson,
    userOperationReceiptTransactionHash
} from './zkapiGasless.mjs';

const WITHDRAWAL_STORAGE_KEY = 'zkapi-withdrawal-v2';
// The sponsored path (design §3.2). The dry run of a user operation calls
// handleOps with a beneficiary that holds no code: eth_call needs no balance.
const GASLESS_DRY_RUN_BENEFICIARY = '0x000000000000000000000000000000000000dEaD';
// The pre-flight refusals that come before the fee selection (§3.1 (2) and
// the policy of (3)); a fee refusal outranks the float, the pause and the attempts.
const GASLESS_PREFLIGHT_BEFORE_FEES = ['bundler_unavailable', 'bundler_wrong_chain', 'bundler_unsupported_entry_point', 'sponsorship_paused',
    'escapes_disabled', 'gasless_policy_mismatch'];
// Silent EntryPoint refusals a bundler may answer a send with are rebuilt at
// most this many times (the dry run of `prepare` is bounded the same way).
const GASLESS_BUNDLER_REBUILD_LIMIT = 2;
// What the bundler learns (design: the operator-run bundler pre-discloses escapes unless the user names their own).
const GASLESS_BUNDLER_NOTE = 'The bundler (the operator’s unless you set your own) sees the operation, with its note, transit account and payout address, together with this browser’s IP address and timing before it is included; for an escape it learns of the exit before the chain does. A bundler you choose keeps that from the operator.';
const GASLESS_PRIVACY_NOTE = `The connected account becomes the on-chain owner of this withdrawal’s transit account (visible in the account’s creation data) and receives the payout. A fresh account, which needs no ETH, breaks the link to your funding history. ${GASLESS_BUNDLER_NOTE}`;
const GASLESS_PRIVACY_NOTE_SEPARATE_PAYOUT = `The connected account becomes the on-chain owner of this withdrawal’s transit account (visible in the account’s creation data); the payout goes to the address you chose. A fresh owner account, which needs no ETH, breaks the link to your funding history. ${GASLESS_BUNDLER_NOTE}`;
// The record phases claimWithdrawalFinalization accepts (browserWalletStore's claimBrowserWithdrawalFinalization).
const FINALIZATION_CLAIMABLE_PHASES = new Set(['pending', 'finalizing', 'awaiting_wallet', 'ambiguous']);
// The vault call a close or escape is priced with before its proof exists:
// 836 nonzero bytes (16 gas each in preVerificationGas, where a zero byte
// costs 4), so the quoted maxCost bounds the signed operation's.
const WORST_CASE_EXIT_CALL = `0x${'ff'.repeat(836)}`;
const GASLESS_PAYOUT_CONTRACT_WARNING = 'The payout address is a contract. It must accept ETH within 100,000 gas, or the paymaster only credits the payout for a later claim (claimGaslessCredit).';
// Ethereum's `finalized` block tag is authoritative when the wallet RPC
// supports it. A confirmation-depth fallback keeps recovery moving on older
// providers without ever blocking the user from selecting a fresh note.
const CLOSE_FINALITY_FALLBACK_BLOCKS = 64;

// One provider is retained across all nested/concurrent asynchronous client
// operations. In particular a manual signing prompt can outlive many RPCs.
const walletProviders = new WeakMap();

const {
    ABI,
    ESCAPE_PAYOUT_GAS,
    GASLESS_ABI,
    abiWord,
    addressWord,
    callData,
    decodePendingConcessions,
    decodeVaultEvent,
    encodeClaimCredit,
    encodeClaimEscapePayout,
    encodeCreateAccount,
    encodeDeposit,
    encodeEscapePayoutCredits,
    encodeFinalizeEscape,
    encodeSweep,
    encodeTransitWithdraw,
    encodeWithdrawal,
    escapePeriodBadge,
    escapePeriodLabel,
    escapePeriodPhrase,
    parseEscapePayoutClaim,
    parseNoteDeposited,
    parseWithdrawalReceipt
} = walletCodec;

// The vault (revision 2 and later) closes an escape even when its push to
// the destination fails (the destination rejects ETH or needs more than
// ESCAPE_PAYOUT_GAS): the balance is then credited to
// escapePayoutCredits(destination) and reaches it only through
// claimEscapePayout(destination), which anyone may call.
const ESCAPE_PAYOUT_CREDITED_MESSAGE = 'The escape closed, but the destination did not accept the payout. The vault holds it for that address until it is claimed; anyone can claim it for that address once it accepts ETH.';
const ESCAPE_PAYOUT_STILL_REJECTED_MESSAGE = 'The destination still does not accept ETH, so the vault keeps its payout. Try the claim again once the address can receive ETH.';
// A top-level call pays 21,000 intrinsic gas before its target runs, and the
// vault's value-bearing push adds the 2,300 call stipend. This budget gives
// the destination the same execution gas as the vault's push.
const ESCAPE_DESTINATION_CHECK_GAS = 21_000 + ESCAPE_PAYOUT_GAS + 2_300;
const ESCAPE_DESTINATION_CREDIT_WARNING = 'This address did not accept a plain ETH transfer within the vault’s 100,000-gas payout limit. An escape to it still closes, but the vault would only hold the payout for this address until someone claims it. An escape destination cannot be changed later, so prefer an ordinary account.';
const DEVICE_NOT_NEWEST_MESSAGE = 'The escape was defeated: another device spent this balance’s next state, so this device is not the newest. Restore the newest backup or exit kit.';
const CONCESSION_EXCEEDED_BOUND_MESSAGE = 'The escape paid less than this balance minus its last chat’s budget (concession_exceeded_bound). The vault’s accounting is final; report this to the operator.';

// A failed eth_call whose provider reports an EVM failure (a revert, out of
// gas or an invalid instruction), as opposed to an RPC, network or account error.
// Geth words halts ("out of gas", "invalid jump destination"); anvil reports
// them as "EVM error <HaltReason>" ("EVM error OutOfGas") with code -32603,
// and uses that prefix only for halts. Account and validation failures
// ("insufficient funds", "header not found") match neither.
const EXECUTION_FAILURE = /revert|out\s*of\s*gas|gas required exceeds allowance|invalid\s*(?:fe\s*)?opcode|invalid\s*jump|stack\s*(?:under|over)flow|opcode\s*not\s*found|\bEVM error\b/i;

function executionFailure(error) {
    const queue = [error];
    const seen = new Set();
    while (queue.length) {
        const value = queue.shift();
        if (value == null) continue;
        if (typeof value === 'string') {
            if (EXECUTION_FAILURE.test(value)) return true;
            continue;
        }
        if (typeof value !== 'object' || seen.has(value)) continue;
        seen.add(value);
        if (Number(value.code) === 3) return true;
        for (const field of ['message', 'shortMessage', 'reason', 'error', 'cause', 'originalError', 'data']) {
            queue.push(value[field]);
        }
    }
    return false;
}

// The payout reading of a close that a reorganization removed.
const REOPENED_PAYOUT_FIELDS = Object.freeze({
    payoutVerified: false,
    payoutCredited: false,
    creditedAmount: null,
    payoutCreditEvidence: null,
    payoutClaimed: false,
    payoutClaimEvidence: null,
    payoutClaimTransactionHash: null,
    payoutClaimBlockNumber: null,
    payoutClaimedAmount: null
});

function rpcQuantity(value) {
    return `0x${BigInt(value).toString(16)}`;
}

// The payout fields of a closed withdrawal record, from this pass's receipt
// evidence (payoutVerified: a receipt proved the payout; payoutCredit: the
// vault only credited it) and the record's earlier reading. Receipt and claim
// evidence is kept: a pass that cannot read the receipt again never undoes a
// proven payout, and a credited escape payout is never reported as paid
// (payoutVerified) until a claim for its destination is proven. Only a credit
// inferred from the vault's balance (evidence 'vault_credit') yields, to this
// escape's own receipt proving that the push was paid. A payout the
// paymaster credited (`paymasterCredited`, a sponsored operation whose payee
// refused the push) is likewise never reported as paid until
// claimGaslessCredit delivers it and clears the flag.
function closedWithdrawalPayout(record, payoutVerified, payoutCredit) {
    if (record.paymasterCredited === true && !record.creditClaimTransactionHash) return { payoutVerified: false };
    const credited = record.payoutCredited === true;
    if (!payoutCredit && credited && payoutVerified === true && record.payoutCreditEvidence === 'vault_credit') {
        return { payoutVerified: true, payoutCredited: false, creditedAmount: null, payoutCreditEvidence: null };
    }
    if (!payoutCredit && !credited) return { payoutVerified: payoutVerified === true || record.payoutVerified === true };
    const receiptCredit = payoutCredit?.evidence === 'receipt' ? payoutCredit : null;
    return {
        payoutCredited: true,
        creditedAmount: receiptCredit ? receiptCredit.amount : (record.creditedAmount ?? null),
        payoutCreditEvidence: receiptCredit ? 'receipt'
            : (record.payoutCreditEvidence || payoutCredit?.evidence || 'receipt'),
        payoutVerified: record.payoutClaimed === true
    };
}

function readStoredWithdrawal() {
    if (typeof window === 'undefined' || typeof localStorage === 'undefined') return null;
    try {
        const stored = JSON.parse(localStorage.getItem(WITHDRAWAL_STORAGE_KEY) || 'null');
        return stored?.noteId != null && ['prepared', 'submitted', 'pending'].includes(stored.phase)
            ? stored
            : null;
    } catch {
        localStorage.removeItem(WITHDRAWAL_STORAGE_KEY);
        return null;
    }
}

/** The earliest of the given block numbers (null and undefined ignored), or null. */
function earliestBlock(...blocks) {
    const known = blocks.filter(block => block != null && Number.isFinite(Number(block))).map(Number);
    return known.length ? Math.min(...known) : null;
}

function normalizeWithdrawalDestination(destination, funding) {
    if (destination === undefined) return null;
    if (typeof destination !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(destination)
        || /^0x0{40}$/i.test(destination)) {
        throw new TypeError('Choose a valid nonzero Ethereum withdrawal address.');
    }
    const normalized = destination.toLowerCase();
    if (funding?.contract_address?.toLowerCase() === normalized) {
        throw new TypeError('The withdrawal address cannot be the vault contract.');
    }
    return normalized;
}

function walletErrorCode(error) {
    return error?.code
        ?? error?.cause?.code
        ?? error?.data?.originalError?.code
        ?? error?.error?.code
        ?? null;
}

function isWalletRejection(error) {
    const code = walletErrorCode(error);
    return code === 4001
        || code === 'ACTION_REJECTED'
        || /(?:user|wallet).*(?:reject|denied|cancel)|request rejected/i.test(error?.message || '');
}

function isDefinitelyPreBroadcastSendFailure(error) {
    const code = walletErrorCode(error);
    // EIP-1193 authorization/connectivity failures and JSON-RPC request-shape
    // failures are rejected by the provider before it can accept a signed
    // transaction. Broad -32000 errors are intentionally classified only by
    // narrow messages because that code also covers ambiguous node failures.
    if ([4100, 4200, 4900, 4901, -32600, -32601, -32602].includes(Number(code))) {
        return true;
    }
    const message = [
        error?.message,
        error?.shortMessage,
        error?.data?.message,
        error?.data?.originalError?.message,
        error?.error?.message
    ].filter(Boolean).join(' ');
    return /insufficient funds(?: for gas| to pay)|intrinsic gas too low|exceeds (?:the )?block gas limit|transaction gas limit too high|gas limit (?:is )?too high|sender account not recognized|unknown account/i.test(message);
}

// Actionable copy for wallet-gate refusals and vault reverts. error.data keeps
// the machine-readable details (for example escape_at).
const WITHDRAWAL_ERROR_MESSAGES = Object.freeze({
    request_settlement_pending: 'A private chat payment for this balance may still settle. A mutual close waits for it; an escape is available now, and from the time shown it concedes at most that chat’s budget.',
    device_not_newest: 'Another device spent this balance’s next state, so this device is not the newest. Restore the newest backup or exit kit before withdrawing.',
    exit_locked: 'A withdrawal of this balance is in progress. Finish or cancel it before starting a private chat.',
    exit_lock_mode: 'An escape proof for this balance may still land, so it can only exit by escape until that proof expires.',
    exit_lock_state: 'An exit proof of another balance state may still land. Check its status first.',
    exit_release_pending: 'An earlier exit proof of this balance has expired, and a newer balance state waits until the vault confirms that proof can no longer land. The vault could not be read yet: try again shortly, or set your own exit RPC. Close to the exit deadline the exit goes ahead from the earlier state.',
    note_near_expiry: 'This balance is too close to its expiry for a new private chat. Withdraw it instead.',
    invalid_successor: 'The server settled a private request with a successor that fails this wallet’s checks. Only withdrawing remains, conceding at most that request’s budget.',
    deployment_mismatch: 'This vault does not match the deployment this app pins, so deposits are refused. Existing balances can still be withdrawn.',
    deployment_unverifiable: 'This app cannot verify its vault deployment, so deposits are refused. Existing balances can still be withdrawn.',
    canary_cap_exceeded: 'During its launch period this vault takes only limited deposits. Choose a smaller amount.',
    canary_cap_unverified: 'The vault balance could not be read to check its launch-period limit. Try again.',
    receipt_unrecoverable: 'The server reports a settled private request for this balance that this browser cannot apply. Only withdrawing remains, conceding at most that request’s budget.',
    receipt_response_missing: 'The server reports a finalized private request for this balance but returned no receipt. Try again shortly.',
    receipt_pending_install: 'A settled private request must be applied to this balance first. Select the balance and try again.',
    request_archive_limit: 'Too many unsettled private requests are recorded for this balance, so no new chat can start from it. Chats resume only if the server settles one of them; otherwise withdraw the balance.',
    withdrawal_submission_pending: 'A withdrawal transaction for this balance is still unresolved. Check its status first.',
    challenged_nullifier: 'The vault already defeated an escape at this balance state: another device spent its next state. Restore the newest backup or exit kit.',
    superseded_state: 'The vault already defeated an escape from this balance’s next state: another device holds a newer state. Restore the newest backup or exit kit.',
    proof_expired: 'The withdrawal proof expired before it was included. Prepare the withdrawal again.',
    unknown_root: 'The vault does not know this withdrawal proof’s Merkle root. Prepare the withdrawal again.',
    invalid_destination: 'The vault rejected the withdrawal address. Choose a valid nonzero address.',
    vault_paused: 'The vault is paused by its owner. Withdrawals reopen at the latest when its pause limit ends.',
    testnet_password_required: 'Enter the Sepolia password to check this balance’s private request status.',
    // Sponsored withdrawals (design §3.2).
    ...GASLESS_MESSAGES
});

function withdrawalErrorWithMessage(error) {
    const message = WITHDRAWAL_ERROR_MESSAGES[error?.code];
    if (message && error && typeof error === 'object') error.shortMessage = message;
    return error;
}

function tagTransactionError(error, stage, broadcastPossible, transactionHash = null) {
    const tagged = normalizeWalletError(error);
    tagged.transactionStage = stage;
    tagged.broadcastPossible = Boolean(broadcastPossible);
    if (transactionHash) tagged.transactionHash = transactionHash;
    return tagged;
}

// EIP-1193 normally exposes JSON-RPC quantities as 0x-prefixed strings, but
// MetaMask's pending-nonce middleware can return a number directly. Other
// injected-provider compatibility layers also surface bigints, decimal
// strings, ethers-style {_hex}, or an unwrapped RPC result.
// Normalize only exact non-negative integers; never coerce floats, signs, or
// arbitrary objects into a wallet nonce.
function walletNonceNumber(value, depth = 0) {
    if (depth > 2) return null;
    if (value && typeof value === 'object') {
        if (Object.prototype.hasOwnProperty.call(value, 'error')) return null;
        for (const field of ['result', '_hex', 'hex']) {
            if (Object.prototype.hasOwnProperty.call(value, field)) {
                return walletNonceNumber(value[field], depth + 1);
            }
        }
        return null;
    }

    let quantity;
    if (typeof value === 'bigint') {
        quantity = value;
    } else if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) return null;
        quantity = BigInt(value);
    } else if (typeof value === 'string') {
        const text = value.trim();
        if (!/^(?:0[xX][0-9a-fA-F]+|(?:0|[1-9][0-9]*))$/.test(text)) return null;
        try {
            quantity = BigInt(text);
        } catch {
            return null;
        }
    } else {
        return null;
    }

    if (quantity < 0n || quantity > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(quantity);
}

/**
 * The payout a withdrawal started with, as its start receipt states it. An
 * escape's record follows raises (its finalBalance is the vault's current
 * pendingWithdrawals amount), so its start is B − concededAtInit (E5); a
 * record without B and c_init (or a close) started at its finalBalance.
 */
function startFinalBalance(record) {
    if (record?.mode !== 'mutual' && record?.stateBalance != null && record?.concededAtInit != null) {
        try {
            const started = BigInt(record.stateBalance) - BigInt(record.concededAtInit);
            if (started >= 0n) return started;
        } catch {
            // A malformed record falls back to its finalBalance.
        }
    }
    return BigInt(record.finalBalance);
}

// Refusals of an exit that a new proof can cure: valid_until passed (E4.7) or
// the vault does not know the proof's root (E4.1).
const REPROVABLE_EXIT_ERRORS = Object.freeze(['proof_expired', 'unknown_root']);

/** The G1 warning (design §2.3) as a status message; amounts are gwei ledger units. */
function exitCostMessage({ floor, cost }) {
    return `This balance can return as little as ${formatUnits(floor, 9)} ETH, less than three times the estimated network fee of an escape (${formatUnits(cost, 9)} ETH at the current gas price). Exiting by escape may cost more than it returns.`;
}

class ZkapiClient extends EventTarget {
    constructor() {
        super();
        walletProviders.set(this, { override: null, active: null, operations: 0 });
        this.config = null;
        this.wallet = null;
        this.walletAddress = null;
        this.withdrawal = readStoredWithdrawal();
        this.withdrawals = [];
        this.deposits = [];
        this.challengePeriodSeconds = 24 * 60 * 60;
        this.loading = false;
        this.lastError = null;
        this.initialized = false;
        this.initPromise = null;
        this.refreshTimer = null;
        this.clockTimer = null;
        this.browserMode = true;
        this.activities = [];
        this.activitySequence = 0;
        this.withdrawPromise = null;
        this.withdrawPromiseKey = null;
        this.finalizePromise = null;
        this.finalizePromiseKey = null;
        this.depositPromise = null;
        this.depositPromiseKey = null;
        this.backgroundReconciliationPromise = null;
        this.visibilityHandler = null;
    }

    async init() {
        beginBrowserSdkInitialization();
        if (this.initPromise) return this.initPromise;
        this.initPromise = (async () => {
            await this.enableBrowserMode();
            await this.refresh();
            await this.reconcileBrowserWithdrawalsOnLoad();
            this.attachWalletEvents();
            this.refreshTimer = window.setInterval(
                () => void this.reconcileBrowserWalletInBackground(),
                15_000
            );
            if (typeof document !== 'undefined' && !this.visibilityHandler) {
                this.visibilityHandler = () => {
                    if (document.visibilityState !== 'hidden') {
                        void this.reconcileBrowserWalletInBackground();
                    }
                };
                document.addEventListener('visibilitychange', this.visibilityHandler);
                window.addEventListener?.('focus', this.visibilityHandler);
            }
            // Time-only ticks have their own channel. Publishing them as a
            // semantic state change caused every subscriber to rebuild UI once
            // per second, disconnecting animated nodes and resetting focus.
            this.clockTimer = window.setInterval(() => this.emitClock(), 1_000);
            this.initialized = true;
            return this.snapshot();
        })().catch((error) => {
            this.lastError = error;
            this.loading = false;
            // A failed start is not kept: the next init() (an exit, for
            // one) starts again rather than replaying this error.
            this.initPromise = null;
            this.emitChange('error');
            throw error;
        });
        return this.initPromise;
    }

    async enableBrowserMode() {
        await browserWalletRuntime.init();
        if (!this.browserRuntimeListener) {
            this.browserRuntimeListener = () => void this.refresh({ quiet: true });
            browserWalletRuntime.addEventListener('change', this.browserRuntimeListener);
        }
    }

    async reconcileBrowserWithdrawalsOnLoad() {
        if (!this.ethereum || !this.config?.funding?.chain_id) return false;
        try {
            const currentChain = Number.parseInt(
                await this.ethereum.request({ method: 'eth_chainId' }),
                16
            );
            if (currentChain !== Number(this.config.funding.chain_id)) return false;
            const reconcile = async (label, action) => {
                try {
                    await action();
                    return true;
                } catch (error) {
                    // Each durable record is an independent recovery capability.
                    // One malformed receipt or temporarily unavailable RPC path
                    // must not starve every other withdrawal during startup.
                    console.warn(`Unable to reconcile ${label} on load.`, error);
                    return false;
                }
            };
            let complete = await reconcile(
                'late withdrawal transactions',
                () => this.syncLateWithdrawalAttempts(() => {})
            );
            complete = await reconcile(
                'the selected wallet snapshot',
                () => this.refresh({ quiet: true })
            ) && complete;
            complete = await reconcile(
                'the selected MetaMask request',
                () => browserWalletRuntime.recoverPreparedWithdrawalSubmissionClaim()
            ) && complete;
            complete = await reconcile(
                'the selected wallet state',
                () => this.refresh({ quiet: true })
            ) && complete;
            if (this.note && (this.config?.prepared_withdrawal || this.withdrawal)) {
                complete = await reconcile(
                    'the selected withdrawal',
                    () => this.syncWithdrawal(() => {})
                ) && complete;
            }
            if (this.withdrawals.some(record => record.phase !== 'closed'
                || record.finalizeTransactionHash
                || record.finalizeSubmissionId)) {
                complete = await reconcile(
                    'background withdrawals',
                    () => this.syncEscapeWithdrawals(() => {})
                ) && complete;
            }
            complete = await reconcile('expiry payments', () => this.syncExpiryHistory()) && complete;
            return complete;
        } catch (error) {
            // Startup recovery must never summon MetaMask or prevent the host from
            // loading. The exact durable state remains available through
            // the explicit status action in the balance panel.
            console.warn('Unable to reconcile browser withdrawals on load.', error);
            return false;
        }
    }

    async reconcileBrowserWalletInBackground() {
        if (this.backgroundReconciliationPromise) return this.backgroundReconciliationPromise;
        const operation = (async () => {
            await this.refresh({ quiet: true });
            if (!this.ethereum || !this.config?.funding?.chain_id) {
                return false;
            }
            if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
                return false;
            }
            const currentChain = Number.parseInt(
                await this.ethereum.request({ method: 'eth_chainId' }),
                16
            );
            if (currentChain !== Number(this.config.funding.chain_id)) return false;

            // These paths only read the connected chain and reconcile durable
            // browser state. They never request accounts or open MetaMask.
            const reconcile = async (label, action) => {
                try {
                    await action();
                    return true;
                } catch (error) {
                    // Keep independent recovery records making progress. In
                    // particular, a broken deposit RPC response must not leave
                    // an unrelated withdrawal looking frozen forever.
                    console.warn(`Unable to reconcile ${label} in the background.`, error);
                    return false;
                }
            };
            let complete = true;
            if (this.config?.pending_deposit) {
                complete = await reconcile(
                    'the pending deposit',
                    () => this.recoverBrowserDeposit(() => {})
                ) && complete;
            }
            complete = await reconcile(
                'late withdrawal transactions',
                () => this.syncLateWithdrawalAttempts(() => {})
            ) && complete;
            complete = await reconcile(
                'the wallet snapshot',
                () => this.refresh({ quiet: true })
            ) && complete;
            if (this.note && (this.config?.prepared_withdrawal || this.withdrawal)) {
                complete = await reconcile(
                    'the selected withdrawal',
                    () => this.syncWithdrawal(() => {})
                ) && complete;
            }
            if (this.withdrawals.some(record => record.phase !== 'closed'
                || record.finalizeTransactionHash
                || record.finalizeSubmissionId)) {
                complete = await reconcile(
                    'background withdrawals',
                    () => this.syncEscapeWithdrawals(() => {})
                ) && complete;
            }
            complete = await reconcile('expiry payments', () => this.syncExpiryHistory()) && complete;
            return complete;
        })().catch(error => {
            // A background provider outage is not a new wallet failure. The
            // durable recovery card remains available for an explicit check.
            console.warn('Unable to reconcile browser wallet in the background.', error);
            return false;
        }).finally(() => {
            if (this.backgroundReconciliationPromise === operation) {
                this.backgroundReconciliationPromise = null;
            }
        });
        this.backgroundReconciliationPromise = operation;
        return operation;
    }

    get ethereum() {
        const state = walletProviders.get(this);
        return state.operations ? state.active : state.override || globalThis.ethereum;
    }

    get walletProviderBusy() {
        return walletProviders.get(this).operations > 0;
    }

    setWalletProvider(provider = null) {
        if (provider !== null && (typeof provider !== 'object' || typeof provider.request !== 'function')) {
            throw new TypeError('The wallet provider must implement EIP-1193 request().');
        }
        const state = walletProviders.get(this);
        if (state.override === provider) return this.ethereum;
        if (state.operations || state.override?.hasPendingTransaction === true) {
            const error = new Error('Wait for the current wallet action to finish before changing payment methods.');
            error.code = 'wallet_provider_busy';
            throw error;
        }
        this.detachWalletEvents();
        state.override = provider;
        this.walletAddress = null;
        this.attachWalletEvents();
        return this.ethereum;
    }

    detachWalletEvents() {
        const attached = this.walletEventHandlers;
        if (!attached) return;
        if (typeof attached.provider.removeListener === 'function') {
            attached.provider.removeListener('accountsChanged', attached.accountsChanged);
            attached.provider.removeListener('chainChanged', attached.chainChanged);
        }
        this.walletEventHandlers = null;
    }

    attachWalletEvents() {
        const provider = this.ethereum;
        if (this.walletEventHandlers?.provider === provider) return;
        this.detachWalletEvents();
        if (typeof provider?.on !== 'function') return;
        const accountsChanged = (accounts) => {
            if (this.ethereum !== provider) return;
            this.walletAddress = accounts?.[0] || null;
            this.emitChange('wallet-account');
        };
        const chainChanged = () => {
            if (this.ethereum !== provider) return;
            this.walletAddress = null;
            this.emitChange('wallet-network');
        };
        this.walletEventHandlers = { provider, accountsChanged, chainChanged };
        provider.on('accountsChanged', accountsChanged);
        provider.on('chainChanged', chainChanged);
    }

    snapshot() {
        return {
            config: this.config,
            wallet: this.wallet,
            walletAddress: this.walletAddress,
            withdrawal: this.withdrawal,
            withdrawals: this.withdrawals.map(record => ({ ...record })),
            deposits: this.deposits.map(record => ({ ...record })),
            challengePeriodSeconds: this.challengePeriodSeconds,
            loading: this.loading,
            lastError: this.lastError,
            initialized: this.initialized,
            activities: this.activities.map(activity => ({ ...activity }))
        };
    }

    runtimeStateSignature() {
        const error = this.lastError ? {
            name: this.lastError.name || null,
            code: this.lastError.code || null,
            status: this.lastError.status || null,
            message: walletErrorMessage(this.lastError)
        } : null;
        return JSON.stringify({
            config: this.config,
            wallet: this.wallet,
            withdrawal: this.withdrawal,
            withdrawals: this.withdrawals,
            deposits: this.deposits,
            error
        });
    }

    beginActivity(kind, details = {}) {
        const now = Date.now();
        const activity = {
            id: `zkapi-${now}-${++this.activitySequence}`,
            kind,
            phase: details.phase || 'starting',
            title: details.title || null,
            message: details.message || null,
            status: 'running',
            blocksSend: Boolean(details.blocksSend),
            sessionId: details.sessionId || null,
            startedAt: now,
            updatedAt: now,
            finishedAt: null,
            error: null
        };
        this.activities.push(activity);
        if (this.activities.length > 16) this.activities.splice(0, this.activities.length - 16);
        this.emitChange('activity-start');
        return activity.id;
    }

    updateActivity(id, changes = {}) {
        const activity = this.activities.find(entry => entry.id === id);
        if (!activity) return null;
        Object.assign(activity, changes, { updatedAt: Date.now() });
        this.emitChange('activity-update');
        return { ...activity };
    }

    completeActivity(id, changes = {}) {
        return this.updateActivity(id, {
            ...changes,
            status: 'success',
            phase: changes.phase || 'complete',
            finishedAt: Date.now(),
            blocksSend: false,
            error: null
        });
    }

    failActivity(id, error, changes = {}) {
        const message = walletErrorMessage(error);
        return this.updateActivity(id, {
            ...changes,
            status: 'error',
            phase: 'error',
            finishedAt: Date.now(),
            blocksSend: Boolean(changes.blocksSend),
            error: message
        });
    }

    cancelActivity(id, message = 'Canceled. No changes were made.') {
        return this.updateActivity(id, {
            status: 'canceled',
            phase: 'canceled',
            message,
            finishedAt: Date.now(),
            blocksSend: false,
            error: null
        });
    }

    subscribe(listener) {
        const handler = (event) => listener(this.snapshot(), event.detail);
        this.addEventListener('change', handler);
        return () => this.removeEventListener('change', handler);
    }

    subscribeClock(listener) {
        const handler = (event) => listener(event.detail);
        this.addEventListener('clock', handler);
        return () => this.removeEventListener('clock', handler);
    }

    emitClock() {
        this.dispatchEvent(new CustomEvent('clock', {
            detail: { now: Date.now() }
        }));
    }

    emitChange(reason = 'update') {
        this.dispatchEvent(new CustomEvent('change', { detail: { reason } }));
        window.dispatchEvent(new CustomEvent('zkapi-state-changed', {
            detail: { reason, snapshot: this.snapshot() }
        }));
    }

    rememberWithdrawal(value, { emit = true } = {}) {
        this.withdrawal = value;
        if (value) localStorage.setItem(WITHDRAWAL_STORAGE_KEY, JSON.stringify(value));
        else localStorage.removeItem(WITHDRAWAL_STORAGE_KEY);
        if (emit) this.emitChange('withdrawal');
    }

    async refresh({ quiet = false } = {}) {
        const stateBeforeRefresh = this.runtimeStateSignature();
        if (!quiet) {
            this.loading = true;
            this.emitChange('loading');
        }
        try {
            const wallet = await browserWalletRuntime.walletStatus();
            const browserSnapshot = browserWalletRuntime.snapshot();
            validateNativeFunding(browserSnapshot.config?.funding);
            this.config = browserSnapshot.config;
            this.wallet = wallet;
            this.withdrawals = browserSnapshot.withdrawals || [];
            this.deposits = browserSnapshot.deposits || [];
            this.lastError = null;
            if (this.isNativeEthFunding && (!this.ethUsdCheckedAt || Date.now() - this.ethUsdCheckedAt > 60_000)) {
                this.ethUsdCheckedAt = Date.now();
                void this.refreshEthUsdPrice().catch(() => {});
            }

            const prepared = this.config?.prepared_withdrawal;
            if (prepared) {
                const mirror = {
                    phase: prepared.phase || (prepared.transaction_hash ? 'submitted' : 'prepared'),
                    mode: prepared.mode,
                    noteId: prepared.note_id,
                    destination: prepared.destination,
                    transactionHash: prepared.transaction_hash || null,
                    clearanceReserved: prepared.clearance_reserved === true || prepared.mode === 'mutual'
                };
                if (JSON.stringify(this.withdrawal) !== JSON.stringify(mirror)) {
                    this.rememberWithdrawal(mirror, { emit: false });
                }
            } else if (this.withdrawal) {
                // IndexedDB is authoritative in browser mode. localStorage is
                // only a presentation mirror and must never resurrect a
                // canceled/prepared marker after the durable plan is cleared.
                this.rememberWithdrawal(null, { emit: false });
            }
        } catch (error) {
            this.lastError = error;
            if (!quiet) throw error;
        } finally {
            this.loading = false;
            // Periodic/browser-runtime refreshes often return byte-for-byte
            // equivalent state. Do not fan those out as semantic UI changes;
            // full panel/modal renders would otherwise replay animations even
            // though nothing users can act on changed.
            if (!quiet || stateBeforeRefresh !== this.runtimeStateSignature()) {
                this.emitChange(this.lastError ? 'error' : 'runtime');
            }
        }
        return this.snapshot();
    }

    get isNativeEthFunding() {
        return isNativeEthFunding(this.config?.funding);
    }

    get nativePriceQuote() {
        for (const quote of [this.ethUsdQuote, browserWalletRuntime.ethUsdQuote]) {
            try { return validateNativeQuote(quote, this.config?.funding); }
            catch { /* Only a current quote from this deployment may value ETH. */ }
        }
        return null;
    }

    async refreshEthUsdPrice({ signal } = {}) {
        if (!this.isNativeEthFunding) throw new Error('This deployment does not accept native ETH.');
        const funding = this.config.funding;
        const quote = await readNativeQuote(funding, { signal });
        if (funding !== this.config.funding && funding.contract_address !== this.config.funding.contract_address) {
            throw new Error('The payment deployment changed while checking the ETH price.');
        }
        this.ethUsdQuote = quote;
        this.ethUsdCheckedAt = Date.now();
        this.emitChange('price');
        return quote;
    }

    async quoteDepositUsd(usd, { signal } = {}) {
        // A quote is for a new deposit, which a closed deployment refuses.
        if (browserWalletRuntime.depositsClosed()) throw browserWalletRuntime.depositsClosedError();
        const price = await this.refreshEthUsdPrice({ signal });
        const amount = nativeUnitsForUsd(usd, price);
        return Object.freeze({ amount: String(amount), ethAmount: formatUnits(amount, 9),
            depositWei: String(nativeDepositValue(amount, this.config.funding)),
            usdAmount: formatUnits(parseUnits(usd, 6), 6), priceUpdatedAt: price.updated_at,
            price, chainId: this.config.funding.chain_id, contractAddress: this.config.funding.contract_address });
    }

    async prepareDepositQuote(amountInput, { from } = {}) {
        if (!this.initialized) await this.init();
        await this.ensureTestnetAccess();
        if (!this.isNativeEthFunding) {
            throw new Error('Prefunding deposit quotes require a native ETH browser wallet.');
        }
        if (typeof from !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(from) || /^0x0{40}$/i.test(from)) {
            throw new Error('Choose a valid funding address before estimating this deposit.');
        }
        await this.assertDepositMayStart();
        const funding = this.config.funding;
        const amount = parseUnits(amountInput, 9);
        if (amount <= 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error('Choose a smaller positive deposit amount.');
        }
        await assertNativeVault(funding);
        const root = await this.readContractUint(funding.contract_address, `0x${ABI.currentRoot}`);
        const plan = await browserWalletRuntime.prepareDepositQuote(Number(amount), root);
        await this.assertFundingChain();
        const value = nativeDepositValue(amount, funding);
        // Never return the durable secret, note witness, or runtime object.
        return Object.freeze({
            operationId: plan.operationId,
            commitment: plan.commitment,
            amount: String(amount),
            depositWei: String(value),
            chainId: Number(funding.chain_id),
            contractAddress: funding.contract_address,
            transaction: Object.freeze({ from: from.toLowerCase(), to: funding.contract_address,
                data: encodeDeposit(plan, amount), value: `0x${value.toString(16)}` })
        });
    }

    get creditsPerUsd() {
        const quote = this.nativePriceQuote;
        return quote ? 1e9 * (10 ** quote.decimals) / Number(quote.answer) : Number.NaN;
    }

    get hasNote() {
        return !!this.wallet?.has_note && !!this.wallet?.note;
    }

    async acquireInferenceAccess(sessionId, options = {}) {
        const signal = options.signal || null;
        const throwIfCancelled = () => {
            if (!signal?.aborted) return;
            const error = new DOMException('The operation was aborted.', 'AbortError');
            error.isCancelled = true;
            throw error;
        };
        throwIfCancelled();
        if (!this.initialized) await this.init();
        await this.ensureTestnetAccess({ signal, interactive: true });
        throwIfCancelled();
        const activityId = this.beginActivity('access', {
            phase: 'checking',
            title: 'Starting private chat',
            message: 'Checking your private balance…',
            progressKind: 'access',
            sessionId,
            blocksSend: true
        });
        let lastProgressPhase = 'checking';
        let lastProgressKind = 'access';
        const notifyProgress = (phase, message, kind = 'access', metadata = {}) => {
            try {
                options.onProgress?.({
                    kind,
                    phase,
                    message,
                    sessionId,
                    ...metadata
                });
            } catch (error) {
                console.warn('The assistant private-access trace could not update.', error);
            }
        };
        const reportProgress = (phase, message, kind = 'access') => {
            lastProgressPhase = phase;
            lastProgressKind = kind;
            this.updateActivity(activityId, { phase, message, progressKind: kind });
            notifyProgress(phase, message, kind);
        };
        notifyProgress('checking', 'Checking your private balance…');
        try {
            const access = await browserWalletRuntime.acquireEphemeralKey(
                sessionId,
                reportProgress,
                { signal, spendingLimitUsd: options.spendingLimitUsd }
            );
            if (signal?.aborted) {
                access.release?.();
                throwIfCancelled();
            }
            if (lastProgressPhase !== 'ready') {
                reportProgress('ready', 'Private chat ready.', lastProgressKind);
            }
            this.completeActivity(activityId, {
                phase: 'ready',
                message: 'Private chat ready.',
                progressKind: lastProgressKind
            });
            return access;
        } catch (error) {
            if (signal?.aborted) error.isCancelled = true;
            this.failActivity(activityId, error, { blocksSend: true });
            notifyProgress(
                error?.isCancelled ? 'canceled' : 'error',
                'Private access was not created.',
                lastProgressKind,
                { failedPhase: lastProgressPhase }
            );
            throw error;
        }
    }

    get note() {
        return this.wallet?.note || null;
    }

    get noteExpiryClaim() {
        if (this.note?.note_id == null) return null;
        return this.deposits.find(record => record.status === 'confirmed'
            && record.noteId === Number(this.note.note_id))?.expiryClaim || null;
    }

    get expiryHistory() {
        return deriveExpiryRecords(this.deposits, this.withdrawals);
    }

    async syncExpiryHistory() {
        if (this.expiryHistoryPromise) return this.expiryHistoryPromise;
        if (!this.config?.funding) return { complete: true, claims: [] };
        const operation = (async () => {
            this.deposits = await browserWalletRuntime.getDepositHistory();
            // A generic Closed vault status may itself be an expiry claim.
            // Never let a withdrawal's phase suppress checking actual payments.
            if (!deriveExpiryRecords(this.deposits).some(record => record.status === 'expired')) {
                return { complete: true, claims: [] };
            }
            if (!this.ethereum?.request) throw new Error('Open MetaMask on the balance’s network to check expiry payments. No transaction is needed.');
            const funding = this.config.funding;
            const deploymentId = browserWalletRuntime.manifest.deployment_id;
            const historyIdentity = JSON.stringify(this.deposits.filter(record => record.status === 'confirmed')
                .map(record => [record.recordId, record.expiryTs, record.amount]).sort());
            const scan = this.expiryScan?.deploymentId === deploymentId
                && this.expiryScan.historyIdentity === historyIdentity ? this.expiryScan : null;
            const result = await readFinalizedExpiryClaims({
                request: request => this.ethereum.request(request),
                vaultAddress: funding.contract_address,
                chainId: funding.chain_id,
                deposits: this.deposits,
                fromBlock: scan ? scan.scannedTo + 1 : 0,
                deploymentBlock: scan?.deploymentBlock ?? null
            });
            // Advance only after durable history succeeds. A failed save can
            // safely rescan the same public events without losing a payment.
            if (result.claims.length) await browserWalletRuntime.rememberExpiryClaims(result.claims);
            this.expiryScan = { deploymentId, historyIdentity, scannedTo: result.scannedTo,
                deploymentBlock: result.deploymentBlock };
            await this.refresh({ quiet: true });
            return result;
        })();
        this.expiryHistoryPromise = operation;
        try { return await operation; }
        finally { if (this.expiryHistoryPromise === operation) this.expiryHistoryPromise = null; }
    }

    async archiveClaimedBalance() {
        if (!this.noteExpiryClaim) throw new Error('The balance has no verified expiry payment.');
        await browserWalletRuntime.archiveNote('expiry-claimed', Number(this.note.note_id));
        await this.refresh();
    }

    async assertBalanceNotClaimed(noteId) {
        this.deposits = await browserWalletRuntime.getDepositHistory();
        if (this.deposits.some(record => record.status === 'confirmed'
            && record.noteId === Number(noteId) && record.expiryClaim)) {
            throw new Error('This balance was claimed after expiry. Open Balance details to start a new balance.');
        }
    }

    get requestMode() {
        return 'direct_openrouter';
    }

    get isDirectMode() {
        return this.requestMode === 'direct_openrouter';
    }

    get suggestedDeposit() {
        return 5;
    }

    get billingTokenSymbol() {
        return 'ETH';
    }

    get isMainnetFunding() {
        return Number(this.config?.funding?.chain_id) === 1;
    }

    get activeLease() {
        const lease = this.config?.active_lease;
        return lease && Number(lease.expires_at) * 1000 > Date.now() ? lease : null;
    }

    get activeLateWithdrawal() {
        const noteId = this.note?.note_id;
        if (noteId == null) return null;
        return (this.config?.late_withdrawal_attempts || []).find(attempt =>
            Number(attempt.note_id) === Number(noteId)) || null;
    }

    get withdrawalBlocksChat() {
        // C3: a held exit lock freezes requests until the exit ends (E6).
        return !!this.activeLateWithdrawal
            || !!this.config?.prepared_withdrawal
            || !!this.config?.exit?.lock
            || ['prepared', 'submitted', 'pending'].includes(this.withdrawal?.phase);
    }

    get activeWithdrawal() {
        return this.config?.prepared_withdrawal
            || this.withdrawal
            || (this.activeLateWithdrawal ? {
                phase: 'late_submitted',
                mode: this.activeLateWithdrawal.mode,
                noteId: this.activeLateWithdrawal.note_id,
                destination: this.activeLateWithdrawal.destination,
                transactionHash: this.activeLateWithdrawal.transaction_hash
            } : null);
    }

    get openWithdrawals() {
        return this.withdrawals.filter(record => record.phase !== 'closed'
            || record.finalizeTransactionHash
            || record.finalizeSubmissionId);
    }

    get unresolvedLateWithdrawals() {
        return [...(this.config?.late_withdrawal_attempts || [])];
    }

    get withdrawalRecoveryCount() {
        return this.openWithdrawals.length + this.unresolvedLateWithdrawals.length;
    }

    formatMoney(credits) {
        if (credits == null) return '—';
        if (!this.nativePriceQuote) return '—';
        const value = Number(nativeUsdMicros(credits, this.nativePriceQuote)) / 1_000_000;
        const digits = value > 0 && value < 0.01 ? 6 : 2;
        return new Intl.NumberFormat(undefined, {
            style: 'currency',
            currency: 'USD',
            minimumFractionDigits: 2,
            maximumFractionDigits: digits
        }).format(value);
    }

    formatBillingAmount(credits) {
        return formatUnits(credits || 0, 9);
    }

    formatExpiry(timestamp) {
        if (!timestamp) return '—';
        const remaining = Number(timestamp) * 1000 - Date.now();
        if (remaining <= 0) return 'expired';
        const days = Math.floor(remaining / 86_400_000);
        if (days > 1) return `${days} days`;
        const hours = Math.floor(remaining / 3_600_000);
        if (hours > 0) return `${hours}h`;
        return `${Math.max(1, Math.ceil(remaining / 60_000))}m`;
    }

    compact(value, width = 7) {
        if (!value) return '—';
        const text = String(value);
        return text.length > width * 2 + 2
            ? `${text.slice(0, width)}…${text.slice(-width)}`
            : text;
    }

    networkName(chainId = this.config?.funding?.chain_id) {
        const names = { 1: 'Ethereum Mainnet', 11155111: 'Sepolia', 31337: 'Local Anvil' };
        return names[Number(chainId)] || `Chain ${chainId ?? '—'}`;
    }

    chainParameters(chainId, rpcUrl) {
        const known = {
            1: { chainName: 'Ethereum Mainnet', nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, blockExplorerUrls: ['https://etherscan.io'] },
            11155111: { chainName: 'Sepolia', nativeCurrency: { name: 'Sepolia Ether', symbol: 'ETH', decimals: 18 }, blockExplorerUrls: ['https://sepolia.etherscan.io'] },
            31337: { chainName: 'Local Anvil', nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, blockExplorerUrls: [] }
        };
        return {
            chainId: `0x${Number(chainId).toString(16)}`,
            ...(known[Number(chainId)] || {
                chainName: `Chain ${chainId}`,
                nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
                blockExplorerUrls: []
            }),
            rpcUrls: rpcUrl ? [rpcUrl] : []
        };
    }

    async ensureNetwork() {
        const wanted = Number(this.config?.funding?.chain_id);
        if (!Number.isFinite(wanted)) throw new Error('The payment deployment did not advertise a chain ID.');
        const current = Number.parseInt(await this.ethereum.request({ method: 'eth_chainId' }), 16);
        if (current === wanted) return;
        const chainId = `0x${wanted.toString(16)}`;
        try {
            await this.ethereum.request({
                method: 'wallet_switchEthereumChain',
                params: [{ chainId }]
            });
        } catch (error) {
            if (error.code !== 4902) throw error;
            await this.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [this.chainParameters(wanted, this.config?.funding?.demo_rpc_url)]
            });
        }
    }

    async assertFundingChain() {
        const wanted = Number(this.config?.funding?.chain_id);
        if (!Number.isFinite(wanted) || !this.ethereum) return;
        const current = Number.parseInt(
            await this.ethereum.request({ method: 'eth_chainId' }),
            16
        );
        if (current !== wanted) {
            const error = new Error(`MetaMask changed networks. Switch back to ${this.networkName()} and try again.`);
            error.code = 'wrong_network';
            throw error;
        }
    }

    async connectWallet() {
        if (!this.ethereum) {
            throw new Error('MetaMask was not detected. Install or enable it, then reload this page.');
        }
        this.attachWalletEvents();
        if (!this.config) await this.refresh();
        const accounts = await this.ethereum.request({ method: 'eth_requestAccounts' });
        await this.ensureNetwork();
        this.walletAddress = accounts?.[0] || null;
        if (!this.walletAddress) throw new Error('MetaMask did not return an account.');
        await this.loadChallengePeriod();
        this.emitChange('wallet-connected');
        return this.walletAddress;
    }

    async readContractUint(to, data, blockTag = 'latest') {
        const value = await this.ethereum.request({
            method: 'eth_call',
            params: [{ to, data }, blockTag]
        });
        return BigInt(value || '0x0');
    }

    async loadChallengePeriod() {
        const vault = this.config?.funding?.contract_address;
        if (!vault || !this.ethereum) return;
        // Both published v2 vaults expose the original CHALLENGE_PERIOD()
        // getter. Probe it first so MetaMask does not report a benign
        // `execution reverted` RPC warning while connecting. Keep the newer
        // challengePeriod() getter as a forward-compatible fallback.
        for (const selector of [ABI.legacyChallengePeriod, ABI.challengePeriod]) {
            try {
                const value = await this.readContractUint(vault, `0x${selector}`);
                if (value > 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
                    this.challengePeriodSeconds = Number(value);
                    this.emitChange('challenge-period');
                    return;
                }
            } catch {
                // Older deployments expose a differently named constant getter.
            }
        }
    }

    async waitForReceipt(hash, candidateHashes = null) {
        let consecutiveReadFailures = 0;
        for (let attempt = 0; attempt < 180; attempt += 1) {
            let receipt;
            try {
                const candidates = candidateHashes ? candidateHashes(hash) : [hash];
                if (candidateHashes && (!Array.isArray(candidates) || !candidates.length
                    || candidates.some(candidate => !/^0x[0-9a-f]{64}$/i.test(candidate)))) {
                    throw new Error('The external wallet returned invalid receipt candidates.');
                }
                for (const candidate of candidates) {
                    receipt = await this.ethereum.request({
                        method: 'eth_getTransactionReceipt',
                        params: [candidate]
                    });
                    if (receipt && candidateHashes
                        && String(receipt.transactionHash || '').toLowerCase() !== candidate.toLowerCase()) {
                        throw new Error('The external transaction receipt has a different transaction hash.');
                    }
                    if (receipt) break;
                }
                consecutiveReadFailures = 0;
            } catch (failure) {
                const error = normalizeWalletError(failure);
                // Receipt reads can briefly fail while the wallet switches
                // from its submitted transaction to the mined RPC record.
                // Retry reads only; the transaction hash is already journaled.
                consecutiveReadFailures += 1;
                if ([4001, 4100, 4200, 4901, -32600, -32601, -32602].includes(Number(walletErrorCode(error)))
                    || consecutiveReadFailures >= 3) {
                    throw error;
                }
                await new Promise(resolve => setTimeout(resolve, 1_000));
                continue;
            }
            if (receipt) {
                if (BigInt(receipt.status || '0x0') !== 1n) {
                    const error = new Error(`Transaction ${this.compact(hash)} reverted.`);
                    error.transactionReceipt = receipt;
                    throw error;
                }
                return receipt;
            }
            await new Promise(resolve => setTimeout(resolve, 1_000));
        }
        throw new Error(`Timed out waiting for transaction ${this.compact(hash)}.`);
    }

    async submittedTransactionMetadata(transactionHash, fallbackFrom = null) {
        try {
            const transaction = await this.ethereum.request({
                method: 'eth_getTransactionByHash',
                params: [transactionHash]
            });
            const nonce = walletNonceNumber(transaction?.nonce);
            const from = transaction.from || fallbackFrom;
            if (nonce == null
                || !/^0x[0-9a-fA-F]{40}$/.test(from || '')) {
                return null;
            }
            return { from: from.toLowerCase(), nonce };
        } catch {
            // The hash itself is the critical write-ahead record. Metadata is
            // best-effort and can be retried while the transaction is visible.
            return null;
        }
    }

    externalRecoveryContext(recovery) {
        return externalRecoveryContext(recovery, this.config?.funding, browserWalletRuntime.manifest?.deployment_id);
    }

    async acknowledgeExternalTransactionReceipt(hash) {
        const provider = this.ethereum;
        if (typeof provider.acknowledgeTransaction !== 'function') return this.waitForReceipt(hash);
        // A manual wallet can verify a fee replacement while this transaction
        // is awaiting its receipt. Check every verified version:
        // either original or replacement may win the identical nonce, and a
        // receipt must always retain the hash the RPC actually returned.
        const candidates = typeof provider.getVerifiedTransactionHashes === 'function'
            ? value => provider.getVerifiedTransactionHashes(value) : null;
        provider.beginTransactionReceiptWait?.(hash);
        try {
            const receipt = await this.waitForReceipt(hash, candidates);
            await provider.acknowledgeTransaction(candidates ? receipt.transactionHash : hash);
            return receipt;
        } catch (error) {
            if (error.transactionReceipt) {
                const receiptHash = candidates ? error.transactionReceipt.transactionHash : hash;
                const finality = await this.browserRevertedReceiptFinality(receiptHash, error.transactionReceipt);
                if (finality.finalized) await provider.acknowledgeTransaction(receiptHash);
            }
            throw error;
        } finally {
            provider.endTransactionReceiptWait?.(hash);
        }
    }

    async resumeExternalTransaction({ transaction, hash, context }) {

        if (this.depositPromise || this.withdrawPromise || this.finalizePromise
            || this.payoutClaimPromise || this.backgroundWithdrawalPromises?.size) {
            throw new Error('The original wallet action is still running. Return its transaction ID to that action.');
        }
        const funding = this.config?.funding;
        validateNativeFunding(funding);
        if (context?.version !== 1 || context.deploymentId !== browserWalletRuntime.manifest?.deployment_id
            || Number(context.chainId) !== Number(funding?.chain_id)
            || !sameAddress(context.contractAddress, funding?.contract_address)
            || !['deposit', 'withdrawal', 'background-withdrawal',
                'background-replacement', 'finalization', 'escape-payout-claim'].includes(context.kind)) {
            throw new Error('The saved external transaction belongs to a different payment deployment.');
        }
        await this.assertFundingChain();
        const actual = await this.ethereum.request({ method: 'eth_getTransactionByHash', params: [hash] });
        const expectedValue = context.kind === 'deposit'
            ? nativeDepositValue(context.amount, funding) : 0n;
        const metadata = assertExternalTransaction(actual, transaction, hash, funding.chain_id, expectedValue);
        await this.assertFundingChain();

        if (!sameAddress(transaction.to, funding.contract_address)) {
            throw new Error('The external transaction targets a different private vault.');
        }
        await browserWalletRuntime.reload();
        const runtime = browserWalletRuntime.runtime;
        const records = browserWalletRuntime.withdrawals || [];
        let known = [runtime?.pendingDeposit, runtime?.preparedWithdrawal,
            ...(runtime?.lateDepositAttempts || []), ...(runtime?.lateWithdrawalAttempts || []),
            ...(browserWalletRuntime.deposits || []), ...records]
            .some(record => hasDurableTransactionHash(record, hash));
        // A read-only recovery in this or another tab can already have moved
        // the note out of its pending slot before the host supplies the hash.
        // A matching successful event may acknowledge that completed work;
        // it never creates a note or bypasses the normal confirmation path.
        if (!known && context.kind === 'deposit') {
            const recovered = (browserWalletRuntime.deposits || []).find(record =>
                record.status === 'confirmed' && record.operationId === context.operationId
                && Number(record.noteId) === Number(context.noteId)
                && Number(record.amount) === Number(context.amount));
            if (recovered) {
                const receipt = await this.ethereum.request({ method: 'eth_getTransactionReceipt', params: [hash] });
                const event = receipt?.status === '0x1' && parseNoteDeposited(receipt, funding.contract_address);
                known = Boolean(String(receipt?.transactionHash).toLowerCase() === hash.toLowerCase()
                    && event?.noteId === BigInt(context.noteId) && event.amount === BigInt(context.amount)
                    && BigInt(event.commitment) === BigInt(context.commitment));
            }
        }
        if (!known) {
            const sameClaim = (operationId, submissionId) => operationId === context.operationId
                && submissionId === context.submissionId && Boolean(operationId && submissionId);
            const sameMetadata = (from, nonce) => sameAddress(from, metadata.from)
                && externalTransactionNonce(nonce) === metadata.nonce;
            const retainedClaim = (operationId, submissionId, from, nonce, history = []) => {
                if (sameClaim(operationId, submissionId)) return sameMetadata(from, nonce);
                return history.some(claim => claim.submissionId === context.submissionId
                    && (claim.operationId ?? operationId) === context.operationId
                    && (claim.from == null || sameAddress(claim.from, metadata.from))
                    && (claim.nonce == null || externalTransactionNonce(claim.nonce) === metadata.nonce)
                    && (claim.generation == null || Number(claim.generation) === Number(context.generation)));
            };
            const sameData = data => data.toLowerCase() === transaction.data.toLowerCase();
            const reference = { ...context };

            if (context.kind === 'deposit') {
                const plan = runtime?.pendingDeposit;
                if (!plan || !retainedClaim(plan.operationId, plan.submissionId,
                    plan.submissionFrom, plan.submissionNonce, plan.ambiguousSubmissions)
                    || Number(context.noteId) !== Number(plan.next_note_id)
                    || Number(context.amount) !== Number(plan.amount)
                    || String(context.commitment).toLowerCase() !== String(plan.commitment).toLowerCase()
                    || !sameData(encodeDeposit(plan, BigInt(plan.amount)))) {
                    throw new Error('The external deposit no longer matches its saved private note.');
                }
                // Only the SDK rehydrates the note secret; the provider never receives it.
                await browserWalletRuntime.rememberPendingDepositTransaction(hash,
                    { ...reference, secret: plan.secret }, metadata);
            } else if (context.kind === 'withdrawal') {
                const selected = runtime?.preparedWithdrawal;
                const plan = selected?.operationId === context.operationId ? selected
                    : records.find(record => Number(record.noteId) === Number(context.noteId)
                        && record.preparedWithdrawal?.operationId === context.operationId)?.preparedWithdrawal;
                if (!plan || !retainedClaim(plan.operationId, plan.submissionId,
                    plan.submissionFrom, plan.submissionNonce, plan.ambiguousSubmissions)
                    || Number(context.noteId) !== Number(plan.noteId ?? plan.public_inputs?.note_id)
                    || context.mode !== plan.mode || !sameAddress(context.destination, plan.destination)
                    || Number(context.finalBalance) !== Number(plan.public_inputs?.final_balance)
                    || !sameData(encodeWithdrawal(plan, plan.mode, plan.destination, funding.contract_address))) {
                    throw new Error('The external withdrawal no longer matches its saved proof.');
                }
                await browserWalletRuntime.rememberPreparedWithdrawalTransaction(hash, reference, metadata);
            } else if (['background-withdrawal', 'background-replacement'].includes(context.kind)) {
                const record = records.find(entry => entry.recordId === context.recordId
                    || (context.kind === 'background-replacement' && Number(entry.noteId) === Number(context.noteId)));
                const plan = record?.preparedWithdrawal;
                const history = [...(record?.dismissedStartSubmissionClaims || []),
                    ...(record?.supersededStartSubmissionClaims || []),
                    ...(record?.ambiguousStartReplacements || []), ...(record?.transactionAttempts || [])];
                if (!record || !plan || !retainedClaim(record.startOperationId, record.startSubmissionId,
                    record.startSubmissionFrom, record.startSubmissionNonce, history)
                    || Number(context.noteId) !== Number(record.noteId)
                    || context.mode !== plan.mode || !sameAddress(context.destination, plan.destination)
                    || Number(context.finalBalance) !== Number(plan.public_inputs?.final_balance)
                    || !sameData(encodeWithdrawal(plan, plan.mode, plan.destination, funding.contract_address))) {
                    throw new Error('The external transaction no longer matches its saved background withdrawal.');
                }
                if (context.kind === 'background-replacement') {
                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(hash, reference, metadata);
                } else {
                    await browserWalletRuntime.rememberBackgroundWithdrawalTransaction(hash, reference, metadata);
                }
            } else if (context.kind === 'finalization') {
                const record = records.find(entry => entry.recordId === context.recordId);
                const activeGeneration = Number(context.generation) === Number(record?.finalizeGeneration || 0);
                if (!record || !retainedClaim(record.finalizeOperationId,
                    activeGeneration ? record.finalizeSubmissionId : null,
                    record.finalizeSubmissionFrom, record.finalizeSubmissionNonce,
                    [...(record.ambiguousFinalizationSubmissions || []), ...(record.finalizeAttempts || [])])
                    || Number(context.noteId) !== Number(record.noteId)
                    || !sameAddress(context.destination, record.destination)
                    || !sameData(encodeFinalizeEscape(record.noteId))) {
                    throw new Error('The external transaction no longer matches its saved finalization.');
                }
                await browserWalletRuntime.rememberWithdrawalFinalization(record.recordId, hash, reference, metadata);
            } else if (context.kind === 'escape-payout-claim') {
                // A claim moves no private state and anyone may send it; keep
                // its hash so claimEscapePayout can prove the delivery.
                const record = records.find(entry => entry.recordId === context.recordId);
                if (!record || record.payoutCredited !== true
                    || !sameAddress(context.destination, record.destination)
                    || !sameData(encodeClaimEscapePayout(record.destination))) {
                    throw new Error('The external transaction no longer matches its saved escape payout claim.');
                }
                if (record.payoutClaimed !== true) await this.rememberEscapePayoutClaim(record.recordId, hash);
            } else {
                throw new Error('The external transaction has an unsupported recovery kind.');
            }
        }
        await this.ethereum.acknowledgeTransaction?.(hash);
        await this.refresh({ quiet: true });
        return { kind: context.kind, transactionHash: hash, recordId: context.recordId || null, status: 'submitted' };
    }

    async sendContractTransaction(
        from,
        to,
        data,
        onSubmitted = null,
        onPrepared = null,
        preparedNonce = null,
        externalRecovery = null,
        value = 0n,
        { exitEstimate = null } = {}
    ) {
        const normalizedPreparedNonce = preparedNonce == null
            ? null
            : Number(preparedNonce);
        if (normalizedPreparedNonce != null
            && (!Number.isSafeInteger(normalizedPreparedNonce)
                || normalizedPreparedNonce < 0)) {
            throw tagTransactionError(
                new Error('The replacement transaction nonce is invalid.'),
                'journal',
                false
            );
        }
        const transaction = {
            from,
            to,
            data,
            ...(BigInt(value) === 0n ? {} : { value: `0x${BigInt(value).toString(16)}` }),
            ...(normalizedPreparedNonce == null
                ? {}
                : { nonce: `0x${normalizedPreparedNonce.toString(16)}` })
        };
        try {
            await this.assertFundingChain();
            // MetaMask falls back to a percentage of the block limit when its
            // own simulation fails. Since Ethereum's block limit can now be
            // higher than the EIP-7825 per-transaction cap, that fallback can
            // create an invalid 21M-gas transaction. Preflight the exact call
            // and set only a bounded gas limit; MetaMask still chooses all
            // EIP-1559 fee fields and the user remains in control of the rate.
            const estimate = await this.ethereum.request({
                method: 'eth_estimateGas',
                params: [transaction]
            });
            transaction.gas = bufferedGasLimit(estimate);
        } catch (error) {
            if (error?.code === 'wrong_network'
                || error?.code === 'transaction_gas_limit_exceeded') {
                throw tagTransactionError(error, 'estimate', false);
            }
            const estimateError = contractEstimateError(error);
            if (!exitEstimate || exitEstimate.blocking?.(estimateError)) {
                throw tagTransactionError(estimateError, 'estimate', false);
            }
            // E4.5: an exit's simulation is advisory. A lagging or lying
            // wallet RPC cannot stop it: simulate through the user's exit RPC
            // when one is set, else submit with a fixed, bounded gas limit, and
            // warn; the wallet still asks the user to confirm.
            let alternative = null;
            try {
                alternative = await exitEstimate.alternative?.({ from: transaction.from, to: transaction.to,
                    data: transaction.data }) ?? null;
            } catch {
                alternative = null;
            }
            try {
                transaction.gas = alternative != null ? bufferedGasLimit(alternative) : `0x${EXIT_FALLBACK_GAS_LIMIT.toString(16)}`;
            } catch {
                transaction.gas = `0x${EXIT_FALLBACK_GAS_LIMIT.toString(16)}`;
            }
            await exitEstimate.onAdvisory?.(estimateError, { gas: transaction.gas, exitRpcEstimate: alternative });
        }
        let hash;
        try {
            await this.assertFundingChain();
        } catch (error) {
            throw tagTransactionError(error, 'network-check', false);
        }
        if (onPrepared) {
            try {
                let nonce = normalizedPreparedNonce;
                if (nonce == null) {
                    const pendingNonce = await this.ethereum.request({
                        method: 'eth_getTransactionCount',
                        params: [from, 'pending']
                    });
                    nonce = walletNonceNumber(pendingNonce);
                    if (nonce == null) {
                        throw new Error('MetaMask returned an invalid pending transaction nonce.');
                    }
                    transaction.nonce = `0x${nonce.toString(16)}`;
                }
                await onPrepared({ from: from.toLowerCase(), nonce });
            } catch (error) {
                throw tagTransactionError(error, 'journal', false);
            }
        }
        try {
            hash = await this.ethereum.request({
                method: 'eth_sendTransaction',
                params: [transaction],
                ...(typeof this.ethereum.acknowledgeTransaction === 'function'
                    ? { zkapiRecovery: this.externalRecoveryContext(externalRecovery) }
                    : {})
            });
        } catch (error) {
            if (isWalletRejection(error)) {
                throw tagTransactionError(error, 'send', false);
            }
            if (isDefinitelyPreBroadcastSendFailure(error)) {
                throw tagTransactionError(error, 'send', false);
            }
            if (contractRevertSelector(error)) {
                throw tagTransactionError(contractEstimateError(error), 'send', false);
            }
            // Some providers time out after accepting a transaction but
            // before returning its hash. Do not report that as cancellation.
            throw tagTransactionError(error, 'send', true);
        }
        try {
            if (onSubmitted) {
                await onSubmitted(hash);
                await this.ethereum.acknowledgeTransaction?.(hash);
            }
        } catch (error) {
            throw tagTransactionError(error, 'journal', true, hash);
        }
        try {
            return onSubmitted ? await this.waitForReceipt(hash)
                : await this.acknowledgeExternalTransactionReceipt(hash);
        } catch (error) {
            throw tagTransactionError(error, 'receipt', true, hash);
        }
    }

    async readDepositReceiptMetadata(plan, receipt) {
        // Fee display must use a mined transaction, never its estimated limit
        // or an unverified cached receipt. Failure only makes fees unavailable.
        try {
            if (BigInt(receipt?.status || 0) !== 1n
                || !/^0x[0-9a-fA-F]{64}$/.test(receipt.transactionHash || '')
                || !/^0x[0-9a-fA-F]{64}$/.test(receipt.blockHash || '')
                || !/^0x[0-9a-fA-F]+$/.test(receipt.blockNumber || '')) return null;
            const funding = this.config.funding;
            await this.assertFundingChain();
            const deposited = parseNoteDeposited(receipt, funding.contract_address);
            if (!deposited || deposited.noteId !== BigInt(plan.next_note_id)
                || deposited.amount !== BigInt(plan.amount)
                || BigInt(deposited.commitment) !== BigInt(plan.commitment)) return null;
            const transaction = await this.ethereum.request({ method: 'eth_getTransactionByHash',
                params: [receipt.transactionHash] });
            const hash = receipt.transactionHash.toLowerCase();
            if (!transaction || String(transaction.hash).toLowerCase() !== hash
                || String(transaction.blockHash).toLowerCase() !== receipt.blockHash.toLowerCase()
                || BigInt(transaction.blockNumber) !== BigInt(receipt.blockNumber)
                || !sameAddress(transaction.to, funding.contract_address)
                || !/^0x[0-9a-fA-F]{40}$/.test(transaction.from || '')
                || (transaction.chainId != null && BigInt(transaction.chainId) !== BigInt(funding.chain_id))
                || String(transaction.input ?? transaction.data).toLowerCase() !== encodeDeposit(plan, BigInt(plan.amount)).toLowerCase()
                || BigInt(transaction.value || 0) !== nativeDepositValue(plan.amount, funding)) return null;
            const block = await this.ethereum.request({ method: 'eth_getBlockByNumber',
                params: [receipt.blockNumber, false] });
            if (String(block?.hash).toLowerCase() !== receipt.blockHash.toLowerCase()) return null;
            await this.assertFundingChain();
            const gasUsed = BigInt(receipt.gasUsed);
            const effectiveGasPrice = BigInt(receipt.effectiveGasPrice);
            const blockNumber = Number(BigInt(receipt.blockNumber));
            if (gasUsed <= 0n || effectiveGasPrice <= 0n || !Number.isSafeInteger(blockNumber) || blockNumber <= 0) return null;
            return { transactionHash: hash, fundingAddress: transaction.from.toLowerCase(),
                feeWei: String(gasUsed * effectiveGasPrice), gasUsed: String(gasUsed),
                effectiveGasPrice: String(effectiveGasPrice), receiptBlockNumber: blockNumber,
                receiptBlockHash: receipt.blockHash.toLowerCase() };
        } catch { return null; }
    }

    async refreshConfirmedBrowserDeposit() {
        // Called only after confirmDeposit has committed the exact durable
        // pending operation. Keep refresh failures available to normal status
        // recovery without reporting a completed deposit as failed.
        try {
            // Publish the committed history and cleared pending plan even if
            // the separate worker projection of the balance is unavailable.
            const snapshot = browserWalletRuntime.snapshot();
            this.config = snapshot.config;
            this.deposits = snapshot.deposits || [];
            this.withdrawals = snapshot.withdrawals || [];
            await this.refresh({ quiet: true });
        } catch (error) {
            this.lastError = error;
        }
        return Boolean(this.lastError);
    }

    async confirmBrowserDepositReceipt(plan, receipt, vaultAddress, onStatus) {
        const deposited = parseNoteDeposited(receipt, vaultAddress);
        if (!deposited) {
            throw new Error('The transaction succeeded, but its NoteDeposited event was not found.');
        }
        if (deposited.noteId !== BigInt(plan.next_note_id)
            || deposited.amount !== BigInt(plan.amount)
            || BigInt(deposited.commitment) !== BigInt(plan.commitment)) {
            throw new Error('The mined deposit did not match this browser’s durable private note.');
        }
        const receiptMetadata = await this.readDepositReceiptMetadata(plan, receipt);
        onStatus('Saving the private note securely in this browser…');
        await browserWalletRuntime.confirmDeposit({
            operationId: plan.operationId,
            secret: plan.secret,
            note_id: Number(deposited.noteId),
            amount: Number(plan.amount),
            commitment: plan.commitment,
            transactionHash: receipt.transactionHash,
            receiptMetadata,
            expiry_ts: Number(deposited.expiryTs),
            // The root this deposit set: with its path, the note's exit path
            // for life (Amendment A1). The plan's siblings come along for a
            // note the background recovery committed first, whose pending
            // deposit (and its zero_path) is gone by then.
            deposit_root: `0x${deposited.newRoot.toString(16)}`,
            zero_path: Array.isArray(plan.zero_path) ? plan.zero_path : null
        });
        const balanceRefreshPending = await this.refreshConfirmedBrowserDeposit();
        onStatus(balanceRefreshPending
            ? 'Deposit confirmed and saved. The balance display will refresh when available.'
            : 'Private balance is ready.');
        // G1: a balance smaller than three escape fees is worth less than
        // its unilateral exit. The gas price read ends within E0's
        // CALL_TIMEOUT, so a silent wallet cannot hold the confirmation.
        const costWarning = await browserWalletRuntime.refreshExitCost({ request: request => this.ethereum.request(request) });
        if (costWarning) onStatus(exitCostMessage(costWarning));
        return {
            status: 'confirmed',
            balanceRefreshPending,
            noteId: Number(deposited.noteId),
            amount: Number(plan.amount),
            receipt,
            ...(receiptMetadata || {})
        };
    }

    async readBrowserNote(noteId, requestedBlock = 'latest') {
        await this.assertFundingChain();
        const blockTag = requestedBlock || 'latest';
        const encoded = await this.ethereum.request({
            method: 'eth_call',
            params: [{
                to: this.config.funding.contract_address,
                data: callData(ABI.notes, [abiWord(noteId)])
            }, blockTag]
        });
        const words = String(encoded || '').replace(/^0x/, '').match(/.{64}/g) || [];
        if (words.length < 4) throw new Error('The vault returned a truncated note record.');
        return {
            noteId: Number(noteId),
            commitment: `0x${words[0]}`,
            amount: BigInt(`0x${words[1]}`),
            expiryTs: Number(BigInt(`0x${words[2]}`)),
            status: Number(BigInt(`0x${words[3]}`)),
            observedBlock: /^0x[0-9a-fA-F]+$/.test(String(blockTag))
                ? Number(BigInt(blockTag))
                : null
        };
    }

    async recoverBrowserDeposit(onStatus = () => {}) {

        const plan = await browserWalletRuntime.pendingDeposit();
        if (!plan) return null;
        onStatus('Checking the private-vault deposit…');
        const note = await this.readBrowserNote(plan.next_note_id);
        const matches = note.status !== 0
            && note.amount === BigInt(plan.amount)
            && BigInt(note.commitment) === BigInt(plan.commitment);
        if (matches) {
            if (note.status !== 1) {
                throw new Error('The recovered deposit exists, but its private note is no longer active.');
            }
            // Wait for the privacy-preserving whole-tree mirror before making
            // the recovered note available to chat requests.
            await browserWalletRuntime.treePath(Number(plan.next_note_id), true);
            let receiptMetadata = null;
            let confirmedReceipt = null;
            const hashes = plan.transactionHashes || (plan.transactionHash ? [plan.transactionHash] : []);
            for (const hash of hashes) {
                try {
                    const candidate = await this.ethereum.request({ method: 'eth_getTransactionReceipt', params: [hash] });
                    if (String(candidate?.transactionHash).toLowerCase() !== String(hash).toLowerCase()) continue;
                    receiptMetadata = await this.readDepositReceiptMetadata(plan, candidate);
                    if (receiptMetadata) { confirmedReceipt = candidate; break; }
                } catch { /* Vault recovery remains available when fee evidence is temporarily unavailable. */ }
            }
            const recoveredDeposit = confirmedReceipt
                ? parseNoteDeposited(confirmedReceipt, this.config.funding.contract_address) : null;
            await browserWalletRuntime.confirmDeposit({
                operationId: plan.operationId,
                secret: plan.secret,
                note_id: Number(plan.next_note_id),
                amount: Number(plan.amount),
                commitment: plan.commitment,
                transactionHash: receiptMetadata?.transactionHash || null,
                receiptMetadata,
                expiry_ts: note.expiryTs,
                ...(recoveredDeposit && recoveredDeposit.noteId === BigInt(plan.next_note_id)
                    ? { deposit_root: `0x${recoveredDeposit.newRoot.toString(16)}` } : {})
            });
            const balanceRefreshPending = await this.refreshConfirmedBrowserDeposit();
            onStatus(balanceRefreshPending
                ? 'Deposit recovered and saved. The balance display will refresh when available.'
                : 'Deposit recovered. Your private balance is ready.');
            return {
                status: 'confirmed',
                balanceRefreshPending,
                noteId: Number(plan.next_note_id),
                amount: Number(plan.amount),
                receipt: confirmedReceipt,
                ...(receiptMetadata || {})
            };
        }
        if (note.status !== 0) {
            const conflictFinality = await this.browserDepositSlotConflictFinality(plan);
            if (!conflictFinality.finalized) {
                await this.refresh({ quiet: true });
                onStatus('Another deposit currently occupies this slot. Waiting for chain finality before retrying safely.');
                return { status: 'slot_conflict_unconfirmed' };
            }
            // The exact append slot was consumed by a different commitment;
            // this plan can no longer succeed, so rebasing it is now safe.
            await browserWalletRuntime.resolvePendingDepositSlotConflict({
                operationId: plan.operationId,
                noteId: Number(plan.next_note_id),
                amount: Number(plan.amount),
                commitment: plan.commitment,
                phase: plan.phase || null,
                submissionId: plan.submissionId || null,
                transactionHashes: Array.isArray(plan.transactionHashes)
                    ? plan.transactionHashes
                    : plan.transactionHash ? [plan.transactionHash] : []
            });
            await this.refresh({ quiet: true });
            onStatus('The old deposit slot was used by another transaction. The deposit is ready to retry safely.');
            return { status: 'slot_consumed' };
        }

        const hashes = Array.isArray(plan.transactionHashes)
            ? plan.transactionHashes
            : plan.transactionHash ? [plan.transactionHash] : [];
        let pendingHash = null;
        const missingReceiptHashes = [];
        for (const hash of hashes) {
            let receipt = null;
            try {
                receipt = await this.ethereum.request({
                    method: 'eth_getTransactionReceipt',
                    params: [hash]
                });
            } catch {
                // A replacement/cancel can make the original hash disappear.
                // Resolve it only from finalized nonce + empty-slot evidence.
            }
            if (!receipt) {
                const transactionAttempt = (plan.transactionAttempts || []).find(attempt =>
                    String(attempt.hash || '').toLowerCase() === String(hash).toLowerCase());
                const nonceStatus = await this.browserDepositNonceConsumed(
                    transactionAttempt,
                    Number(plan.next_note_id)
                );
                if (nonceStatus.consumed) {
                    await browserWalletRuntime.markPendingDepositRetryable(hash);
                } else {
                    pendingHash = pendingHash || hash;
                    missingReceiptHashes.push(hash);
                }
            } else if (BigInt(receipt.status || '0x0') !== 1n) {
                const finality = await this.browserRevertedReceiptFinality(hash, receipt);
                if (finality.finalized) {
                    await browserWalletRuntime.markPendingDepositRetryable(hash);
                } else {
                    // A status-0 receipt can disappear in a short reorg and
                    // later become a successful canonical deposit. Retain its
                    // exact WAL until the revert itself is finalized.
                    pendingHash = pendingHash || hash;
                }
            } else {
                throw new Error('The deposit transaction mined, but the latest vault read has not caught up yet. Check again shortly.');
            }
        }
        if (!pendingHash && plan.submissionId && plan.submissionFrom
            && Number.isSafeInteger(Number(plan.submissionNonce))) {
            const nonceStatus = await this.browserDepositNonceConsumed({
                from: plan.submissionFrom,
                nonce: Number(plan.submissionNonce)
            }, Number(plan.next_note_id));
            if (nonceStatus.consumed) {
                await browserWalletRuntime.markPendingDepositRetryable(null, {
                    operationId: plan.operationId,
                    submissionId: plan.submissionId,
                    noteId: Number(plan.next_note_id),
                    amount: Number(plan.amount),
                    commitment: plan.commitment,
                    deploymentId: browserWalletRuntime.manifest?.deployment_id,
                    chainId: Number(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                });
            }
        }
        await this.refresh({ quiet: true });
        if (pendingHash) {
            const current = await browserWalletRuntime.pendingDeposit();
            const currentHashes = Array.isArray(current?.transactionHashes)
                ? current.transactionHashes
                : current?.transactionHash ? [current.transactionHash] : [];
            const missingSet = new Set(missingReceiptHashes.map(hash => hash.toLowerCase()));
            const allReceiptsMissing = currentHashes.length > 0
                && currentHashes.every(hash => missingSet.has(hash.toLowerCase()));
            let marked = current;
            if (allReceiptsMissing) {
                marked = await browserWalletRuntime.markPendingDepositMissingReceipts(
                    currentHashes
                );
                await this.refresh({ quiet: true });
            }
            const hashSet = new Set(currentHashes.map(hash => String(hash).toLowerCase()));
            const replacementIdentities = new Set((marked?.transactionAttempts || [])
                .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
                    && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    && Number.isSafeInteger(Number(attempt.nonce))
                    && Number(attempt.nonce) >= 0)
                .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
            return {
                status: allReceiptsMissing ? 'dropped_or_pending' : 'submitted',
                transactionHash: pendingHash,
                replacement_available: allReceiptsMissing
                    && replacementIdentities.size === 1
                    && !marked?.submissionId
            };
        }
        const current = await browserWalletRuntime.pendingDeposit();
        return {
            status: current?.phase === 'ambiguous'
                ? 'ambiguous'
                : current?.phase || 'prepared'
        };
    }

    async recoverUnknownDeposit(onStatus = () => {}) {

        await browserWalletRuntime.markPendingDepositUnknown();
        await this.refresh();
        onStatus('The old wallet prompt was marked unresolved. Check the vault before retrying.');
        return this.config?.pending_deposit || null;
    }

    async prepareDepositRetry(onStatus = () => {}) {
        if (!this.isNativeEthFunding) {
            throw new Error('Funding-address retry quotes require a native ETH browser wallet.');
        }
        const recovery = await this.recoverBrowserDeposit(onStatus);
        if (recovery?.status === 'confirmed') return recovery;
        const pending = await browserWalletRuntime.pendingDeposit();
        if (pending?.phase === 'prepared' && browserWalletRuntime.canQuotePendingDeposit(pending)) {
            await this.refresh({ quiet: true });
            return { status: 'prepared', operationId: pending.operationId };
        }
        const retry = await browserWalletRuntime.authorizePendingDepositRetry({ forFundingQuote: true });
        await this.refresh({ quiet: true });
        onStatus('Review the network fee for the saved deposit before continuing.');
        return { status: 'retry_exact', operationId: retry.operationId };
    }

    async retryUnknownDeposit(onStatus = () => {}) {

        const recovery = await this.recoverBrowserDeposit(onStatus);
        if (recovery?.status === 'confirmed') return recovery;
        const pending = await browserWalletRuntime.pendingDeposit();
        if (pending?.phase !== 'ambiguous') {
            throw new Error('There is no unresolved deposit request to retry.');
        }
        await browserWalletRuntime.authorizePendingDepositRetry();
        await this.refresh({ quiet: true });
        onStatus('Retry authorized. Opening the same deposit in MetaMask…');
        return this.deposit(this.formatBillingAmount(pending.amount), onStatus);
    }

    async retryDroppedDeposit(onStatus = () => {}) {

        const current = await browserWalletRuntime.pendingDeposit();
        if (!current || current.phase !== 'dropped_or_pending') {
            throw new Error('Check the submitted deposit before replacing it.');
        }
        onStatus('Connecting to the MetaMask account that submitted this deposit…');
        const from = await this.connectWallet();
        const submission = await browserWalletRuntime.claimPendingDepositReplacement(from);
        const plan = submission.plan;
        let submittedHash = null;
        let submissionMetadata = {
            from: submission.replacementFrom,
            nonce: Number(submission.replacementNonce)
        };
        let receipt;
        try {
            onStatus('Confirm the exact same deposit in MetaMask. It reuses the original nonce, so only one version can execute.');
            receipt = await this.sendContractTransaction(
                from,
                this.config.funding.contract_address,
                encodeDeposit(plan, BigInt(plan.amount)),
                async hash => {
                    submittedHash = hash;
                    await browserWalletRuntime.rememberPendingDepositTransaction(
                        hash,
                        submission,
                        submissionMetadata
                    );
                    onStatus(`Deposit replacement submitted ${this.compact(hash)} · checking confirmation…`);
                },
                async metadata => {
                    submissionMetadata = metadata;
                    await browserWalletRuntime.rememberPendingDepositSubmissionMetadata(
                        submission,
                        metadata
                    );
                },
                submission.replacementNonce,
                { kind: 'deposit', submission },
                nativeDepositValue(plan.amount, this.config.funding)
            );
        } catch (error) {
            if (error?.transactionHash) {
                submittedHash = error.transactionHash;
                try {
                    await browserWalletRuntime.rememberPendingDepositTransaction(
                        submittedHash,
                        submission,
                        submissionMetadata
                    );
                } catch (journalError) {
                    error.journalRecoveryError = journalError;
                }
            } else {
                await browserWalletRuntime.releasePendingDepositReplacementClaim(
                    submission,
                    error?.message || 'MetaMask did not return a deposit replacement transaction ID.'
                );
                error.shortMessage = error?.broadcastPossible === false || isWalletRejection(error)
                    ? 'The deposit replacement was canceled before broadcast. The original transaction remains saved and can be replaced again.'
                    : 'MetaMask did not return a replacement transaction ID. The original deposit remains saved, and you can safely resubmit it with the same nonce.';
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        return this.confirmBrowserDepositReceipt(
            plan,
            receipt,
            this.config.funding.contract_address,
            onStatus
        );
    }

    async deposit(amountInput, onStatus = () => {}, { preparedOperationId = null } = {}) {
        const key = JSON.stringify([String(amountInput).trim(), preparedOperationId]);
        if (this.depositPromise) {
            if (this.depositPromiseKey === key) return this.depositPromise;
            throw new Error('A different deposit action is already running.');
        }
        const operation = this.performDeposit(amountInput, onStatus, { preparedOperationId });
        this.depositPromise = operation;
        this.depositPromiseKey = key;
        try {
            return await operation;
        } finally {
            if (this.depositPromise === operation) {
                this.depositPromise = null;
                this.depositPromiseKey = null;
            }
        }
    }

    /**
     * On a deployment the pinned profile closed to deposits, refuse before any
     * chain read or wallet prompt unless a deposit was already started (it
     * stays completable and recoverable). The runtime enforces the same rule
     * under its wallet lock.
     */
    async assertDepositMayStart() {
        if (browserWalletRuntime.depositsClosed() && !(await browserWalletRuntime.pendingDeposit())) {
            throw browserWalletRuntime.depositsClosedError();
        }
    }

    async performDeposit(amountInput, onStatus = () => {}, { preparedOperationId = null } = {}) {
        await this.ensureTestnetAccess({ interactive: true });
        if (this.hasNote) throw new Error('This client already has an active private note.');
        await this.assertDepositMayStart();
        const funding = this.config?.funding;
        validateNativeFunding(funding);
        await assertNativeVault(funding);
        onStatus('Connecting to MetaMask…');
        const address = await this.connectWallet();
        const amount = parseUnits(amountInput, 9);
        if (amount <= 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error('Choose a smaller positive deposit amount.');
        }

        const vaultAddress = funding.contract_address;
        let pendingDeposit = await browserWalletRuntime.pendingDeposit();
        if (pendingDeposit) {
            if (preparedOperationId && pendingDeposit.operationId !== preparedOperationId) {
                throw new Error('The deposit quote changed in another tab. Check the pending deposit before continuing.');
            }
            const recovery = await this.recoverBrowserDeposit(onStatus);
            if (recovery?.status === 'confirmed') return recovery;
            pendingDeposit = await browserWalletRuntime.pendingDeposit();
            if (Number(pendingDeposit.amount) !== Number(amount)) {
                throw new Error('A previous deposit is unfinished. Recover or cancel its MetaMask prompt before changing the amount.');
            }
            if (recovery?.status === 'submitted') {
                throw new Error(`Deposit ${this.compact(recovery.transactionHash)} is still waiting for confirmation.`);
            }
            if (pendingDeposit.phase === 'awaiting_wallet') {
                throw new Error('This deposit may still be open in MetaMask. Check its status or mark the prompt closed.');
            }
            if (pendingDeposit.phase === 'ambiguous') {
                throw new Error('MetaMask did not return a deposit transaction ID. Check its status before explicitly retrying the same deposit.');
            }
        }
        const balance = BigInt(await this.ethereum.request({ method: 'eth_getBalance', params: [address, 'latest'] }));
        if (balance < nativeDepositValue(amount, funding)) throw new Error('Your wallet needs more ETH for this deposit and its network fee.');
        // Design §6.5: the deployment pins, through the provider that will
        // sign and through the pinned RPC, and the canary caps, before every
        // deposit. A mismatch refuses the deposit; exits stay allowed.
        onStatus('Verifying the vault deployment…');
        const provider = this.ethereum;
        await browserWalletRuntime.verifyDeploymentForDeposit({
            walletRequest: args => provider.request(args),
            depositWei: nativeDepositValue(amount, funding)
        });

        onStatus('Generating the private note commitment locally…');
        let plan = await browserWalletRuntime.prepareDeposit(Number(amount), { preparedOperationId });

        let receipt;
        let submission = null;
        let submissionMetadata = null;
        const attempts = 3;
        for (let attempt = 0; attempt < attempts; attempt += 1) {
            if (plan.phase !== 'retry_exact') {
                onStatus(attempt === 0
                    ? 'Checking the latest private-vault state…'
                    : 'The vault changed. Refreshing the deposit before retrying…');
                const expectedActiveRoot = await this.readContractUint(
                    vaultAddress,
                    `0x${ABI.currentRoot}`
                );
                plan = await browserWalletRuntime.refreshPendingDeposit(
                    Number(amount),
                    expectedActiveRoot,
                    { expectedOperationId: plan.operationId }
                );
            }
            submission = await browserWalletRuntime.claimPendingDepositSubmission(plan.operationId);
            // Another read-only preparation can refresh the append path;
            // send exactly the plan frozen by the atomic submission claim.
            if (submission.plan) plan = submission.plan;
            if (submission.transactionHash) {
                onStatus(`Checking submitted deposit ${this.compact(submission.transactionHash)}…`);
                receipt = await this.waitForReceipt(submission.transactionHash);
                break;
            }
            onStatus('Depositing into the private-note vault… confirm in MetaMask.');
            try {
                receipt = await this.sendContractTransaction(
                    address,
                    vaultAddress,
                    encodeDeposit(plan, amount),
                    async hash => {
                            await browserWalletRuntime.rememberPendingDepositTransaction(
                                hash,
                                submission,
                                submissionMetadata
                            );
                            onStatus(`Deposit submitted ${this.compact(hash)} · waiting for confirmation…`);
                        },
                    async metadata => {
                            submissionMetadata = metadata;
                            await browserWalletRuntime.rememberPendingDepositSubmissionMetadata(
                                submission,
                                metadata
                            );
                        },
                    null,
                    { kind: 'deposit', submission },
                    nativeDepositValue(amount, funding)
                );
                break;
            } catch (error) {
                if (!error?.transactionHash && submission) {
                    if (error?.broadcastPossible === false || isWalletRejection(error)) {
                        await browserWalletRuntime.markPendingDepositRetryable(null, submission);
                    } else if (error?.broadcastPossible === true) {
                        await browserWalletRuntime.markPendingDepositAmbiguous(
                            submission,
                            error?.message || 'MetaMask did not return a transaction ID.'
                        );
                        error.shortMessage = 'MetaMask did not return a deposit transaction ID. Check the deposit status before retrying.';
                    }
                } else if (error?.transactionHash) {
                    try {
                        await browserWalletRuntime.rememberPendingDepositTransaction(
                            error.transactionHash,
                            submission,
                            submissionMetadata
                        );
                    } catch (journalError) {
                        error.journalRecoveryError = journalError;
                    }
                }
                await this.refresh({ quiet: true });
                if (error?.code !== 'stale_root' || attempt + 1 >= attempts) throw error;
                const recovery = await this.recoverBrowserDeposit(onStatus);
                if (recovery?.status === 'confirmed') return recovery;
                plan = await browserWalletRuntime.pendingDeposit();
                submission = null;
                submissionMetadata = null;
            }
        }
        return this.confirmBrowserDepositReceipt(plan, receipt, vaultAddress, onStatus);
    }

    /**
     * Withdraw the selected balance. `mode` 'mutual' asks for a cooperative
     * close where the exit rules allow one (design §6.4 E2); the rules may
     * turn it into an escape. 'escape' exits unilaterally now. `concede`
     * ('zero', the default, or 'bound') is the concession of an escape
     * forced before its settlement time T (E3).
     */
    async withdraw(mode, onStatus = () => {}, {
        destination,
        concede = 'zero',
        fees = 'wallet',
        feeCapWei = null,
        bundlerUrl = null,
        allowExpensiveGas = false,
        selfBundle = false
    } = {}) {
        // The password dialog must not transfer an earlier withdrawal click
        // to a successor note installed by another tab while it was open.
        const expectedNoteId = this.note?.note_id;
        // Unilateral escape remains independent of the service credential.
        // Only cooperative withdrawal requests the server's authorization.
        if (mode === 'mutual') await this.ensureTestnetAccess({ interactive: true });
        if (this.note?.note_id !== expectedNoteId) {
            throw new Error('The private balance changed while withdrawal was opening. Review the current balance before continuing.');
        }
        const requestedDestination = normalizeWithdrawalDestination(destination, this.config?.funding);
        if (!['zero', 'bound'].includes(concede)) throw new TypeError('Choose zero or bound for a forced escape.');
        // `fees: 'payout'` pays the network fee from the payout through the
        // withdrawal paymaster (design §3.2); 'wallet' is today's path.
        if (!['wallet', 'payout'].includes(fees)) throw new TypeError('Choose wallet or payout for the withdrawal fees.');
        const operationKey = `${mode}:${requestedDestination || ''}:${concede}${fees === 'payout' ? ':payout' : ''}`;
        if (this.withdrawPromise) {
            if (this.withdrawPromiseKey === operationKey) return this.withdrawPromise;
            throw new Error('A different withdrawal action is already running.');
        }
        const options = { destination, concede, fees, feeCapWei, bundlerUrl, allowExpensiveGas, selfBundle };
        const operation = (async () => {
            try {
                return await this.performWithdrawal(mode, onStatus, options);
            } catch (error) {
                // The escape gate contacts the server only at a state already
                // sent with a private request; its Sepolia password prompt
                // then belongs to this explicit action.
                if (mode !== 'escape' || error?.code !== 'testnet_password_required') {
                    throw withdrawalErrorWithMessage(error);
                }
                await this.ensureTestnetAccess({ interactive: true });
                if (this.note?.note_id !== expectedNoteId) {
                    throw new Error('The private balance changed while withdrawal was opening. Review the current balance before continuing.');
                }
                try {
                    return await this.performWithdrawal(mode, onStatus, options);
                } catch (retryError) {
                    throw withdrawalErrorWithMessage(retryError);
                }
            }
        })();
        this.withdrawPromise = operation;
        this.withdrawPromiseKey = operationKey;
        try {
            return await operation;
        } finally {
            if (this.withdrawPromise === operation) {
                this.withdrawPromise = null;
                this.withdrawPromiseKey = null;
            }
        }
    }

    async performWithdrawal(mode, onStatus = () => {}, {
        destination: requested,
        concede = 'zero',
        fees = 'wallet',
        feeCapWei = null,
        bundlerUrl = null,
        allowExpensiveGas = false,
        selfBundle = false
    } = {}) {
        const requestedDestination = normalizeWithdrawalDestination(requested, this.config?.funding);
        const note = this.note;
        if (!note) throw new Error('There is no active private note to withdraw.');
        if (!['mutual', 'escape'].includes(mode)) throw new Error('Choose a valid withdrawal mode.');
        if (!['wallet', 'payout'].includes(fees)) throw new TypeError('Choose wallet or payout for the withdrawal fees.');
        await this.assertBalanceNotClaimed(note.note_id);

        onStatus('Connecting to MetaMask…');
        const from = await this.connectWallet();
        if (fees === 'payout') {
            // The sponsored path (design §3.2) branches here: the plan is
            // bound to a transit account, every read goes to the read RPC and
            // no transaction is ever sent from the wallet.
            return this.performGaslessWithdrawal(mode, onStatus, {
                requestedDestination, concede, feeCapWei, bundlerUrl, allowExpensiveGas, selfBundle, from, note,
                durablePrepared: await browserWalletRuntime.currentPreparedWithdrawal()
            });
        }
        // G1: warn when this balance returns less than three escape fees.
        // The gas price read is advisory and never delays the exit: the
        // warning is shown when the read completes.
        void browserWalletRuntime.refreshExitCost({ request: request => this.ethereum.request(request) })
            .then(costWarning => {
                if (costWarning) onStatus(exitCostMessage(costWarning));
            }, () => {});
        // MetaMask connection can outlive a cross-tab update. Re-read the
        // durable plan under the wallet lock instead of trusting the UI/config
        // snapshot that existed before the prompt opened.
        const durablePrepared = await browserWalletRuntime.currentPreparedWithdrawal();
        // A sponsored plan paid from a wallet after all (the direct-call
        // fallback of §3.1) keeps its destination, the transit account: the
        // payout then waits there for sweepTransit.
        const sponsoredPlan = isGaslessWithdrawal(durablePrepared);
        const prepared = durablePrepared
            ? {
                mode: durablePrepared.mode,
                phase: durablePrepared.phase,
                destination: durablePrepared.destination,
                transaction_hash: durablePrepared.transactionHash || null,
                clearance_reserved: durablePrepared.clearanceReserved === true
                    || durablePrepared.mode === 'mutual'
            }
            : this.config?.prepared_withdrawal;
        if (prepared?.transaction_hash) mode = prepared.mode;
        // A sponsored plan's vault destination is its transit account S; the
        // host names the payout address Y it chose for the sponsored attempt
        // (design §3.2), so the guard compares Y (S itself is accepted too).
        // The transaction still pays S.
        const boundDestinations = sponsoredPlan
            ? [durablePrepared.payout, durablePrepared.destination].filter(Boolean).map(address => String(address).toLowerCase())
            : [String(prepared?.destination || '').toLowerCase()];
        if (requestedDestination && prepared?.destination
            && !boundDestinations.includes(requestedDestination)) {
            throw new Error('This withdrawal is already bound to a different destination. Resume it with its saved address.');
        }
        // The connected account only pays gas. A resumed plan keeps its
        // original payout destination, so recovery remains permissionless and
        // a harmless account switch cannot strand the note.
        const destination = prepared?.destination || requestedDestination || from;

        const withdrawal = {
            phase: 'prepared',
            mode,
            noteId: Number(note.note_id),
            destination
        };

        let plan;
        let receipt;
        let submittedHash = prepared?.transaction_hash || null;
        let submission = null;
        let submissionMetadata = null;
        // The vault accepts any root it ever held and exits carry no Merkle
        // path, so a saved proof is reused until its valid_until (E4.7). An
        // expired proof or UnknownRoot() re-proves.
        const withdrawalAttempts = 4;
        let reprove = false;
        // After UnknownRoot the next proof takes its path at any other root:
        // the indexer checked against the vault, or the vault's logs (E4.1,
        // §6.6), never the refused one. The wallet provider is read before
        // the pinned RPC when no exit RPC is set.
        let refusedRoot = null;
        const walletRequest = request => this.ethereum.request(request);
        // A simulation refusal re-proves once per reason; after that it only
        // warns (E4.5).
        const reproved = new Set();
        // An escape's destination is fixed once its proof exists. Before
        // proving, check the vault's payout push to it: a destination that
        // rejects ETH is only credited, which anyone can claim for it later.
        let destinationWarning = null;
        if (mode === 'escape' && !submittedHash) {
            try {
                // A zero balance is never pushed. Otherwise a nominal value
                // keeps the balance out of this read.
                const destinationCheck = await this.checkEscapeDestination(destination, {
                    finalBalance: Number(note.current_balance) > 0 ? 1 : 0
                });
                destinationWarning = destinationCheck?.warning || null;
            } catch (error) {
                if (error?.code === 'wrong_network') throw error;
            }
            if (destinationWarning) onStatus(destinationWarning);
        }
        try {
            if (submittedHash) {
                // A broadcast hash owns recovery. Never read a new root or
                // replace its proof while the receipt is unknown: doing so can
                // sever the only durable link to a transaction already in the
                // mempool.
                plan = durablePrepared;
                if (!plan?.public_inputs) {
                    throw new Error('The submitted withdrawal proof is missing from this browser.');
                }
                onStatus(`Checking submitted transaction ${this.compact(submittedHash)}…`);
                receipt = await this.waitForReceipt(submittedHash);
            } else for (let attempt = 0; attempt < withdrawalAttempts; attempt += 1) {
                onStatus(attempt === 0
                    ? (mode === 'mutual'
                        ? 'Checking this balance and requesting a cooperative close…'
                        : 'Preparing a unilateral escape locally…')
                    : 'The withdrawal proof expired or the vault refused its root. Proving again…');
                const expectedActiveRoot = mode === 'mutual'
                    ? await this.readContractUint(this.config.funding.contract_address, `0x${ABI.currentRoot}`)
                    : null;
                try {
                    plan = await browserWalletRuntime.prepareWithdrawal(mode, destination, {
                        expectedActiveRoot,
                        reprove,
                        earlyConcession: concede,
                        walletRequest,
                        ...(refusedRoot != null ? { refusedRoot } : {}),
                        onProgress: (_phase, message) => onStatus(message)
                    });
                } catch (error) {
                    // E4.5 is advisory: when no path at another root can be
                    // found after UnknownRoot, the proof that exists is
                    // submitted anyway (its refusal then only warns).
                    if (refusedRoot == null || error?.data?.exit_path_unavailable !== true
                        || attempt + 1 >= withdrawalAttempts) throw error;
                    onStatus(`No Merkle path at another root was found (${error.message}). The existing proof is submitted anyway; if the vault does not know its root, the transaction reverts and costs only gas.`);
                    refusedRoot = null;
                    reprove = false;
                    continue;
                }
                for (const warning of plan.warnings || []) {
                    if (warning?.message) onStatus(`${warning.message} It can still be submitted.`);
                }
                if (Number(plan.public_inputs?.note_id) !== Number(note.note_id)) {
                    throw new Error('The private wallet returned a withdrawal for a different note.');
                }
                if (plan.mode !== mode) {
                    // E2: the exit rules turned a mutual request into an escape.
                    onStatus(plan.decision?.clearance_error_code
                        ? 'The server did not grant a cooperative close, so this balance exits by escape, conceding nothing.'
                        : 'This balance exits by escape.');
                    mode = plan.mode;
                    withdrawal.mode = mode;
                }
                submittedHash = plan.transactionHash || submittedHash;
                this.rememberWithdrawal({
                    ...withdrawal,
                    phase: submittedHash ? 'submitted' : 'prepared',
                    transactionHash: submittedHash,
                    clearanceReserved: plan.clearanceReserved === true || mode === 'mutual'
                });
                if (this.config) {
                    this.config.prepared_withdrawal = {
                        mode,
                        phase: submittedHash ? 'submitted' : 'prepared',
                        note_id: withdrawal.noteId,
                        destination,
                        transaction_hash: submittedHash,
                        clearance_reserved: plan.clearanceReserved === true || mode === 'mutual',
                        clearance_granted: mode === 'mutual' && Boolean(plan.clearance?.signature)
                    };
                }
                const calldata = encodeWithdrawal(
                    plan,
                    mode,
                    destination,
                    this.config.funding.contract_address,
                    { conceded: plan.public_inputs.conceded }
                );
                const claim = await browserWalletRuntime.claimPreparedWithdrawalSubmission();
                submission = claim;
                submittedHash = claim.transactionHash || submittedHash;
                if (submittedHash) {
                    onStatus(`Checking submitted transaction ${this.compact(submittedHash)}…`);
                    receipt = await this.waitForReceipt(submittedHash);
                    break;
                }
                // E4.6: one more bounded recovery pass before broadcast. A
                // successor that arrives now is archived until the exit ends.
                const late = await browserWalletRuntime.exitBeforeBroadcast().catch(() => null);
                if (late?.lateSuccessor) {
                    onStatus('A settled private request arrived after the exit proof was made. It is kept and applied if this exit expires unused.');
                }
                onStatus(mode === 'mutual'
                    ? 'Confirm the mutual close in MetaMask…'
                    : 'Confirm the escape-hatch start in MetaMask…');
                try {
                    receipt = await this.sendContractTransaction(
                        from,
                        this.config.funding.contract_address,
                        calldata,
                        async hash => {
                                submittedHash = hash;
                                await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                                    hash,
                                    submission,
                                    submissionMetadata
                                );
                                const metadata = await this.submittedTransactionMetadata(hash, from);
                                if (metadata) {
                                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                                        hash,
                                        submission,
                                        metadata
                                    );
                                }
                                this.rememberWithdrawal({
                                    ...withdrawal,
                                    phase: 'submitted',
                                    transactionHash: hash,
                                    clearanceReserved: plan.clearanceReserved === true || mode === 'mutual'
                                });
                                onStatus(`Withdrawal submitted ${this.compact(hash)} · waiting for confirmation…`);
                            },
                        async metadata => {
                                submissionMetadata = metadata;
                                await browserWalletRuntime.rememberPreparedWithdrawalSubmissionMetadata(
                                    submission,
                                    metadata
                                );
                            },
                        null,
                        { kind: 'withdrawal', submission },
                        0n,
                        {
                            exitEstimate: {
                                blocking: error => REPROVABLE_EXIT_ERRORS.includes(error?.code)
                                    && !reproved.has(error.code) && attempt + 1 < withdrawalAttempts,
                                alternative: transaction => browserWalletRuntime.exitRpcEstimateGas(transaction),
                                onAdvisory: (error, { exitRpcEstimate }) => onStatus(exitRpcEstimate != null
                                    ? `Your wallet’s simulation refused this ${mode === 'mutual' ? 'close' : 'escape'} (${error.message}), but your exit RPC accepts it. It is submitted with that estimate.`
                                    : `Your wallet’s simulation refused this ${mode === 'mutual' ? 'close' : 'escape'} (${error.message}). It can still be submitted, with a fixed gas limit; if the refusal is right, the transaction reverts and costs only gas.`)
                            }
                        }
                    );
                    break;
                } catch (error) {
                    // A proof past its valid_until (E4.7) or a root the vault
                    // does not know is proved again: another release.
                    const reprovable = REPROVABLE_EXIT_ERRORS.includes(error?.code);
                    if (!reprovable || attempt + 1 >= withdrawalAttempts) throw error;
                    reproved.add(error.code);
                    if (error.code === 'unknown_root') refusedRoot = plan.public_inputs.active_root;
                    await browserWalletRuntime.markPreparedWithdrawalRetryable(null, submission);
                    submission = null;
                    submissionMetadata = null;
                    reprove = true;
                }
            }
        } catch (failure) {
            const error = normalizeWalletError(failure);
            const recoveredReceipt = await this.recoverFailedWithdrawalSubmission({
                mode,
                error,
                submittedHash,
                submission,
                submissionMetadata,
                from
            });
            // A polling failure can race mining. Recovery reads the saved
            // hash again; a successful receipt must continue through the
            // exact same event/identity and canonical-vault checks below.
            if (recoveredReceipt && BigInt(recoveredReceipt.status || '0x0') === 1n) {
                receipt = recoveredReceipt;
            }
            if (!receipt) throw error;
        }
        const event = parseWithdrawalReceipt(receipt, this.config.funding.contract_address, mode);
        if (!event || event.noteId !== BigInt(note.note_id)
            || event.destination.toLowerCase() !== destination.toLowerCase()
            || event.finalBalance !== BigInt(plan.public_inputs.final_balance)) {
            throw new Error('The transaction succeeded, but its withdrawal event did not match the prepared note.');
        }
        if (mode === 'escape' && event.concession
            && (event.concession.conceded !== BigInt(plan.public_inputs.conceded)
                || event.concession.stateBalance !== BigInt(plan.public_inputs.final_balance) + BigInt(plan.public_inputs.conceded)
                || event.concession.nextNullifier !== BigInt(plan.public_inputs.next_nullifier))) {
            throw new Error('The transaction succeeded, but its recorded concession did not match the prepared escape.');
        }

        onStatus('Confirming the vault state and updating this browser…');
        const confirmed = await this.confirmMinedWithdrawalStatus(Number(note.note_id), receipt);
        if (mode === 'mutual') {
            if (confirmed.status !== 'closed') {
                throw new Error(`The vault still reports this private balance as ${confirmed.status}.`);
            }
            await browserWalletRuntime.detachClosedWithdrawal({
                mode: 'mutual',
                payoutVerified: true,
                noteId: Number(note.note_id),
                destination,
                finalBalance: Number(event.finalBalance),
                transactionHash: submittedHash || receipt?.transactionHash || null,
                closeBlockNumber: Number(BigInt(receipt?.blockNumber || '0x0')),
                lastObservedBlock: Number(confirmed.observed_block || 0),
                clearanceReserved: true,
                createdAt: plan.createdAt,
                // Paid from a wallet to a transit account: the payout sits in
                // the transit account until sweepTransit forwards it.
                ...(sponsoredPlan ? { payoutVerified: false, fundsWaitingInTransit: true,
                    transitBalanceWei: event.finalBalance * NATIVE_WEI_PER_UNIT } : {})
            });
            this.rememberWithdrawal(null);
            await this.refresh();
            onStatus(sponsoredPlan
                ? `Withdrawal closed to its transit account. ${await this.transitFundsMessage(durablePrepared)}`
                : 'Withdrawal returned. Finality is being checked safely in the background.');
            return { status: 'closed', event, receipt, ...(sponsoredPlan ? { fundsWaitingInTransit: true, transitAccount: destination } : {}) };
        }

        const deadline = Number(confirmed.challenge_deadline || event.challengeDeadline);
        if (confirmed.status !== 'pending_withdrawal' || !deadline) {
            throw new Error('The escape transaction mined, but the vault did not report its safety deadline.');
        }
        const record = await browserWalletRuntime.detachEscapeWithdrawal({
            noteId: Number(note.note_id),
            destination,
            finalBalance: Number(event.finalBalance),
            challengeDeadline: deadline,
            transactionHash: submittedHash || receipt?.transactionHash || null,
            startBlockNumber: Number(BigInt(receipt?.blockNumber || '0x0')),
            lastObservedBlock: Number(confirmed.observed_block || 0),
            createdAt: plan.createdAt
        });
        this.rememberWithdrawal(null);
        await this.refresh();
        onStatus(destinationWarning
            ? `Escape started. ${destinationWarning}`
            : 'Escape started. You can add a new private balance while the safety window runs.');
        return {
            status: 'pending_withdrawal',
            deadline,
            event,
            receipt,
            recordId: record.recordId,
            conceded: BigInt(plan.public_inputs.conceded),
            decision: plan.decision || null,
            // Where the proof's Merkle path came from (E4.1): the saved
            // deposit-time path, the indexer or the rebuild from the vault's
            // logs.
            pathSource: plan.pathSource || null,
            ...(destinationWarning ? { destinationWarning } : {})
        };
    }

    async recoverFailedWithdrawalSubmission({
        mode,
        error,
        submittedHash,
        submission,
        submissionMetadata = null,
        from = null
    }) {
        if (error?.transactionHash) {
            // onSubmitted assigns the in-memory hash before its IndexedDB
            // write. Retry that idempotent write even when submittedHash is
            // already populated, so a one-shot journal failure cannot lose a
            // MetaMask transaction across reload.
            submittedHash = error.transactionHash;
            try {
                await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                    submittedHash,
                    submission,
                    submissionMetadata
                );
                const metadata = await this.submittedTransactionMetadata(submittedHash, from);
                if (metadata) {
                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                        submittedHash,
                        submission,
                        metadata
                    );
                }
            } catch (journalError) {
                error.journalRecoveryError = journalError;
            }
        }
        const prepared = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal;
        // A takeover can leave another tab's hash in the durable plan while
        // this tab's MetaMask prompt is still open. Reconcile only the hash
        // owned by this operation; never mistake the other transaction for a
        // successful response to the prompt that just failed.
        const operationHash = submittedHash
            || (!submission ? prepared?.transactionHash : null)
            || null;
        let receipt = null;
        if (operationHash) {
            try {
                receipt = await this.ethereum.request({
                    method: 'eth_getTransactionReceipt',
                    params: [operationHash]
                });
            } catch {
                // Provider ambiguity is not evidence that the transaction was
                // rejected. Keep the submitted hash for deterministic recovery.
            }
        }
        const reverted = receipt && BigInt(receipt.status || '0x0') !== 1n;
        const rejectedBeforeSubmission = !submittedHash && isWalletRejection(error);
        const definitelyNotSubmitted = !submittedHash && submission
            && (error?.broadcastPossible === false || rejectedBeforeSubmission);
        const clearanceReserved = prepared?.clearanceReserved === true
            || submission?.clearanceReserved === true
            || mode === 'mutual';
        let releasedBackgroundClaim = false;

        if (reverted) {
            const finality = await this.browserRevertedReceiptFinality(operationHash, receipt);
            if (finality.finalized) {
                await browserWalletRuntime.markPreparedWithdrawalRetryable(operationHash, submission);
            } else {
                error.shortMessage = 'The transaction currently shows as reverted, but that block is not final yet. It remains tracked and will be checked automatically.';
                error.withdrawalNeedsAction = true;
            }
        } else if (definitelyNotSubmitted) {
            // A failed estimate, wrong network, or explicit wallet rejection
            // happened before broadcast, so this exact claim is safe to release.
            const released = await browserWalletRuntime
                .releaseBackgroundWithdrawalStartSubmission(submission);
            releasedBackgroundClaim = ['background', 'both'].includes(released?.location);
        } else if (!submittedHash && submission && error?.broadcastPossible === true) {
            if (submission.replacementNonce != null
                && Number.isSafeInteger(Number(submission.replacementNonce))) {
                // Every replacement deliberately reuses the same account
                // nonce. Even if this call was accepted before the provider
                // timed out, another exact replacement cannot execute twice.
                await browserWalletRuntime.releaseBackgroundWithdrawalStartSubmission(
                    submission,
                    {
                        replacementUnknown: true,
                        message: error?.message
                            || 'MetaMask did not return a replacement transaction ID.'
                    }
                );
                error.shortMessage = 'MetaMask did not return a replacement transaction ID. The original hashes remain saved, and you can check or safely resubmit with the same nonce.';
            } else {
                // A first submission has no prior nonce-equivalent hash to
                // constrain an explicit retry. Preserve its claim until the
                // user checks the vault and deliberately authorizes retry.
                await browserWalletRuntime.markPreparedWithdrawalAmbiguous(
                    submission,
                    error?.message || 'MetaMask did not return a transaction ID.'
                );
                error.shortMessage = 'MetaMask did not return a transaction ID. Check the withdrawal status; retry only if the vault still shows this balance as active.';
            }
            error.withdrawalNeedsAction = true;
        }
        if (definitelyNotSubmitted && mode === 'escape' && !clearanceReserved) {
            if (releasedBackgroundClaim) {
                this.rememberWithdrawal(null, { emit: false });
                error.shortMessage = 'MetaMask canceled this prompt before broadcast. The earlier submitted withdrawal remains saved in the background and does not block a new private balance.';
                error.withdrawalNeedsAction = true;
                await this.refresh({ quiet: true });
                return;
            }
            const remaining = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal;
            const remainingHashes = Array.isArray(remaining?.transactionHashes)
                ? remaining.transactionHashes
                : remaining?.transactionHash ? [remaining.transactionHash] : [];
            if (!remainingHashes.length) {
                await browserWalletRuntime.clearPreparedWithdrawal();
                this.rememberWithdrawal(null, { emit: false });
                // E6: the proof reached the wallet, so the exit lock holds the
                // balance until that proof expires; another escape is allowed.
                error.shortMessage = rejectedBeforeSubmission
                    ? 'MetaMask canceled the escape. No funds moved. The escape proof already reached the wallet, so this balance stays withdrawal-only until that proof expires; you can still escape.'
                    : 'The wallet refused the escape before broadcast. No funds moved. The escape proof already reached the wallet, so this balance stays withdrawal-only until that proof expires; you can still escape.';
            } else {
                error.shortMessage = 'MetaMask canceled this prompt. Another submitted withdrawal is still being checked.';
            }
        } else if (definitelyNotSubmitted) {
            error.shortMessage = releasedBackgroundClaim
                ? 'MetaMask canceled this prompt before broadcast. The earlier submitted withdrawal remains saved in the background.'
                : rejectedBeforeSubmission
                    ? 'MetaMask canceled the transaction. No funds moved; this balance is safely ready to withdraw. Finish the close or switch to the escape hatch.'
                    : 'The wallet refused the transaction before broadcast. No funds moved; this balance remains safely ready to withdraw.';
            error.withdrawalNeedsAction = true;
        }
        await this.refresh({ quiet: true });
        return receipt
            && String(receipt.transactionHash || '').toLowerCase() === String(operationHash || '').toLowerCase()
            ? receipt
            : null;
    }

    // ------------------------------------------------------------------ gasless withdrawals (design §3.2)
    //
    // With `fees: 'payout'` a withdrawal proof names a transit account S =
    // CREATE2(factory, 0, creationCode ‖ (entryPoint, vault, paymaster, owner,
    // payee)) as its destination, where owner is the connected account and
    // payee the payout address Y. The vault call runs inside an ERC-4337 user
    // operation sent from S and sponsored by the withdrawal paymaster P, which
    // keeps a measured charge out of the payout and pushes the rest to Y. The
    // connected account signs the operation's hash with personal_sign and never
    // sends a transaction. Every read of this path goes through the exit RPC
    // (on the vault's chain) and the pinned RPC, never the wallet provider,
    // unless the host opts in (client.gaslessReadsViaWallet = true).

    /** The timing of the sponsored submission loop (§3.1); `gaslessTimingOverrides` shortens it in tests. */
    get gaslessTiming() {
        return { ...GASLESS_TIMING, ...(this.gaslessTimingOverrides || {}) };
    }

    gaslessSleep(milliseconds) {
        return new Promise(resolve => setTimeout(resolve, milliseconds));
    }

    /** The read RPC of the gasless path: exit RPC on the vault chain, then the pinned RPC (the wallet only when opted in). */
    gaslessReader() {
        return browserWalletRuntime.gaslessReader({
            walletRequest: this.gaslessReadsViaWallet === true ? request => this.ethereum.request(request) : null
        });
    }

    /** The build-pinned gasless configuration, or the `gasless_unavailable` refusal that explains why there is none. */
    requireGaslessPins() {
        let pins;
        try {
            pins = gaslessPinsOf(browserWalletRuntime.browserConfig?.trusted_deployment);
        } catch (error) {
            throw gaslessError('gasless_unavailable', { reason: error?.code || 'gasless_profile_invalid', detail: error?.message || null });
        }
        if (!pins) throw gaslessError('gasless_unavailable', { reason: 'not_pinned' });
        return pins;
    }

    /**
     * The pins a sponsored operation for an existing gasless record needs
     * (a FORWARD, a FINALIZE, a new, re-sent or re-signed operation of a
     * sponsored close or escape; an operation already sent is still looked
     * for on chain and released, see releaseUnpinnedFinalization and
     * recoverGaslessSubmission):
     * the current profile's, naming the paymaster and factory the record's
     * transit account was made under. A profile that publishes no gasless
     * contracts any more (`gasless: null`, the paymaster's retirement) or
     * pins others is refused with `gasless_record_not_pinned`, which names
     * the wallet-paid recovery that keeps working from the journaled
     * addresses: sweepTransit, claimGaslessCredit and finalizeEscape with
     * fees: 'wallet', led by withdraw(mode, onStatus, { fees: 'wallet' })
     * while a prepared plan's exit is not on chain yet.
     */
    requireRecordPins(record) {
        const transit = record?.transit || {};
        // A prepared plan (no withdrawal record yet) whose close or escape
        // initiation is not on chain: the note is still open, so the
        // wallet-paid exit is the way forward, named first.
        const exitPending = Boolean(record) && !record.recordId && !record.transactionHash;
        const refusal = (reason, pins = null) => gaslessError('gasless_record_not_pinned', {
            reason,
            transitAccount: transit.account ? String(transit.account).toLowerCase() : null,
            paymaster: transit.paymaster ? String(transit.paymaster).toLowerCase() : null,
            factory: transit.factory ? String(transit.factory).toLowerCase() : null,
            pinnedPaymaster: pins ? pins.paymaster.toLowerCase() : null,
            pinnedFactory: pins ? pins.factory.toLowerCase() : null,
            alternatives: [...(exitPending ? [`withdraw('${record.mode === 'escape' ? 'escape' : 'mutual'}', onStatus, { fees: 'wallet' })`] : []),
                'sweepTransit', 'claimGaslessCredit', "finalizeEscape({ fees: 'wallet' })"]
        });
        let pins;
        try {
            pins = this.requireGaslessPins();
        } catch (error) {
            if (error?.data?.reason === 'not_pinned') throw refusal('not_pinned');
            throw error;
        }
        if ((transit.paymaster && !sameAddress(transit.paymaster, pins.paymaster))
            || (transit.factory && !sameAddress(transit.factory, pins.factory))) {
            throw refusal('pins_mismatch', pins);
        }
        return pins;
    }

    /**
     * The contracts a wallet-paid action on an existing gasless record uses
     * (sweepTransit; claimGaslessCredit reads the paymaster the same way):
     * the transit account, factory, paymaster, EntryPoint, owner and payee
     * journaled with the record, never the current profile's, so recovery
     * keeps working after the profile retires its pins or names another
     * paymaster. The journaled factory's getAddress(owner, payee) must name
     * the journaled account through the read RPC; while the profile still
     * pins the same contracts their deployment is verified too.
     */
    async journaledTransit(record, reader) {
        const transit = record?.transit || {};
        const address = value => /^0x[0-9a-fA-F]{40}$/.test(String(value || '')) ? String(value).toLowerCase() : null;
        const journaled = {
            account: address(transit.account), factory: address(transit.factory), paymaster: address(transit.paymaster),
            entryPoint: address(transit.entryPoint), owner: address(transit.owner), payee: address(transit.payee || record?.payout)
        };
        if (Object.values(journaled).some(value => !value)) {
            throw new Error('The journaled transit account of this withdrawal is incomplete; nothing was signed.');
        }
        let pins = null;
        try {
            pins = this.requireGaslessPins();
        } catch {
            pins = null;
        }
        if (pins && sameAddress(pins.paymaster, journaled.paymaster) && sameAddress(pins.factory, journaled.factory)
            && sameAddress(pins.entryPoint, journaled.entryPoint)) {
            await this.assertGaslessDeployment(pins, reader);
        }
        const derived = decodeAddressWord(await this.gaslessCall(reader, journaled.factory, encodeGetAddress(journaled.owner, journaled.payee)));
        if (derived.toLowerCase() !== journaled.account) {
            throw gaslessError('gasless_unavailable', {
                reason: 'gasless_deployment_mismatch', field: 'factory.getAddress', expected: journaled.account, actual: derived.toLowerCase()
            }, 'The journaled factory derives another transit account for this withdrawal’s owner and payout address. Nothing was signed.');
        }
        return journaled;
    }

    async gaslessCall(reader, to, data) {
        return reader({ method: 'eth_call', params: [{ to, data }, 'latest'] });
    }

    /** The gasless contracts are checked once per session (per chain and paymaster) through the read RPC (§4.4). */
    async assertGaslessDeployment(pins, reader) {
        const key = `${Number(this.config.funding.chain_id)}:${pins.paymaster.toLowerCase()}`;
        if (this.gaslessDeploymentVerified === key) return;
        const result = await verifyGaslessDeployment({
            request: reader,
            trusted: browserWalletRuntime.browserConfig?.trusted_deployment,
            chainId: this.config.funding.chain_id,
            source: 'read_rpc'
        });
        if (!result.ok) throw gaslessDeploymentError([result]);
        this.gaslessDeploymentVerified = key;
    }

    /** The transit identity of (owner, payout): S from the pinned creation code, cross-checked with factory.getAddress. */
    async transitIdentity(pins, reader, { owner, payout, expected = null }) {
        const vault = this.config.funding.contract_address;
        const account = transitAccountAddress({
            factory: pins.factory, creationCodeHex: pins.accountCreationCode, entryPoint: pins.entryPoint, vault,
            paymaster: pins.paymaster, owner, payee: payout
        });
        const onChain = decodeAddressWord(await this.gaslessCall(reader, pins.factory, encodeGetAddress(owner, payout)));
        if (onChain.toLowerCase() !== account) {
            throw gaslessError('gasless_unavailable', {
                reason: 'gasless_deployment_mismatch', field: 'factory.getAddress', expected: account, actual: onChain.toLowerCase()
            }, GASLESS_MESSAGES.gasless_deployment_mismatch);
        }
        if (expected && String(expected).toLowerCase() !== account) {
            throw new Error('The journaled transit account does not match its owner and payout address.');
        }
        return {
            factory: pins.factory.toLowerCase(),
            paymaster: pins.paymaster.toLowerCase(),
            entryPoint: pins.entryPoint.toLowerCase(),
            account,
            owner: String(owner).toLowerCase(),
            payee: String(payout).toLowerCase(),
            creationCodeKeccak: pins.accountCreationCodeKeccak256
        };
    }

    /**
     * Everything one sponsored operation needs: the pins, the read RPC, the
     * verified deployment, the transit identity and the bundler (a host
     * transport on the provider, `provider.zkapiBundler`, else the URL given,
     * the user's, or the profile's).
     */
    async gaslessContext({ from, payout, owner = from, expectedAccount = null, bundlerUrl = null, kind = KIND.close, record = null }) {
        if (!this.config?.funding?.contract_address) throw new Error('Initialize the wallet before a sponsored withdrawal.');
        // An existing record is sponsored only by the paymaster it was made under.
        const pins = record?.transit ? this.requireRecordPins(record) : this.requireGaslessPins();
        const reader = this.gaslessReader();
        await this.assertGaslessDeployment(pins, reader);
        const transit = await this.transitIdentity(pins, reader, { owner, payout, expected: expectedAccount });
        const transport = this.ethereum?.zkapiBundler && typeof this.ethereum.zkapiBundler.sendUserOperation === 'function'
            ? this.ethereum.zkapiBundler : null;
        const url = transport ? null : (bundlerUrl || browserWalletRuntime.effectiveBundlerUrl());
        const bundler = transport ? browserWalletRuntime.bundlerRpc(null, { transport }) : (url ? browserWalletRuntime.bundlerRpc(url) : null);
        return { pins, reader, transit, payout: String(payout).toLowerCase(), bundler, bundlerUrl: url, kind };
    }

    /**
     * The paymaster's live policy, ceilings and gas policy (checked against the
     * pins), its float, the vault's pause, the key's attempts and S's debt.
     */
    async readPaymasterState(pins, reader, { kind, key = null, account = null }) {
        const P = pins.paymaster;
        const trusted = browserWalletRuntime.browserConfig?.trusted_deployment || {};
        const vault = this.config.funding.contract_address;
        const policy = decodePolicy(await this.gaslessCall(reader, P, `0x${GASLESS_ABI.policy}`));
        const maxFeeCeiling = decodeWord(await this.gaslessCall(reader, P, `0x${GASLESS_ABI.maxFeeCeiling}`), 'maxFeeCeiling');
        const priorityFeeCeiling = decodeWord(await this.gaslessCall(reader, P, `0x${GASLESS_ABI.priorityFeeCeiling}`), 'priorityFeeCeiling');
        const gasPolicy = decodeGasPolicy(await this.gaslessCall(reader, P, `0x${GASLESS_ABI.gasPolicy}`));
        gasPolicy.defaults = pins.gasPolicy.defaults;
        const depositWei = decodeWord(await this.gaslessCall(reader, pins.entryPoint, encodeBalanceOf(P)), 'balanceOf');
        const callCap = decodeWord(await this.gaslessCall(reader, P, encodeCallCap(kind)), 'callCap');
        const paused = decodeBool(await this.gaslessCall(reader, vault, `0x${GASLESS_ABI.paused}`), 'paused');
        let reopenAt = null;
        if (paused) {
            const pausedAt = decodeWord(await this.gaslessCall(reader, vault, `0x${GASLESS_ABI.pausedAt}`), 'pausedAt');
            reopenAt = Number(pausedAt + BigInt(trusted.max_pause_duration || 0));
        }
        const attempts = key ? decodeWord(await this.gaslessCall(reader, P, encodeAttempts(key)), 'attempts') : null;
        const owed = account ? decodeWord(await this.gaslessCall(reader, P, encodeOwed(account)), 'owed') : 0n;
        return {
            policy, maxFeeCeiling, priorityFeeCeiling, gasPolicy, policyMatches: sameGasPolicy(gasPolicy, pins.gasPolicy),
            depositWei, callCap, paused, reopenAt, attempts, owed
        };
    }

    /** The bundler's chain and EntryPoint answers; `reachable: false` when it cannot be asked at all. */
    async probeBundler(bundler, pins, url) {
        if (!bundler) return { reachable: false, configured: false };
        let chainId = null;
        try {
            chainId = await bundler.chainId();
        } catch (error) {
            if (error?.code === 'bundler_unavailable') return { reachable: false, configured: true, error };
            // A bundler that does not serve eth_chainId answers eth_supportedEntryPoints.
        }
        const wrongChain = chainId != null && chainId !== BigInt(this.config.funding.chain_id);
        let entryPoints = null;
        if (!wrongChain) {
            try {
                entryPoints = await bundler.supportedEntryPoints();
            } catch (error) {
                if (error?.code === 'bundler_unavailable') return { reachable: false, configured: true, error };
                entryPoints = [];
            }
        }
        const supportsEntryPoint = entryPoints == null ? null : entryPoints.includes(pins.entryPoint.toLowerCase());
        if (url) browserWalletRuntime.noteBundlerChain(url, !wrongChain, supportsEntryPoint);
        return { reachable: true, configured: true, chainId, wrongChain, entryPoints, supportsEntryPoint };
    }

    /**
     * The pre-flight of §3.1 for one sponsorship, before any proof is made
     * (the proof binds S): the bundler, the paymaster's policy and float, the
     * vault's pause and the key's attempts. Publishes the snapshot's `gasless` object.
     */
    async gaslessPreflight(context, { kind, key = null, maxCost = null, noteId = null }) {
        const state = await this.readPaymasterState(context.pins, context.reader, { kind, key, account: context.transit.account });
        const bundler = await this.probeBundler(context.bundler, context.pins, context.bundlerUrl);
        // An unreachable bundler is not asked for its tip by the sizing below.
        context.bundlerReachable = bundler.reachable === true;
        // The operation's prefund, before any proof binds S (§3.1 pre-flight
        // (3)): the fees within the ceilings and the gas fields of a draft of
        // this kind, so the float and the fee ceilings refuse here, not after
        // the proof.
        const sizing = maxCost == null ? await this.gaslessPreflightSizing(context, state, { kind, noteId })
            : { fees: null, gas: null, maxCost: toBigInt(maxCost, 'maxCost'), withInitCode: null, refusal: null };
        const first = availabilityVerdict({
            bundler: bundler.configured ? bundler : { reachable: false },
            policy: state.policy, policyMatches: state.policyMatches, depositWei: state.depositWei, maxCost: sizing.maxCost,
            vaultPaused: state.paused, reopenAt: state.reopenAt, attempts: state.attempts, kind, maxAttempts: state.gasPolicy.maxAttempts
        });
        // A fee refusal comes after the bundler and the policy, before the float and the attempts.
        const verdict = sizing.refusal && !GASLESS_PREFLIGHT_BEFORE_FEES.includes(first.reason) ? sizing.refusal : first;
        const status = {
            available: verdict.available,
            reason: verdict.reason,
            bundler_url: context.bundlerUrl,
            paymaster_deposit_wei: state.depositWei.toString(),
            policy: journalValue({
                max_sponsored_cost_wei: state.policy.maxSponsoredCostWei, flat_fee_wei: state.policy.flatFeeWei,
                min_escape_net_wei: state.policy.minEscapeNetWei, escapes_enabled: state.policy.escapesEnabled,
                sponsorship_paused: state.policy.sponsorshipPaused, max_fee_ceiling_wei: state.maxFeeCeiling,
                priority_fee_ceiling_wei: state.priorityFeeCeiling
            }),
            attempts_left: state.attempts == null ? null : Number(state.gasPolicy.maxAttempts - state.attempts),
            max_cost_wei: sizing.maxCost.toString(),
            checked_at: Date.now()
        };
        browserWalletRuntime.noteGaslessStatus(status);
        return { state, bundler, verdict, status, fees: sizing.fees, gas: sizing.gas, maxCost: sizing.maxCost, withInitCode: sizing.withInitCode };
    }

    /**
     * The prefund of a draft operation of `kind` from S at the current fees
     * (§3.1): selectFees within the ceilings (`gas_above_paymaster_ceiling`),
     * the gas fields from the pinned defaults with the live callCap, initCode
     * when S has no code yet, the calldata sized as the real op's (an 836-byte
     * vault call for a close or escape, finalizeEscape(noteId), nothing for a
     * forward), then `maxCost` against the policy (`max_cost_above_policy`).
     * A refusal is returned, not thrown, so the pre-flight can rank it.
     */
    async gaslessPreflightSizing(context, state, { kind, noteId = null }) {
        const { pins, reader, transit } = context;
        const refusal = error => ({ available: false, reason: error.code, message: error.shortMessage || error.message, data: error.data ?? null });
        let fees;
        try {
            fees = await this.selectGaslessFees(context, state);
        } catch (error) {
            if (error?.code !== 'gas_above_paymaster_ceiling') throw error;
            return { fees: null, gas: null, maxCost: 0n, withInitCode: null, refusal: refusal(error) };
        }
        let withInitCode = true;
        if (transit.account) {
            const code = await reader({ method: 'eth_getCode', params: [transit.account, 'latest'] });
            withInitCode = !code || code === '0x';
        }
        const sender = transit.account || GASLESS_DRY_RUN_BENEFICIARY;
        const owner = transit.owner || sender;
        const payee = transit.payee || context.payout || sender;
        const initCode = withInitCode ? transitInitCode({ factory: pins.factory, owner, payee }) : '0x';
        const vaultCall = kind === KIND.forward ? '0x' : kind === KIND.finalize ? encodeFinalizeEscape(noteId ?? 0) : WORST_CASE_EXIT_CALL;
        const draft = gas => buildUserOperation({
            sender, nonce: 0n, initCode, callData: encodeTransitWithdraw(vaultCall), gas, fees, paymaster: pins.paymaster, feeCapWei: state.policy.flatFeeWei
        });
        const sized = gasFields({ gasPolicy: pins.gasPolicy, kind, withInitCode, calldataBytes: 0, callCap: state.callCap });
        const sizedOp = draft(sized);
        const calldataBytes = handleOpsCalldataBytes(sizedOp, owner);
        const gas = gasFields({ gasPolicy: pins.gasPolicy, kind, withInitCode, calldataBytes, callCap: state.callCap, op: sizedOp });
        const maxCost = maxCostWei(gas, fees.maxFeePerGas);
        if (maxCost > state.policy.maxSponsoredCostWei) {
            return { fees, gas, maxCost, withInitCode, refusal: refusal(gaslessError('max_cost_above_policy', { maxCost, cap: state.policy.maxSponsoredCostWei })) };
        }
        return { fees, gas, maxCost, withInitCode, refusal: null };
    }

    /**
     * The fee fields of §3.1: a tip within the paymaster's ceiling (the
     * bundler's own suggestion when it offers one, since a bundler refuses an
     * operation below its minimum tip; else the chain's) and min(2 × baseFee
     * + tip, the max-fee ceiling), refused only when baseFee + tip is above
     * that ceiling (selectFees, the rule clientd shares).
     */
    async selectGaslessFees(context, state) {
        const block = await context.reader({ method: 'eth_getBlockByNumber', params: ['latest', false] });
        const baseFeePerGas = block?.baseFeePerGas != null ? toBigInt(block.baseFeePerGas, 'baseFeePerGas')
            : toBigInt(await context.reader({ method: 'eth_gasPrice', params: [] }), 'gasPrice');
        let priorityFeePerGas = null;
        if (context.bundler && context.bundlerReachable !== false && typeof context.bundler.suggestedPriorityFee === 'function') {
            priorityFeePerGas = await context.bundler.suggestedPriorityFee().catch(() => null);
        }
        if (priorityFeePerGas == null) {
            try {
                priorityFeePerGas = toBigInt(await context.reader({ method: 'eth_maxPriorityFeePerGas', params: [] }), 'priorityFee');
            } catch {
                priorityFeePerGas = null;
            }
        }
        return selectFees({ baseFeePerGas, priorityFeePerGas, maxFeeCeiling: state.maxFeeCeiling, priorityFeeCeiling: state.priorityFeeCeiling });
    }

    /**
     * One sponsored operation of `kind` from S (§3.1): the nonce from the
     * EntryPoint, initCode on first use, gas fields from the pinned policy,
     * fees within the ceilings, the amounts checked against P.quote, and the
     * local hash checked against entryPoint.getUserOpHash. Unsigned.
     */
    async buildGaslessOperation(context, { kind, vaultCall, nullifier = null, noteId = null, payoutWei, feeCapWei = null,
        allowExpensiveGas = false, state, fees = null, withInitCode = null, gasOverrides = {} }) {
        const { pins, reader, transit } = context;
        const key = nonceKeyFor(kind, { nullifier });
        const nonceWord = decodeWord(await this.gaslessCall(reader, pins.entryPoint, encodeGetNonce(transit.account, key)), 'getNonce');
        const { sequence } = unpackNonce(nonceWord);
        let initCode = '0x';
        let created = withInitCode;
        if (created == null) {
            const code = await reader({ method: 'eth_getCode', params: [transit.account, 'latest'] });
            created = !code || code === '0x';
        }
        if (created) initCode = transitInitCode({ factory: pins.factory, owner: transit.owner, payee: transit.payee });
        const callData = encodeTransitWithdraw(vaultCall);
        const flatFee = state.policy.flatFeeWei;
        const userCap = feeCapWei == null ? null : toBigInt(feeCapWei, 'feeCapWei');
        if (userCap != null && flatFee > userCap) throw gaslessError('gasless_fee_above_cap', { flatFeeWei: flatFee, feeCapWei: userCap });
        const selectedFees = fees || await this.selectGaslessFees(context, state);
        const nonce = packNonce(key, sequence);
        const draft = gas => buildUserOperation({
            sender: transit.account, nonce, initCode, callData, gas, fees: selectedFees, paymaster: pins.paymaster, feeCapWei: flatFee
        });
        const sized = gasFields({ gasPolicy: pins.gasPolicy, kind, withInitCode: created, calldataBytes: 0, callCap: state.callCap, overrides: gasOverrides });
        const sizedOp = draft(sized);
        const calldataBytes = handleOpsCalldataBytes(sizedOp, transit.owner);
        const gas = gasFields({ gasPolicy: pins.gasPolicy, kind, withInitCode: created, calldataBytes, callCap: state.callCap, overrides: gasOverrides,
            op: sizedOp });
        const op = draft(gas);
        const maxCost = maxCostWei(gas, selectedFees.maxFeePerGas);
        if (maxCost > state.policy.maxSponsoredCostWei) {
            throw gaslessError('max_cost_above_policy', { maxCost, cap: state.policy.maxSponsoredCostWei });
        }
        // The float must cover the prefund (a bundler reserves it per pending op, EREP-010).
        if (state.depositWei != null && state.depositWei < maxCost) {
            throw gaslessError('paymaster_underfunded', { depositWei: state.depositWei, maxCost });
        }
        const finalizeReserveWei = kind === KIND.escape ? pins.gasPolicy.finalizeReserveGas * selectedFees.maxFeePerGas : 0n;
        const amounts = gaslessAmounts({
            kind, payoutWei, maxCost, flatFee, owed: state.owed, finalizeReserveWei, minEscapeNetWei: state.policy.minEscapeNetWei,
            uneconomicFractionPercent: pins.uneconomicFractionPercent, allowExpensiveGas
        });
        const quote = decodeQuote(await this.gaslessCall(reader, pins.paymaster, encodeQuote({
            kind, sender: transit.account, noteId: noteId ?? 0n, nullifier: nullifier ?? 0n, maxCost, maxFeePerGas: selectedFees.maxFeePerGas
        })));
        if (quote.requiredWei !== amounts.requiredWei || quote.owedWei !== state.owed || quote.flatFeeWei !== flatFee
            || quote.finalizeReserveWei !== finalizeReserveWei) {
            throw gaslessError('gasless_policy_mismatch', { local: journalValue(amounts), quote: journalValue(quote) });
        }
        if (!quote.attemptsLeft) throw gaslessError('gasless_attempts_exhausted');
        if (kind === KIND.escape && !quote.escapeOpen) {
            throw gaslessError(state.policy.escapesEnabled ? 'escape_already_sponsored' : 'escapes_disabled', { noteId },
                state.policy.escapesEnabled ? 'An escape of this balance was already sponsored once, or this transit account still has an open sponsored escape.' : null);
        }
        const hash = userOpHash(op, pins.entryPoint, this.config.funding.chain_id);
        const onChainHash = await this.gaslessCall(reader, pins.entryPoint, encodeGetUserOpHash(op));
        if (String(onChainHash || '').toLowerCase() !== hash) {
            throw gaslessError('entry_point_hash_mismatch', { local: hash, entryPoint: onChainHash || null });
        }
        return { op, hash, key, sequence, withInitCode: created, gas, fees: selectedFees, maxCost, amounts, quote, payoutWei };
    }

    /** A bundler's estimate is a cross-check only: above a cap it is refused, below the defaults ignored (§3.1). */
    async crossCheckGaslessEstimate(context, built) {
        if (!context.bundler || this.gaslessEstimateCheck === false) return;
        const probe = { ...built.op, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n, signature: `0x${'00'.repeat(65)}` };
        let estimate;
        try {
            estimate = await context.bundler.estimateUserOperationGas(userOperationJson(probe), context.pins.entryPoint);
        } catch {
            return;
        }
        // The caps are the paymaster's (its live callCap for this kind), not
        // the signed defaults: an estimate between a default and its cap is
        // one the paymaster accepts and is ignored like any lower one.
        checkEstimate(estimate, { gasPolicy: context.pins.gasPolicy, kind: context.kind, withInitCode: built.withInitCode,
            callCap: context.state?.callCap ?? null });
        // Except preVerificationGas: the bundler's own minimum for this op
        // (within the paymaster's cap, checked above) is what it will take,
        // so a higher one is returned for the op to be rebuilt with it.
        let preVerificationGas = null;
        try {
            preVerificationGas = estimate?.preVerificationGas == null ? null : toBigInt(estimate.preVerificationGas, 'preVerificationGas');
        } catch {
            preVerificationGas = null;
        }
        return preVerificationGas != null && preVerificationGas > BigInt(built.op.preVerificationGas)
            && preVerificationGas <= context.pins.gasPolicy.pvgCap ? { preVerificationGas } : null;
    }

    /**
     * eth_call entryPoint.handleOps([op], beneficiary) through the read RPC.
     * Unsigned, the run must end in AA24; signed it must be clean. AA10 and
     * AA25 come back as silent errors the caller handles. AA24 is not proof
     * that everything else passed: EntryPoint v0.7.0 reverts with it in
     * _validateAccountAndPaymasterValidationData before it evaluates the
     * time ranges, so it masks AA22 (the account's), AA32 (the paymaster's
     * validAfter/validUntil) and AA34 (the paymaster's signature). The time
     * window is therefore checked against the latest block before the prompt
     * (gaslessAwaitTimeWindow).
     */
    async dryRunGaslessOperation(context, op, { signed }) {
        const beneficiary = GASLESS_DRY_RUN_BENEFICIARY;
        try {
            await context.reader({
                method: 'eth_call',
                params: [{ from: beneficiary, to: context.pins.entryPoint, data: encodeHandleOps([op], beneficiary) }, 'latest']
            });
            return { ok: true };
        } catch (error) {
            const decoded = dryRunError(error);
            if (!decoded) throw error;
            if (!signed && decoded.aa === 'AA24') return { ok: true, signatureCheckPending: true };
            throw decoded;
        }
    }

    /**
     * The time window the paymaster's validationData sets, against the
     * latest block's timestamp (the clock the EntryPoint uses), before any
     * prompt: the unsigned dry run cannot show it (AA24 masks AA32). A close
     * or escape needs `timestamp <= validUntil − stopBeforeValidUntilSeconds`
     * (`gasless_op_expired`, proved again); a finalization needs
     * `timestamp >= validAfter` (the vault's challenge deadline) and waits
     * for it up to `notDueWaitMs` (`escape_not_due` beyond).
     */
    async gaslessAwaitTimeWindow(context, { validAfter = null, validUntil = null, onStatus = () => {} }) {
        if (validAfter == null && validUntil == null) return;
        const timing = this.gaslessTiming;
        const started = Date.now();
        let told = false;
        for (;;) {
            const block = await context.reader({ method: 'eth_getBlockByNumber', params: ['latest', false] });
            if (block?.timestamp == null) throw new Error('The read RPC returned no timestamp for the latest block.');
            const timestamp = Number(toBigInt(block.timestamp, 'timestamp'));
            if (validUntil != null && timestamp > Number(validUntil) - timing.stopBeforeValidUntilSeconds) {
                throw gaslessError('gasless_op_expired', { blockTimestamp: timestamp, validUntil: Number(validUntil) });
            }
            if (validAfter == null || timestamp >= Number(validAfter)) return;
            if (Date.now() - started >= timing.notDueWaitMs) {
                throw gaslessError('escape_not_due', { blockTimestamp: timestamp, validAfter: Number(validAfter) });
            }
            if (!told) {
                told = true;
                onStatus('Waiting for the chain to reach the end of the safety window before asking for a signature…');
            }
            await this.gaslessSleep(timing.receiptPollMs);
        }
    }

    /** personal_sign of the 32 raw bytes of the operation hash by the connected account, which must own S. */
    async signGaslessOperation(context, hash, from) {
        if (String(from || '').toLowerCase() !== context.transit.owner) {
            throw gaslessError('wrong_owner_account', { expected: context.transit.owner, connected: String(from || '').toLowerCase() },
                `Connect the account ${context.transit.owner} that owns this withdrawal’s transit account to sign its operation.`);
        }
        const signature = await this.ethereum.request({ method: 'personal_sign', params: [hash, from] });
        if (!/^0x[0-9a-fA-F]{130}$/.test(signature || '')) throw new Error('The wallet returned an invalid signature for the sponsored operation.');
        return signature.toLowerCase();
    }

    async gaslessBlockNumber(context) {
        try {
            return Number(BigInt(await context.reader({ method: 'eth_blockNumber', params: [] })));
        } catch {
            return null;
        }
    }

    /** The bundle transaction receipt through the read RPC; polls while the node has not indexed it yet. */
    async gaslessTransactionReceipt(context, transactionHash, { attempts = 60 } = {}) {
        for (let attempt = 0; attempt < attempts; attempt += 1) {
            let receipt = null;
            try {
                receipt = await context.reader({ method: 'eth_getTransactionReceipt', params: [transactionHash] });
            } catch {
                receipt = null;
            }
            if (receipt) {
                if (String(receipt.transactionHash || '').toLowerCase() !== String(transactionHash).toLowerCase()) {
                    throw new Error('The bundle transaction receipt has a different transaction hash.');
                }
                if (BigInt(receipt.status || '0x0') !== 1n) {
                    const error = new Error(`The bundle transaction ${this.compact(transactionHash)} reverted.`);
                    error.transactionReceipt = receipt;
                    throw error;
                }
                return receipt;
            }
            await this.gaslessSleep(this.gaslessTiming.receiptPollMs);
        }
        throw new Error(`Timed out waiting for the bundle transaction ${this.compact(transactionHash)}.`);
    }

    /**
     * The inclusion of one of `hashes` (or of S's operation at `nonce`) by
     * the EntryPoint's UserOperationEvent logs from `fromBlock`, through the
     * read RPC: { userOpHash, transactionHash, blockNumber, success }, or null.
     */
    async findUserOperationInclusion(context, hashes, fromBlock, { sender = null, nonce = null } = {}) {
        const topics = [GASLESS_ABI.userOperationEvent];
        const wanted = (hashes || []).map(hash => String(hash).toLowerCase());
        if (wanted.length) topics.push(wanted.length === 1 ? wanted[0] : wanted);
        else if (sender) topics.push(null, `0x${'0'.repeat(24)}${sender.slice(2).toLowerCase()}`);
        else return null;
        let logs;
        try {
            logs = await context.reader({
                method: 'eth_getLogs',
                params: [{
                    address: context.pins.entryPoint,
                    fromBlock: fromBlock != null ? `0x${Math.max(0, Number(fromBlock)).toString(16)}` : '0x0',
                    toBlock: 'latest',
                    topics
                }]
            });
        } catch {
            return null;
        }
        for (const log of Array.isArray(logs) ? logs : []) {
            if (log?.removed === true || !Array.isArray(log?.topics) || log.topics.length !== 4) continue;
            const data = String(log.data || '').replace(/^0x/, '');
            const logNonce = data.length >= 64 ? BigInt(`0x${data.slice(0, 64)}`) : null;
            if (nonce != null && logNonce !== BigInt(nonce)) continue;
            return {
                userOpHash: String(log.topics[1]).toLowerCase(),
                transactionHash: String(log.transactionHash || '').toLowerCase(),
                blockNumber: log.blockNumber == null ? null : Number(BigInt(log.blockNumber)),
                success: data.length >= 128 ? BigInt(`0x${data.slice(64, 128)}`) === 1n : null
            };
        }
        return null;
    }

    /** Whether a bundler's refusal means the identical operation is already known to it (then it is pending, not refused). */
    gaslessAlreadyKnown(error) {
        // An EntryPoint refusal (an AA code, e.g. AA10 "sender already
        // constructed", whose user message says the account already exists)
        // is never the bundler saying it already holds the operation.
        if (error?.aa) return false;
        const text = `${error?.rpcMessage || ''} ${error?.message || ''}`;
        return /already (known|in (the )?mempool|submitted|pending|exists)|duplicate/i.test(text);
    }

    /** Whether a bundler's refusal asks for higher fees (the mempool dropped the op, or will not take it at this price). */
    gaslessFeeTooLow(error) {
        // Decided on the message only (bundlers answer a fee refusal with
        // -32602 or -32500 and fee wording), never for an EntryPoint or
        // paymaster refusal (an AA code, a decoded revert) nor for ERC-7769's
        // -32507 (signature) and -32508 (paymaster balance): re-signing with
        // higher fees cannot cure those, and -32508 only gets worse.
        if (error?.aa || error?.selector || this.gaslessAlreadyKnown(error)) return false;
        if ([-32507, -32508].includes(Number(error?.rpcCode)) || ['signature_rejected', 'paymaster_underfunded'].includes(error?.code)) return false;
        const text = `${error?.rpcMessage || ''} ${error?.message || ''}`;
        return /fee too low|underpriced|replacement|maxFeePerGas|maxPriorityFeePerGas|gas price/i.test(text);
    }

    /**
     * Build, check, sign, journal, submit and follow one sponsored operation
     * (§3.1): the unsigned dry run before any prompt, the signed dry run
     * before any send, the write-ahead journal before eth_sendUserOperation,
     * the hash cross-check, then polling by bundler receipt and by the
     * EntryPoint's logs; an identical re-send after 5 minutes unknown, a fee
     * bump within the ceilings when the bundler asks for it, and a hard stop
     * 60 s before the proof's validUntil. `journal` is the plan's or the
     * record's write-ahead journal; `resume` an operation journaled earlier.
     * With `selfBundle`, a funded wallet sends handleOps itself instead.
     */
    async runGaslessOperation(context, build, journal, { onStatus, validUntil = null, validAfter = null, selfBundle = false, from, resume = null,
        submission = null, amountsMessage = null, stale = null }) {
        const { pins, bundler } = context;
        // The proof's validUntil bounds everything: stop (and prove again) 60 s before it.
        const expired = () => validUntil != null && Date.now() / 1_000 >= Number(validUntil) - this.gaslessTiming.stopBeforeValidUntilSeconds;
        if (expired()) throw gaslessError('gasless_op_expired');
        const bump = () => {
            const bumped = bumpFees(built.fees, { maxFeeCeiling: context.state.maxFeeCeiling, priorityFeeCeiling: context.state.priorityFeeCeiling });
            if (!bumped) throw gaslessError('gasless_fee_bump_exhausted');
            return bumped;
        };
        let built;
        const hashes = new Set();
        // `replacing`: the nonce of an earlier variant this one replaces (a
        // fee bump or a rebuild after a send). That variant may land while
        // the replacement is built or signed: a moved nonce or any refusal is
        // then not rebuilt silently but handed to `replace`, which looks for
        // the earlier variant's inclusion first.
        const buildChecked = async ({ withInitCode = null, fees = null, replacing = null, gasOverrides = undefined }) => {
            // The unsigned dry run exercises every validation step but the
            // signature; AA10 (S exists) and AA25 (nonce moved) are rebuilt.
            for (let pass = 0; pass < 3; pass += 1) {
                built = await build({ withInitCode, fees, ...(gasOverrides ? { gasOverrides } : {}) });
                if (replacing != null && BigInt(built.op.nonce) !== BigInt(replacing)) {
                    const moved = new Error(ENTRY_POINT_ERRORS.AA25.message);
                    throw Object.assign(moved, { name: 'ZkapiEntryPointError', code: ENTRY_POINT_ERRORS.AA25.code,
                        shortMessage: ENTRY_POINT_ERRORS.AA25.message, aa: 'AA25', silent: true });
                }
                try {
                    await this.dryRunGaslessOperation(context, built.op, { signed: false });
                    break;
                } catch (error) {
                    if (error?.silent && error.aa === 'AA10' && pass < 2) {
                        withInitCode = false;
                        continue;
                    }
                    if (error?.silent && error.aa === 'AA25' && pass < 2 && replacing == null) continue;
                    throw error;
                }
            }
        };
        const prepare = async ({ withInitCode = null, fees = null, replacing = null } = {}) => {
            await buildChecked({ withInitCode, fees, replacing });
            const wanted = await this.crossCheckGaslessEstimate(context, built);
            if (wanted) {
                // The bundler asks for more preVerificationGas than the
                // client reserved (within the paymaster's cap): the op is
                // rebuilt with it before anything is shown or signed.
                await buildChecked({ withInitCode: built.withInitCode, fees: built.fees, replacing, gasOverrides: wanted });
            }
            await this.gaslessAwaitTimeWindow(context, { validAfter, validUntil, onStatus });
            onStatus(amountsMessage ? amountsMessage(built) : this.gaslessAmountsMessage(built), { amounts: journalValue(built.amounts) });
            onStatus(context.kind === KIND.forward ? 'Confirm the sponsored collection in MetaMask (a signature, no transaction)…'
                : 'Confirm the sponsored operation in MetaMask (a signature, no transaction)…');
            built.op.signature = await this.signGaslessOperation(context, built.hash, from);
            try {
                await this.dryRunGaslessOperation(context, built.op, { signed: true });
            } catch (error) {
                if (error?.code === 'signature_rejected') throw gaslessError('signature_rejected', { owner: context.transit.owner });
                // The chain passed the proof's validUntil while the prompt
                // was open (the window was checked before it): nothing was
                // journaled or sent, so the plan is proved again (§3.2).
                if (error?.aa === 'AA32' && validUntil != null && validAfter == null) {
                    const expiredWhileSigning = gaslessError('gasless_op_expired', { aa: 'AA32', validUntil: Number(validUntil) });
                    expiredWhileSigning.cause = error;
                    throw expiredWhileSigning;
                }
                throw error;
            }
            await journal.rememberBuilt(built);
            hashes.add(built.hash);
        };
        // The hashes of this plan's earlier operations (released before a
        // re-proof or a rebuild) still count for an inclusion on chain, from
        // the earliest block any of them was tracked from: a released
        // operation can land before the current one was even built.
        const staleHashes = new Set([...(resume?.staleUserOpHashes || []), ...(stale?.hashes || [])].map(hash => String(hash).toLowerCase()));
        const lookupHashes = () => [...new Set([...hashes, ...staleHashes])];
        const fromBlock = earliestBlock(resume?.submittedAtBlock, resume?.staleSubmittedAtBlock, staleHashes.size ? stale?.fromBlock : null)
            ?? await this.gaslessBlockNumber(context);
        const sent = error => Object.assign(error, { userOpSent: true });
        const settleInclusion = async found => {
            await journal.rememberTransaction(found.transactionHash);
            onStatus(`Sponsored operation included in ${this.compact(found.transactionHash)} · reading its settlement…`);
            let receipt;
            try {
                receipt = await this.gaslessTransactionReceipt(context, found.transactionHash);
            } catch (error) {
                throw sent(error);
            }
            // Settled under the hash the EntryPoint emitted: an inclusion
            // named by the bundler under its own hash (bundler_hash_mismatch)
            // carries the locally computed one in its UserOperationEvent.
            const hash = emittedUserOpHash(receipt, {
                entryPoint: pins.entryPoint, sender: context.transit.account,
                candidates: [found.userOpHash, built?.hash, ...lookupHashes()], nonce: built?.op?.nonce ?? null
            }) || found.userOpHash;
            return { receipt, hash, transactionHash: found.transactionHash, built };
        };
        const sequenceAt = async nonce => unpackNonce(decodeWord(await this.gaslessCall(context.reader, pins.entryPoint,
            encodeGetNonce(context.transit.account, unpackNonce(nonce).key)), 'getNonce')).sequence;
        const readSequence = () => sequenceAt(built.op.nonce);
        // An inclusion of S's operation at `nonce` (the journaled one by default), when the chain's nonce moved past it.
        const inclusionByNonce = async (nonce = built.op.nonce) => (await sequenceAt(nonce) > unpackNonce(nonce).sequence
            ? this.findUserOperationInclusion(context, null, fromBlock, { sender: context.transit.account, nonce })
            : null);
        // Whether an operation of this run may sit in a mempool (accepted by
        // the bundler, or journaled as submitted before a resume).
        let everSubmitted = resume?.userOpPhase === 'op_submitted';
        // Set when the chain passed validUntil while a replacement was signed.
        let chainExpired = false;
        /**
         * A replacement of an operation already sent (a fee bump, a rebuild):
         * when it cannot be prepared (its nonce moved, a dry run refused it),
         * the earlier variant may have landed meanwhile, so it is looked for
         * (by every hash, then by its nonce) before anything is reported. An
         * inclusion is returned to settle; an expiry goes to the stop, which
         * follows what was sent; any other refusal is thrown as sent.
         */
        const replace = async options => {
            if (!everSubmitted) {
                await prepare(options);
                return null;
            }
            const previous = built;
            try {
                await prepare({ ...options, replacing: previous.op.nonce });
                return null;
            } catch (error) {
                const found = await this.findUserOperationInclusion(context, lookupHashes(), fromBlock)
                    || await inclusionByNonce(previous.op.nonce).catch(() => null);
                built = previous;
                if (found) return found;
                if (error?.code === 'gasless_op_expired') {
                    chainExpired = true;
                    return null;
                }
                // A wallet's plain rejection object becomes an Error first, so the mark survives.
                throw sent(normalizeWalletError(error));
            }
        };
        if (resume?.userOp) {
            built = {
                op: userOperationFromJson(resume.userOp),
                hash: String(resume.userOpHash).toLowerCase(),
                fees: null,
                resumed: true
            };
            built.fees = { maxFeePerGas: built.op.maxFeePerGas, maxPriorityFeePerGas: built.op.maxPriorityFeePerGas };
            for (const hash of resume.userOpHashes || []) hashes.add(String(hash).toLowerCase());
            hashes.add(built.hash);
            onStatus(`Resuming the sponsored operation ${this.compact(built.hash)}…`);
            // A journaled operation is looked for on chain before anything is
            // sent again (§3.2: logs by local hash, then the nonce, then the
            // re-send): a crash between the send and the submission write
            // must not lose a settlement the bundle already carries.
            const found = await this.findUserOperationInclusion(context, lookupHashes(), fromBlock) || await inclusionByNonce();
            if (found) return settleInclusion(found);
        } else {
            // An operation released earlier (an expiry stop before this
            // re-proof) may have landed meanwhile: it is looked for (by its
            // hashes, then by its nonce) before a replacement is built, dry-run
            // and signed, so its settlement is never mistaken for a refusal
            // of the replacement (NoteNotActive).
            if (staleHashes.size) {
                const found = await this.findUserOperationInclusion(context, [...staleHashes], fromBlock)
                    || (stale?.nonce != null ? await inclusionByNonce(BigInt(stale.nonce)) : null);
                if (found) return settleInclusion(found);
            }
            await prepare();
        }
        if (selfBundle) {
            onStatus('Confirm the bundle transaction in MetaMask. The paymaster still pays the operation’s gas and refunds your account as its beneficiary.');
            let transactionHash = null;
            const receipt = await this.sendContractTransaction(
                from,
                pins.entryPoint,
                encodeHandleOps([built.op], from),
                async hash => {
                    transactionHash = hash;
                    await journal.rememberTransaction(hash);
                    onStatus(`Bundle transaction submitted ${this.compact(hash)} · waiting for confirmation…`);
                },
                null,
                null,
                { kind: 'gasless-self-bundle', submission }
            );
            return { receipt, hash: built.hash, transactionHash: transactionHash || receipt?.transactionHash || null, built };
        }
        if (!bundler) throw this.gaslessBundlerUnavailable(null);
        let submittedAt = resume?.userOpSubmittedAt ?? null;
        let sentHash = resume?.userOpPhase === 'op_submitted';
        let lastLogPoll = 0;
        let resends = 0;
        let rebuilds = 0;
        const started = Date.now();
        for (;;) {
            const timing = this.gaslessTiming;
            if (chainExpired || expired()) {
                // §3.1: no new operation for this key while an older one may
                // still be in a mempool, unless its validUntil has passed.
                // The sent one is followed until it is included (settled
                // here), the bundler no longer knows it, or the chain is
                // past its validUntil; only then is it released for a re-proof.
                if (everSubmitted) {
                    const found = await this.awaitReleasedUserOp(context, {
                        hashes: lookupHashes(), validUntil, fromBlock, inclusionByNonce, onStatus, journal
                    });
                    if (found) return settleInclusion(found);
                }
                await journal.release().catch(() => null);
                const stopped = gaslessError('gasless_op_expired', everSubmitted ? { releasedNonce: built.op.nonce.toString() } : null);
                throw sentHash ? sent(stopped) : stopped;
            }
            if (!sentHash) {
                let bundlerHash;
                try {
                    bundlerHash = await bundler.sendUserOperation(userOperationJson(built.op), pins.entryPoint);
                } catch (error) {
                    if (error?.code === 'bundler_unavailable') throw this.gaslessBundlerUnavailable(error);
                    if (this.gaslessAlreadyKnown(error)) {
                        bundlerHash = built.hash;
                    } else if (error?.silent && (error.aa === 'AA10' || error.aa === 'AA25')) {
                        // The bundler's view of S may lag the chain (or lie):
                        // the read RPC decides. AA25 with the chain's nonce
                        // moved past the op means an inclusion to find, not a
                        // rebuild; unchanged, the refusal is the bundler's. A
                        // rebuild (which prompts again) is bounded like the
                        // dry run's.
                        const refused = () => {
                            const rejected = gaslessError('bundler_rejected', {
                                method: 'eth_sendUserOperation', aa: error.aa, rpcCode: error.rpcCode ?? null, rpcMessage: error.rpcMessage || error.message || null
                            }, error.aa === 'AA25'
                                ? 'The bundler refused the operation’s nonce although the chain has not moved it. Try again later, use another bundler, or pay the fee from a wallet.'
                                : 'The bundler says the transit account already exists although the chain shows no code. Try again later, use another bundler, or pay the fee from a wallet.');
                            rejected.aa = error.aa;
                            rejected.cause = error;
                            return rejected;
                        };
                        if (error.aa === 'AA25') {
                            if (await readSequence() <= unpackNonce(built.op.nonce).sequence) throw refused();
                            const inclusion = await this.findUserOperationInclusion(context, lookupHashes(), fromBlock) || await inclusionByNonce();
                            if (inclusion) return settleInclusion(inclusion);
                        } else {
                            const code = await context.reader({ method: 'eth_getCode', params: [context.transit.account, 'latest'] });
                            if (!code || code === '0x') throw refused();
                        }
                        if (rebuilds >= GASLESS_BUNDLER_REBUILD_LIMIT) throw refused();
                        rebuilds += 1;
                        if (!everSubmitted) await journal.release().catch(() => null);
                        const landed = await replace({ withInitCode: error.aa === 'AA10' ? false : null });
                        if (landed) return settleInclusion(landed);
                        continue;
                    } else if (this.gaslessFeeTooLow(error)) {
                        // The first send as much as a re-send: a bundler
                        // whose minimum fee is above this op's refuses the
                        // identical bytes forever, so it is signed again with
                        // both fee fields raised, until the ceilings stop it
                        // (gasless_fee_bump_exhausted).
                        onStatus('The bundler asks for a higher fee. The operation is signed again with fees raised by 12.5%…');
                        const landed = await replace({ fees: bump(), withInitCode: built.withInitCode });
                        if (landed) return settleInclusion(landed);
                        continue;
                    } else {
                        throw error;
                    }
                }
                const ambiguous = bundlerHash !== built.hash;
                if (ambiguous) {
                    hashes.add(bundlerHash);
                    onStatus(GASLESS_MESSAGES.bundler_hash_mismatch);
                }
                await journal.rememberSubmission({ hash: bundlerHash, ambiguous });
                submittedAt = Date.now();
                sentHash = true;
                everSubmitted = true;
                onStatus(`Sponsored operation submitted ${this.compact(built.hash)} · waiting for its bundle…`);
            }
            // The bundler's receipt names the bundle transaction; the chain decides.
            let found = null;
            for (const hash of hashes) {
                let receipt = null;
                try {
                    receipt = await bundler.getUserOperationReceipt(hash);
                } catch {
                    receipt = null;
                }
                const transactionHash = userOperationReceiptTransactionHash(receipt);
                if (transactionHash) {
                    found = { userOpHash: hash, transactionHash };
                    break;
                }
            }
            if (!found && (lastLogPoll === 0 || Date.now() - lastLogPoll >= timing.logPollMs)) {
                lastLogPoll = Date.now();
                found = await this.findUserOperationInclusion(context, lookupHashes(), fromBlock);
                // Still following: the claim stays live for other tabs.
                if (!found) await journal.heartbeat?.().catch(() => null);
            }
            if (found) return settleInclusion(found);
            if (submittedAt != null && Date.now() - submittedAt >= timing.resendAfterMs) {
                let known = null;
                try {
                    known = await bundler.getUserOperationByHash(built.hash);
                } catch {
                    known = null;
                }
                if (known) {
                    submittedAt = Date.now();
                    await journal.heartbeat?.().catch(() => null);
                } else {
                    // Unknown to the bundler: included under another route, or dropped.
                    const inclusion = await inclusionByNonce();
                    if (inclusion) return settleInclusion(inclusion);
                    resends += 1;
                    sentHash = false;
                    onStatus(resends === 1 ? 'The bundler no longer knows the operation. The identical operation is sent again…'
                        : 'The operation is still not included. It is sent again…');
                    continue;
                }
            }
            if (Date.now() - started > timing.giveUpAfterMs && timing.giveUpAfterMs) {
                throw sent(gaslessError('gasless_op_pending', null, 'The sponsored operation is not included yet. It stays journaled and is checked in the background.'));
            }
            await this.gaslessSleep(timing.receiptPollMs);
        }
    }

    /**
     * After the expiry stop: follow the operation(s) already sent until one
     * is included (returned, to settle), the bundler reports every hash
     * unknown (dropped), or the latest block is past their validUntil (the
     * EntryPoint can no longer include them); then null, and a replacement
     * may be built. Bounded by validUntil, i.e. by the stop's 60 s margin.
     */
    async awaitReleasedUserOp(context, { hashes, validUntil, fromBlock, inclusionByNonce, onStatus, journal = null }) {
        const { bundler } = context;
        const timing = this.gaslessTiming;
        const onChain = async () => (await this.findUserOperationInclusion(context, hashes, fromBlock))
            || (await inclusionByNonce().catch(() => null));
        onStatus('The withdrawal proof is close to its expiry. The operation already sent is followed until it is included or can no longer be, before a new one is prepared…');
        let lastLogPoll = 0;
        for (;;) {
            for (const hash of hashes) {
                let receipt = null;
                try {
                    receipt = bundler ? await bundler.getUserOperationReceipt(hash) : null;
                } catch {
                    receipt = null;
                }
                const transactionHash = userOperationReceiptTransactionHash(receipt);
                if (transactionHash) return { userOpHash: hash, transactionHash };
            }
            if (lastLogPoll === 0 || Date.now() - lastLogPoll >= timing.logPollMs) {
                lastLogPoll = Date.now();
                const found = await onChain();
                if (found) return found;
                await journal?.heartbeat?.().catch(() => null);
            }
            let timestamp = null;
            try {
                const block = await context.reader({ method: 'eth_getBlockByNumber', params: ['latest', false] });
                timestamp = block?.timestamp == null ? null : Number(toBigInt(block.timestamp, 'timestamp'));
            } catch {
                timestamp = null;
            }
            if ((timestamp ?? Date.now() / 1_000) > Number(validUntil)) return onChain();
            let known = false;
            for (const hash of hashes) {
                try {
                    const entry = bundler ? await bundler.getUserOperationByHash(hash) : null;
                    if (entry?.transactionHash) return { userOpHash: hash, transactionHash: String(entry.transactionHash).toLowerCase() };
                    if (entry) known = true;
                } catch {
                    // An unreachable bundler may still hold it: wait for validUntil.
                    known = true;
                }
            }
            if (!known) return onChain();
            await this.gaslessSleep(timing.receiptPollMs);
        }
    }

    /** The `bundler_unavailable` refusal, naming the fallbacks the host can offer. */
    gaslessBundlerUnavailable(cause) {
        const error = gaslessError('bundler_unavailable', { fallbacks: ['self_bundle', 'direct_call'], detail: cause?.message || null });
        error.cause = cause;
        error.withdrawalNeedsAction = true;
        return error;
    }

    /**
     * What the user is told before signing (§3.1): for a close, finalize or
     * forward, the floor the payout address receives; for an escape, only
     * the bound on this start's debt and an estimate at today's fees, since
     * the finalization's fee is measured when it is sent (its own floor is
     * shown when it is signed).
     */
    gaslessAmountsMessage(built) {
        const amounts = built.amounts;
        const eth = value => formatUnits(value / NATIVE_WEI_PER_UNIT, 9);
        if (amounts.kind === KIND.escape) {
            return `The escape is sponsored: nothing is paid now. Its finalization deducts at most ${eth(amounts.initiationDebtMax)} ETH for this start (its network fee and the paymaster’s flat fee), plus the finalization’s own fee and flat fee, measured when the finalization is sent; at current fees the payout address would receive about ${eth(amounts.estimatedReceived)} ETH. The guaranteed minimum is shown when the finalization is signed.`;
        }
        return `The payout address receives at least ${eth(amounts.minimumReceived)} ETH: the sponsored network fee is at most ${eth(amounts.maxCost)} ETH`
            + `${amounts.flatFee ? ` plus a ${eth(amounts.flatFee)} ETH flat fee` : ''}${amounts.owed ? ` and ${eth(amounts.owed)} ETH of earlier debt` : ''}; the exact charge is measured on chain.`;
    }

    gaslessSettledMessage(amounts, credited) {
        const eth = value => formatUnits(toBigInt(value) / NATIVE_WEI_PER_UNIT, 9);
        const parts = `charged ${eth(amounts.chargedWei)} ETH${toBigInt(amounts.owedPaidWei) ? `, ${eth(amounts.owedPaidWei)} ETH of debt paid` : ''}`;
        if (credited) return `${GASLESS_MESSAGES.payout_credited} (${parts}, ${eth(amounts.paymasterCreditedWei ?? 0n)} ETH credited.)`;
        return `Withdrawal settled: ${parts}, ${eth(amounts.paidOutWei)} ETH paid out.`;
    }

    /** The prepared plan's write-ahead journal of a sponsored operation (§3.2 table). */
    preparedUserOpJournal(submission, context) {
        return {
            rememberBuilt: async built => browserWalletRuntime.rememberPreparedWithdrawalUserOp(submission, {
                userOp: userOperationJson(built.op), userOpHash: built.hash, userOpNonce: built.op.nonce.toString(),
                userOpInitCode: built.withInitCode === true, bundlerUrl: context.bundlerUrl, submittedAtBlock: await this.gaslessBlockNumber(context)
            }),
            rememberSubmission: details => browserWalletRuntime.rememberPreparedWithdrawalUserOpSubmission(submission, details),
            rememberTransaction: hash => browserWalletRuntime.rememberPreparedWithdrawalTransaction(hash, submission, null),
            release: () => browserWalletRuntime.releasePreparedWithdrawalUserOp(submission),
            heartbeat: () => browserWalletRuntime.touchPreparedWithdrawalUserOp(submission)
        };
    }

    /** A withdrawal record's write-ahead journal of a finalization ('finalize') or forward ('forward') operation. */
    recordUserOpJournal(recordId, prefix, { submission = null, context }) {
        const field = name => `${prefix}UserOp${name}`;
        const current = async () => (await browserWalletRuntime.currentWithdrawal(recordId)) || {};
        return {
            rememberBuilt: async built => {
                const record = await current();
                await browserWalletRuntime.updateWithdrawal(recordId, {
                    [field('')]: userOperationJson(built.op),
                    [field('Hash')]: built.hash,
                    [field('Hashes')]: [...new Set([...(record[field('Hashes')] || []), built.hash])],
                    [field('Block')]: await this.gaslessBlockNumber(context),
                    [field('BuiltAt')]: Date.now(),
                    [field('Phase')]: 'op_built',
                    bundlerUrl: context.bundlerUrl
                });
            },
            rememberSubmission: async ({ hash, ambiguous }) => {
                const record = await current();
                await browserWalletRuntime.updateWithdrawal(recordId, {
                    [field('Hashes')]: [...new Set([...(record[field('Hashes')] || []), ...(hash ? [hash] : [])])],
                    [field('SubmittedAt')]: Date.now(),
                    [field('Ambiguous')]: Boolean(ambiguous) || record[field('Ambiguous')] === true,
                    [field('Phase')]: 'op_submitted'
                });
            },
            rememberTransaction: async hash => {
                if (prefix === 'finalize' && submission) {
                    await browserWalletRuntime.rememberWithdrawalFinalization(recordId, hash, submission, null);
                    return;
                }
                const record = await current();
                await browserWalletRuntime.updateWithdrawal(recordId, {
                    [`${prefix}TransactionHash`]: hash,
                    [`${prefix}TransactionHashes`]: [...new Set([...(record[`${prefix}TransactionHashes`] || []), hash])]
                });
            },
            release: async () => {
                await browserWalletRuntime.updateWithdrawal(recordId, {
                    [field('')]: null, [field('Hash')]: null, [field('Phase')]: null, [field('SubmittedAt')]: null, [field('FollowedAt')]: null
                });
            },
            // The following client's heartbeat (see touchPreparedWithdrawalUserOp).
            heartbeat: () => browserWalletRuntime.updateWithdrawal(recordId, { [field('FollowedAt')]: Date.now() })
        };
    }

    /** The journaled operation of a record under `prefix`, in the shape `runGaslessOperation` resumes. */
    recordUserOpResume(record, prefix) {
        if (!record?.[`${prefix}UserOp`] || !record[`${prefix}UserOpHash`]) return null;
        return {
            userOp: record[`${prefix}UserOp`],
            userOpHash: record[`${prefix}UserOpHash`],
            userOpHashes: record[`${prefix}UserOpHashes`] || [],
            userOpPhase: record[`${prefix}UserOpPhase`] || 'op_built',
            userOpSubmittedAt: record[`${prefix}UserOpSubmittedAt`] ?? null,
            submittedAtBlock: record[`${prefix}UserOpBlock`] ?? null
        };
    }

    /**
     * `withdraw(mode, onStatus, { fees: 'payout', ... })`: the sponsored
     * branch of performWithdrawal (§3.2). The destination Y defaults to the
     * connected account, which also becomes the owner of S; the plan is
     * prepared with destination S; no eth_sendTransaction is ever sent.
     */
    async performGaslessWithdrawal(mode, onStatus, options) {
        // The plan's claims this call takes are followed until it returns or
        // throws; afterwards a resume (here or in another client of the
        // runtime) may take them over.
        const claimed = new Set();
        try {
            return await this.followGaslessWithdrawal(mode, onStatus, { ...options, claimed });
        } finally {
            for (const submissionId of claimed) browserWalletRuntime.endGaslessClaim(submissionId);
        }
    }

    async followGaslessWithdrawal(mode, onStatus, { requestedDestination, concede, feeCapWei, bundlerUrl, allowExpensiveGas, selfBundle, from,
        durablePrepared, note, claimed }) {
        if (durablePrepared && !isGaslessWithdrawal(durablePrepared)) throw gaslessError('gasless_plan_mismatch');
        if (requestedDestination && durablePrepared?.payout && durablePrepared.payout.toLowerCase() !== requestedDestination) {
            throw new Error('This withdrawal is already bound to a different destination. Resume it with its saved address.');
        }
        const payout = String(durablePrepared?.payout || requestedDestination || from).toLowerCase();
        const owner = String(durablePrepared?.transit?.owner || from).toLowerCase();
        if (durablePrepared?.transactionHash) mode = durablePrepared.mode;
        let kind = mode === 'mutual' ? KIND.close : KIND.escape;
        const vault = this.config.funding.contract_address;
        const noteId = Number(note.note_id);
        onStatus('Checking the sponsored withdrawal path…');
        const context = await this.gaslessContext({
            from, payout, owner, expectedAccount: durablePrepared?.transit?.account || null,
            bundlerUrl: bundlerUrl || durablePrepared?.bundlerUrl || null, kind, record: durablePrepared || null
        });
        const S = context.transit.account;
        if (!durablePrepared) {
            onStatus(owner === payout ? GASLESS_PRIVACY_NOTE : GASLESS_PRIVACY_NOTE_SEPARATE_PAYOUT);
            try {
                const payoutCode = await context.reader({ method: 'eth_getCode', params: [payout, 'latest'] });
                if (payoutCode && payoutCode !== '0x') onStatus(GASLESS_PAYOUT_CONTRACT_WARNING);
            } catch {
                // Advisory only.
            }
        }
        const nullifierHint = durablePrepared?.public_inputs?.withdrawal_nullifier || durablePrepared?.withdrawalNullifier
            || await browserWalletRuntime.currentWithdrawalNullifier();
        let preflight = await this.gaslessPreflight(context, {
            kind, key: kind === KIND.close ? attemptsKey(KIND.close, { nullifier: nullifierHint }) : attemptsKey(KIND.escape, { noteId })
        });
        if (!preflight.verdict.available) throw gaslessError(preflight.verdict.reason, preflight.verdict.data);
        context.state = preflight.state;

        const withdrawal = { phase: 'prepared', mode, noteId, destination: S, payout, feePayer: 'payout', transit: context.transit };
        let plan;
        let receipt;
        let hash = durablePrepared?.userOpHash || null;
        let submission = null;
        const withdrawalAttempts = Number(this.gaslessWithdrawalAttempts) > 0 ? Number(this.gaslessWithdrawalAttempts) : 4;
        let reprove = false;
        // The nonce of an operation an expiry stop released: the next run looks for it on chain before building.
        let releasedNonce = null;
        const walletRequest = this.gaslessReadsViaWallet === true ? request => this.ethereum.request(request) : null;
        try {
            for (let attempt = 0; attempt < withdrawalAttempts; attempt += 1) {
                onStatus(attempt === 0
                    ? (mode === 'mutual'
                        ? 'Checking this balance and requesting a cooperative close…'
                        : 'Preparing a unilateral escape locally…')
                    : 'The withdrawal proof expired or the vault refused its root. Proving again…');
                // A journaled operation whose proof is still valid is resumed
                // as it is (identical bytes, no new proof); its claim, held by
                // this or a crashed tab, is taken over below.
                const journaled = attempt === 0 ? await browserWalletRuntime.currentPreparedWithdrawal() : null;
                const resumable = isGaslessWithdrawal(journaled) && journaled.userOp && !journaled.transactionHash
                    && journaled.mode === mode && journaled.transit.account === S
                    && Number(journaled.public_inputs?.valid_until || 0) - this.gaslessTiming.stopBeforeValidUntilSeconds > Date.now() / 1_000;
                if (resumable) {
                    plan = journaled;
                } else {
                    const expectedActiveRoot = mode === 'mutual'
                        ? decodeWord(await this.gaslessCall(context.reader, vault, `0x${ABI.currentRoot}`), 'currentRoot')
                        : null;
                    plan = await browserWalletRuntime.prepareWithdrawal(mode, S, {
                        expectedActiveRoot,
                        reprove,
                        earlyConcession: concede,
                        walletRequest,
                        gasless: { payout, transit: context.transit },
                        onProgress: (_phase, message) => onStatus(message)
                    });
                }
                for (const warning of plan.warnings || []) {
                    if (warning?.message) onStatus(`${warning.message} It can still be submitted.`);
                }
                if (Number(plan.public_inputs?.note_id) !== noteId) {
                    throw new Error('The private wallet returned a withdrawal for a different note.');
                }
                if (plan.mode !== mode) {
                    // E2: the exit rules turned a mutual request into an escape.
                    onStatus(plan.decision?.clearance_error_code
                        ? 'The server did not grant a cooperative close, so this balance exits by escape, conceding nothing.'
                        : 'This balance exits by escape.');
                    mode = plan.mode;
                    withdrawal.mode = mode;
                    kind = mode === 'mutual' ? KIND.close : KIND.escape;
                    context.kind = kind;
                    preflight = await this.gaslessPreflight(context, { kind, key: attemptsKey(KIND.escape, { noteId }) });
                    if (!preflight.verdict.available) throw gaslessError(preflight.verdict.reason, preflight.verdict.data);
                    context.state = preflight.state;
                }
                const knownHash = plan.transactionHash || null;
                this.rememberWithdrawal({ ...withdrawal, phase: knownHash ? 'submitted' : 'prepared', transactionHash: knownHash,
                    clearanceReserved: plan.clearanceReserved === true || mode === 'mutual' });
                if (this.config) {
                    this.config.prepared_withdrawal = {
                        mode, phase: knownHash ? 'submitted' : 'prepared', note_id: noteId, destination: S, payout, fee_payer: 'payout',
                        transaction_hash: knownHash, clearance_reserved: plan.clearanceReserved === true || mode === 'mutual',
                        clearance_granted: mode === 'mutual' && Boolean(plan.clearance?.signature), user_op_hash: plan.userOpHash || null
                    };
                }
                const vaultCall = encodeWithdrawal(plan, mode, S, vault, { conceded: plan.public_inputs.conceded });
                const claim = await browserWalletRuntime.claimPreparedWithdrawalUserOp({ liveWindowMs: this.gaslessTiming.resendAfterMs });
                if (claim?.submissionId) claimed.add(claim.submissionId);
                submission = claim;
                if (claim.transactionHash) {
                    onStatus(`Checking the bundle transaction ${this.compact(claim.transactionHash)}…`);
                    receipt = await this.gaslessTransactionReceipt(context, claim.transactionHash);
                    hash = plan.userOpHash || hash;
                    break;
                }
                const late = await browserWalletRuntime.exitBeforeBroadcast().catch(() => null);
                if (late?.lateSuccessor) {
                    onStatus('A settled private request arrived after the exit proof was made. It is kept and applied if this exit expires unused.');
                }
                const validUntil = Number(plan.public_inputs.valid_until);
                const payoutWei = BigInt(plan.public_inputs.final_balance) * NATIVE_WEI_PER_UNIT;
                const nullifier = plan.public_inputs.withdrawal_nullifier;
                const build = (options = {}) => this.buildGaslessOperation(context, {
                    kind, vaultCall, nullifier, noteId, payoutWei, feeCapWei, allowExpensiveGas, state: context.state, ...options
                });
                try {
                    // Operations this plan released earlier (an expiry stop
                    // before a re-proof) may still land: their hashes and
                    // the block they were tracked from join the search.
                    const journaled = await browserWalletRuntime.currentPreparedWithdrawal().catch(() => null);
                    const outcome = await this.runGaslessOperation(context, build, this.preparedUserOpJournal(submission, context), {
                        onStatus, validUntil, selfBundle, from, submission,
                        resume: claim.status === 'resumed' ? claim : null,
                        stale: journaled?.staleUserOpHashes?.length
                            ? { hashes: journaled.staleUserOpHashes, fromBlock: journaled.staleSubmittedAtBlock ?? null, nonce: releasedNonce } : null
                    });
                    receipt = outcome.receipt;
                    hash = outcome.hash;
                    break;
                } catch (error) {
                    // A proof past its valid_until (the stop 60 s before it) or
                    // a root the vault does not know is proved again; an
                    // operation that reached a mempool is released with its
                    // proof: a late inclusion fails on the nullifier and costs
                    // one attempt (§3.1).
                    if (error?.code === 'gasless_op_expired' && error.data?.releasedNonce != null) releasedNonce = error.data.releasedNonce;
                    const reprovable = REPROVABLE_EXIT_ERRORS.includes(error?.code) || error?.code === 'gasless_op_expired';
                    if (reprovable && (error?.code === 'gasless_op_expired' || !error?.userOpSent) && attempt + 1 < withdrawalAttempts) {
                        await browserWalletRuntime.markPreparedWithdrawalRetryable(null, submission);
                        submission = null;
                        reprove = true;
                        continue;
                    }
                    throw error;
                }
            }
        } catch (failure) {
            const error = normalizeWalletError(failure);
            if (submission && (!error.userOpSent || error.code === 'gasless_op_expired') && !error.transactionHash) {
                // Nothing left the browser (or what did is past its proof):
                // release this tab's claim so the plan can be resumed or paid
                // from a wallet.
                await browserWalletRuntime.markPreparedWithdrawalRetryable(null, submission).catch(() => null);
                if (isWalletRejection(error)) {
                    error.shortMessage = 'MetaMask canceled the signature. No funds moved; the sponsored withdrawal can be resumed or paid from a wallet.';
                }
            } else if (error.userOpSent) {
                error.shortMessage = error.shortMessage || 'The sponsored operation was sent and is still being checked. It stays journaled; check the withdrawal status before anything else.';
                error.withdrawalNeedsAction = true;
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        return this.settleGaslessWithdrawal(context, { receipt, hash, mode, plan, note, submission, onStatus });
    }

    /**
     * The settlement of a sponsored close or escape from its bundle receipt:
     * the UserOperationEvent, the vault's own event (noteId filtered, destination
     * S), the paymaster's Settled / PayoutCredited / SponsorshipFailed, then the
     * unchanged vault-state confirmation and the detach with the transit fields.
     */
    async settleGaslessWithdrawal(context, { receipt, hash, mode, plan, note, submission, onStatus }) {
        const { pins, reader, transit } = context;
        const vault = this.config.funding.contract_address;
        const S = transit.account;
        const noteId = Number(note.note_id);
        const current = await browserWalletRuntime.currentPreparedWithdrawal().catch(() => null);
        const settlement = settlementOf(receipt, { entryPoint: pins.entryPoint, paymaster: pins.paymaster, hash, sender: S, payee: transit.payee });
        if (!settlement) throw new Error('The bundle transaction carries no settlement of this sponsored operation.');
        const transactionHash = settlement.transactionHash || receipt?.transactionHash || null;
        if (!settlement.success) {
            const reason = settlement.revert?.decoded?.code || null;
            const stranded = settlement.stranded || decodeBool(await this.gaslessCall(reader, pins.paymaster, encodeStranded(S)), 'stranded');
            const balance = toBigInt(await reader({ method: 'eth_getBalance', params: [S, 'latest'] }), 'balance');
            await browserWalletRuntime.rememberPreparedWithdrawalUserOpOutcome(submission, { success: false, transitBalanceWei: balance }).catch(() => null);
            const status = await this.readBrowserWithdrawalStatus(noteId, null, { request: reader });
            await browserWalletRuntime.markPreparedWithdrawalRetryable(transactionHash, submission).catch(() => null);
            // The reverted operation (under every hash it was journaled
            // under) is not a late inclusion to look for again: a retry
            // signs a new operation at the next nonce.
            const revertedHash = String(settlement.event?.userOpHash || hash || '').toLowerCase();
            const journaledHashes = (current?.userOpHashes || []).map(value => String(value).toLowerCase());
            const reverted = [revertedHash, String(hash || '').toLowerCase(),
                ...(journaledHashes.includes(revertedHash) || journaledHashes.includes(String(hash || '').toLowerCase()) ? journaledHashes : [])];
            await browserWalletRuntime.releasePreparedWithdrawalUserOp(submission, { reverted }).catch(() => null);
            if (status.status === 'closed' && (stranded || balance > 0n)) {
                // Someone else closed the note with the same public calldata:
                // the payout reached S and a sponsored forward collects it.
                await browserWalletRuntime.detachClosedWithdrawal({
                    mode: 'mutual', payoutVerified: false, noteId, destination: S, finalBalance: Number(plan.public_inputs.final_balance),
                    transactionHash, closeBlockNumber: Number(status.observed_block || 0), lastObservedBlock: Number(status.observed_block || 0),
                    clearanceReserved: true, createdAt: plan.createdAt, feePayer: 'payout', payout: transit.payee, transit,
                    userOpHash: hash, userOpHashes: current?.userOpHashes || [hash], userOpSuccess: false, fundsWaitingInTransit: balance > 0n,
                    transitBalanceWei: balance
                });
                this.rememberWithdrawal(null);
                await this.refresh();
                onStatus(GASLESS_MESSAGES.transit_funds_waiting);
                return { status: 'closed', fundsWaitingInTransit: balance > 0n, transitBalanceWei: balance.toString(), transitAccount: S,
                    reason, userOpHash: hash, transactionHash, recordId: browserWalletRuntime.withdrawalRecordId(noteId) };
            }
            const error = gaslessError('gasless_op_reverted', {
                reason, revert: settlement.revert?.decoded?.message || null, transactionHash, userOpHash: hash, stranded,
                transitBalanceWei: balance.toString()
            }, reason ? `${GASLESS_MESSAGES.gasless_op_reverted} (${settlement.revert.decoded.message})` : null);
            error.withdrawalNeedsAction = true;
            await this.refresh({ quiet: true });
            throw error;
        }
        const event = parseWithdrawalReceipt(receipt, vault, mode, { noteId });
        if (!event || event.noteId !== BigInt(noteId)
            || event.destination.toLowerCase() !== S
            || event.finalBalance !== BigInt(plan.public_inputs.final_balance)) {
            throw new Error('The operation succeeded, but its withdrawal event did not match the prepared note.');
        }
        if (mode === 'escape' && event.concession
            && (event.concession.conceded !== BigInt(plan.public_inputs.conceded)
                || event.concession.stateBalance !== BigInt(plan.public_inputs.final_balance) + BigInt(plan.public_inputs.conceded)
                || event.concession.nextNullifier !== BigInt(plan.public_inputs.next_nullifier))) {
            throw new Error('The operation succeeded, but its recorded concession did not match the prepared escape.');
        }
        const settled = settlement.settled;
        const credited = settlement.credited;
        const amounts = {
            receivedWei: settled?.received ?? 0n,
            chargedWei: settled?.charged ?? 0n,
            owedPaidWei: settled?.owedPaid ?? 0n,
            paidOutWei: settled?.paidOut ?? 0n,
            paymasterCredited: Boolean(credited),
            paymasterCreditedWei: credited?.amount ?? null
        };
        const initiationDebtWei = mode === 'escape' ? (settlement.owed?.owedWei ?? settled?.charged ?? null) : undefined;
        await browserWalletRuntime.rememberPreparedWithdrawalUserOpOutcome(submission, { success: true, ...amounts,
            ...(initiationDebtWei !== undefined ? { initiationDebtWei } : {}) }).catch(() => null);
        onStatus('Confirming the vault state and updating this browser…');
        const confirmed = await this.confirmMinedWithdrawalStatus(noteId, receipt, { request: reader });
        const shared = {
            feePayer: 'payout', payout: transit.payee, transit, userOpHash: hash, userOpHashes: current?.userOpHashes || [hash],
            userOpSuccess: true, ...amounts, fundsWaitingInTransit: false, transitBalanceWei: 0n
        };
        if (mode === 'mutual') {
            if (confirmed.status !== 'closed') {
                throw new Error(`The vault still reports this private balance as ${confirmed.status}.`);
            }
            await browserWalletRuntime.detachClosedWithdrawal({
                mode: 'mutual',
                payoutVerified: !credited && amounts.paidOutWei > 0n,
                noteId,
                destination: S,
                finalBalance: Number(event.finalBalance),
                transactionHash,
                closeBlockNumber: Number(BigInt(receipt?.blockNumber || '0x0')),
                lastObservedBlock: Number(confirmed.observed_block || 0),
                clearanceReserved: true,
                createdAt: plan.createdAt,
                ...shared
            });
            this.rememberWithdrawal(null);
            await this.refresh();
            onStatus(`${this.gaslessSettledMessage(amounts, Boolean(credited))} Finality is being checked safely in the background.`,
                { amounts: journalValue(amounts) });
            return {
                status: 'closed', event, receipt, userOpHash: hash, transactionHash, transitAccount: S, payout: transit.payee,
                amounts: journalValue(amounts), ...(credited ? { paymasterCredited: true } : {})
            };
        }
        const deadline = Number(confirmed.challenge_deadline || event.challengeDeadline);
        if (confirmed.status !== 'pending_withdrawal' || !deadline) {
            throw new Error('The escape operation settled, but the vault did not report its safety deadline.');
        }
        const record = await browserWalletRuntime.detachEscapeWithdrawal({
            noteId,
            destination: S,
            finalBalance: Number(event.finalBalance),
            challengeDeadline: deadline,
            transactionHash,
            startBlockNumber: Number(BigInt(receipt?.blockNumber || '0x0')),
            lastObservedBlock: Number(confirmed.observed_block || 0),
            createdAt: plan.createdAt,
            ...shared,
            initiationDebtWei: initiationDebtWei ?? null
        });
        this.rememberWithdrawal(null);
        await this.refresh();
        onStatus(`Escape started without a transaction fee. Its finalization will deduct the ${formatUnits(toBigInt(initiationDebtWei ?? 0n) / NATIVE_WEI_PER_UNIT, 9)} ETH this start cost. You can add a new private balance while the safety window runs.`,
            { amounts: journalValue({ ...amounts, initiationDebtWei }) });
        return {
            status: 'pending_withdrawal', deadline, event, receipt, recordId: record.recordId, conceded: BigInt(plan.public_inputs.conceded),
            decision: plan.decision || null, pathSource: plan.pathSource || null, userOpHash: hash, transactionHash, transitAccount: S,
            payout: transit.payee, initiationDebtWei: initiationDebtWei == null ? null : initiationDebtWei.toString()
        };
    }

    /**
     * The sponsored FINALIZE of a pending escape (§3.1): only after the
     * deadline; an escape someone else already finalized goes straight to a
     * FORWARD of the payout now in S.
     */
    async performGaslessFinalization(withdrawal, onStatus, options = {}) {
        const claimed = new Set();
        try {
            return await this.followGaslessFinalization(withdrawal, onStatus, { ...options, claimed });
        } finally {
            for (const submissionId of claimed) browserWalletRuntime.endGaslessClaim(submissionId);
        }
    }

    async followGaslessFinalization(withdrawal, onStatus, { bundlerUrl = null, allowExpensiveGas = false, feeCapWei = null, selfBundle = false,
        claimed = new Set() } = {}) {
        if (!isGaslessWithdrawal(withdrawal)) throw gaslessError('gasless_plan_mismatch', null,
            'This escape was started to pay its fees from a wallet, so it has no transit account to sponsor. Finalize it with fees: \'wallet\'.');
        onStatus('Connecting to MetaMask for the sponsored finalization…');
        const from = await this.connectWallet();
        const transit = withdrawal.transit;
        const context = await this.gaslessContext({
            from, payout: withdrawal.payout, owner: transit.owner, expectedAccount: transit.account,
            bundlerUrl: bundlerUrl || withdrawal.bundlerUrl || null, kind: KIND.finalize, record: withdrawal
        });
        const noteId = Number(withdrawal.noteId);
        const vault = this.config.funding.contract_address;
        const S = transit.account;
        const status = await this.readBrowserWithdrawalStatus(noteId, null, { request: context.reader });
        // This record's own finalization journaled earlier (op_built /
        // op_submitted) may have been included while no one followed it: the
        // chain is asked first (§3.2 resume order: logs by hash, then the
        // nonce), so a closed vault status is not mistaken for a third party's.
        const ownInclusion = withdrawal.finalizeTransactionHash ? null : await this.recordUserOpInclusion(context, withdrawal, 'finalize');
        if (status.status === 'closed' && !ownInclusion) {
            onStatus('The escape was already finalized by someone else. Collecting the payout from the transit account…');
            return this.performTransitForward(withdrawal, onStatus, { context, from, bundlerUrl, allowExpensiveGas, feeCapWei, selfBundle });
        }
        let pendingNullifier = null;
        let payoutWei = null;
        let challengeDeadline = null;
        if (!ownInclusion) {
            if (status.status !== 'pending_withdrawal') throw new Error(`The vault reports this balance as ${status.status}, not as a pending escape.`);
            if (String(status.destination || '').toLowerCase() !== S) throw new Error('The pending escape does not pay this withdrawal’s transit account.');
            pendingNullifier = BigInt(status.withdrawal_nullifier);
            payoutWei = BigInt(status.final_balance) * NATIVE_WEI_PER_UNIT;
            challengeDeadline = Number(status.challenge_deadline ?? withdrawal.challengeDeadline);
            const preflight = await this.gaslessPreflight(context, { kind: KIND.finalize, key: attemptsKey(KIND.finalize, { noteId }), noteId });
            if (!preflight.verdict.available) throw gaslessError(preflight.verdict.reason, preflight.verdict.data);
            context.state = preflight.state;
        }
        let submittedHash = withdrawal.finalizeTransactionHash || null;
        let submission = null;
        let receipt;
        let hash = ownInclusion?.userOpHash || withdrawal.finalizeUserOpHash || null;
        try {
            // A finalization already included settles under this record's
            // own claim; otherwise a journaled one no client follows any more
            // is taken over (no prompt), and a fresh one is claimed.
            const claim = ownInclusion && withdrawal.finalizeSubmissionId ? {
                status: 'resumed', transactionHash: null, recordId: withdrawal.recordId, submissionId: withdrawal.finalizeSubmissionId,
                operationId: withdrawal.finalizeOperationId, generation: Number(withdrawal.finalizeGeneration || 0),
                deploymentId: withdrawal.deploymentId, chainId: Number(withdrawal.chainId), contractAddress: withdrawal.contractAddress,
                noteId: Number(withdrawal.noteId), destination: withdrawal.destination, record: withdrawal
            } : await browserWalletRuntime.claimWithdrawalFinalization(withdrawal.recordId, {
                resumeUserOp: true, liveWindowMs: this.gaslessTiming.resendAfterMs
            });
            if (claim.submissionId && !claim.transactionHash) claimed.add(claim.submissionId);
            submittedHash = claim.transactionHash || null;
            submission = claim;
            withdrawal = claim.record;
            if (!submittedHash && ownInclusion) {
                await browserWalletRuntime.rememberWithdrawalFinalization(withdrawal.recordId, ownInclusion.transactionHash, claim, null);
                onStatus(`Sponsored finalization included in ${this.compact(ownInclusion.transactionHash)} · reading its settlement…`);
                submittedHash = ownInclusion.transactionHash;
            }
            if (submittedHash) {
                onStatus(`Checking the bundle transaction ${this.compact(submittedHash)}…`);
                receipt = await this.gaslessTransactionReceipt(context, submittedHash);
            } else {
                const build = (options = {}) => this.buildGaslessOperation(context, {
                    kind: KIND.finalize, vaultCall: encodeFinalizeEscape(noteId), nullifier: pendingNullifier, noteId, payoutWei, feeCapWei,
                    allowExpensiveGas, state: context.state, ...options
                });
                const outcome = await this.runGaslessOperation(context, build, this.recordUserOpJournal(withdrawal.recordId, 'finalize', { submission, context }), {
                    onStatus, selfBundle, from, submission, resume: this.recordUserOpResume(withdrawal, 'finalize'),
                    // The paymaster's validAfter is the vault's deadline (AA32 before it).
                    validAfter: challengeDeadline
                });
                receipt = outcome.receipt;
                hash = outcome.hash;
                submittedHash = outcome.transactionHash;
            }
        } catch (failure) {
            const error = normalizeWalletError(failure);
            if (submission && !error.userOpSent && !error.transactionHash) {
                await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, { submission }).catch(() => null);
                if (isWalletRejection(error)) error.shortMessage = 'MetaMask canceled the signature. The escape is still safe and can be finalized later.';
            } else if (error.userOpSent) {
                error.withdrawalNeedsAction = true;
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        const settlement = settlementOf(receipt, { entryPoint: context.pins.entryPoint, paymaster: context.pins.paymaster, hash, sender: S, payee: transit.payee });
        if (!settlement) throw new Error('The bundle transaction carries no settlement of this finalization.');
        if (!settlement.success) {
            await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, { transactionHash: settlement.transactionHash }).catch(() => null);
            // Its hashes are set aside as reverted: a retry looks for no
            // earlier inclusion of them and builds a new operation.
            const journaled = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId).catch(() => null) || withdrawal;
            await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
                finalizeUserOp: null, finalizeUserOpPhase: 'reverted',
                ...this.revertedRecordUserOpFields(journaled, 'finalize', [hash, settlement.event?.userOpHash])
            }).catch(() => null);
            const after = await this.readBrowserWithdrawalStatus(noteId, null, { request: context.reader });
            if (after.status === 'closed') {
                onStatus('A third party finalized this escape first. Collecting the payout from the transit account…');
                await this.refresh({ quiet: true });
                return this.performTransitForward(await browserWalletRuntime.currentWithdrawal(withdrawal.recordId) || withdrawal, onStatus,
                    { context, from, bundlerUrl, allowExpensiveGas, feeCapWei, selfBundle });
            }
            const error = gaslessError('gasless_op_reverted', { reason: settlement.revert?.decoded?.code || null, transactionHash: settlement.transactionHash, userOpHash: hash });
            error.withdrawalNeedsAction = true;
            await this.refresh({ quiet: true });
            throw error;
        }
        const event = parseWithdrawalReceipt(receipt, vault, 'finalize', { noteId });
        const receiptBlock = Number(BigInt(receipt?.blockNumber || '0x0'));
        const match = event ? await this.escapePayoutMatch(withdrawal, event.finalBalance, receiptBlock, { request: context.reader }) : null;
        if (!event || event.noteId !== BigInt(noteId) || event.destination.toLowerCase() !== S || !match?.accepted) {
            throw new Error('The finalization event did not match the pending withdrawal.');
        }
        const confirmed = await this.confirmMinedWithdrawalStatus(noteId, receipt, { request: context.reader });
        if (confirmed.status !== 'closed') throw new Error(`The vault reports ${confirmed.status} after finalization.`);
        const settled = settlement.settled;
        const credited = settlement.credited;
        const amounts = {
            receivedWei: settled?.received ?? 0n, chargedWei: settled?.charged ?? 0n, owedPaidWei: settled?.owedPaid ?? 0n,
            paidOutWei: settled?.paidOut ?? 0n, paymasterCredited: Boolean(credited), paymasterCreditedWei: credited?.amount ?? null
        };
        await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
            phase: 'closed_unconfirmed',
            chainStatus: 'closed',
            payoutVerified: !credited && amounts.paidOutWei > 0n,
            payoutCredited: false,
            ...journalValue(amounts),
            finalizeUserOpHash: hash,
            finalizeUserOpPhase: 'settled',
            ...this.payoutMatchFields({ amount: Number(event.finalBalance), match }, onStatus),
            closedAt: Date.now(),
            closeBlockNumber: receiptBlock,
            lastObservedBlock: Number(confirmed.observed_block || 0),
            fundsWaitingInTransit: false,
            transitBalanceWei: '0',
            error: null
        });
        await this.refresh();
        onStatus(`${this.gaslessSettledMessage(amounts, Boolean(credited))} Finality is being checked safely in the background.`,
            { amounts: journalValue(amounts) });
        return { status: 'closed', event, receipt, userOpHash: hash, transactionHash: submittedHash, amounts: journalValue(amounts),
            ...(credited ? { paymasterCredited: true } : {}) };
    }

    /**
     * The status line for a payout waiting in a plan's or record's transit
     * account S. A sponsored forward is named only when the paymaster holds
     * the evidence its forward rule requires (stranded[S], or
     * escapeNotePlusOne[S] of a closed escape: a sponsored close or
     * finalization that reverted, or a sponsored escape); a wallet-paid
     * close or escape to S leaves none, so only sweepTransit is named.
     * Read-only, through the journaled paymaster; any failure names the sweep.
     */
    async transitFundsMessage(record, { reader = null } = {}) {
        const context = this.recordReaderContext(record, reader || this.gaslessReader());
        if (!context) return GASLESS_MESSAGES.transit_sweep_needed;
        try {
            const S = context.transit.account;
            if (decodeBool(await this.gaslessCall(context.reader, context.pins.paymaster, encodeStranded(S)), 'stranded')) {
                return GASLESS_MESSAGES.transit_funds_waiting;
            }
            const notePlusOne = decodeWord(await this.gaslessCall(context.reader, context.pins.paymaster, encodeEscapeNotePlusOne(S)), 'escapeNotePlusOne');
            if (notePlusOne !== 0n) {
                const status = await this.readBrowserWithdrawalStatus(Number(notePlusOne - 1n), null, { request: context.reader });
                if (status.status === 'closed') return GASLESS_MESSAGES.transit_funds_waiting;
            }
        } catch {
            // Unknown evidence: the sweep works either way.
        }
        return GASLESS_MESSAGES.transit_sweep_needed;
    }

    /**
     * `collectTransitBalance(recordId, onStatus)`: a sponsored FORWARD of the
     * balance sitting in S, with the paymaster's evidence (`stranded`, or the
     * record of S's sponsored escape that a third party finalized) (§2.4).
     */
    async collectTransitBalance(recordId, onStatus = () => {}, options = {}) {
        const record = await browserWalletRuntime.currentWithdrawal(recordId);
        if (!record) throw new Error('The withdrawal record was not found.');
        if (!isGaslessWithdrawal(record)) throw gaslessError('gasless_plan_mismatch', null, 'This withdrawal has no transit account to collect from.');
        return this.performTransitForward(record, onStatus, options);
    }

    async performTransitForward(withdrawal, onStatus, { context = null, from = null, bundlerUrl = null, allowExpensiveGas = false, feeCapWei = null,
        selfBundle = false } = {}) {
        const transit = withdrawal.transit;
        if (!from) {
            onStatus('Connecting to MetaMask to collect the transit balance…');
            from = await this.connectWallet();
        }
        if (!context) {
            context = await this.gaslessContext({
                from, payout: withdrawal.payout, owner: transit.owner, expectedAccount: transit.account,
                bundlerUrl: bundlerUrl || withdrawal.bundlerUrl || null, kind: KIND.forward, record: withdrawal
            });
        }
        context.kind = KIND.forward;
        const journal = this.recordUserOpJournal(withdrawal.recordId, 'forward', { context });
        // This record's own forward journaled earlier (op_built /
        // op_submitted) may have been included while no one followed it: the
        // chain is asked first (logs by hash, then the nonce), so an emptied
        // transit account is settled as the record's own collection, not
        // reported as nothing to collect.
        const ownInclusion = ['op_built', 'op_submitted'].includes(withdrawal.forwardUserOpPhase)
            ? await this.recordUserOpInclusion(context, withdrawal, 'forward') : null;
        let balance = null;
        let outcome;
        if (ownInclusion) {
            onStatus(`Sponsored collection included in ${this.compact(ownInclusion.transactionHash)} · reading its settlement…`);
            await journal.rememberTransaction(ownInclusion.transactionHash);
            outcome = {
                receipt: await this.gaslessTransactionReceipt(context, ownInclusion.transactionHash),
                hash: ownInclusion.userOpHash,
                transactionHash: ownInclusion.transactionHash
            };
        } else {
            outcome = await this.submitTransitForward(withdrawal, onStatus, { context, from, allowExpensiveGas, feeCapWei, selfBundle, journal });
            balance = outcome.balance;
        }
        return this.settleTransitForward(withdrawal, onStatus, { context, outcome, balance });
    }

    /** A new sponsored FORWARD of S's balance, with the paymaster's evidence that it is stranded (§2.4). */
    async submitTransitForward(withdrawal, onStatus, { context, from, allowExpensiveGas, feeCapWei, selfBundle, journal }) {
        const { pins, reader } = context;
        const S = withdrawal.transit.account;
        const noteId = Number(withdrawal.noteId);
        const balance = toBigInt(await reader({ method: 'eth_getBalance', params: [S, 'latest'] }), 'balance');
        if (balance === 0n) {
            await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, { fundsWaitingInTransit: false, transitBalanceWei: '0' }).catch(() => null);
            await this.refresh({ quiet: true });
            throw gaslessError('transit_balance_empty', { transitAccount: S });
        }
        const stranded = decodeBool(await this.gaslessCall(reader, pins.paymaster, encodeStranded(S)), 'stranded');
        const notePlusOne = decodeWord(await this.gaslessCall(reader, pins.paymaster, encodeEscapeNotePlusOne(S)), 'escapeNotePlusOne');
        let escapeClosed = false;
        if (notePlusOne !== 0n) {
            const status = await this.readBrowserWithdrawalStatus(Number(notePlusOne - 1n), null, { request: reader });
            escapeClosed = status.status === 'closed';
        }
        if (!stranded && !escapeClosed) {
            await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, { fundsWaitingInTransit: true, transitBalanceWei: balance.toString() }).catch(() => null);
            await this.refresh({ quiet: true });
            throw gaslessError('transit_not_stranded', { transitAccount: S, transitBalanceWei: balance.toString() });
        }
        const preflight = await this.gaslessPreflight(context, { kind: KIND.forward, key: attemptsKey(KIND.forward, { sender: S }) });
        if (!preflight.verdict.available) throw gaslessError(preflight.verdict.reason, preflight.verdict.data);
        context.state = preflight.state;
        const build = (options = {}) => this.buildGaslessOperation(context, {
            kind: KIND.forward, vaultCall: '0x', noteId, payoutWei: balance, feeCapWei, allowExpensiveGas, state: context.state, ...options
        });
        let outcome;
        try {
            outcome = await this.runGaslessOperation(context, build, journal, {
                onStatus, selfBundle, from, resume: this.recordUserOpResume(withdrawal, 'forward'),
                submission: { recordId: withdrawal.recordId, noteId, destination: S },
                amountsMessage: built => `The payout address receives at least ${formatUnits(built.amounts.minimumReceived / NATIVE_WEI_PER_UNIT, 9)} ETH of the ${formatUnits(balance / NATIVE_WEI_PER_UNIT, 9)} ETH in the transit account; the sponsored fee is at most ${formatUnits(built.amounts.maxCost / NATIVE_WEI_PER_UNIT, 9)} ETH${built.amounts.owed ? ` and ${formatUnits(built.amounts.owed / NATIVE_WEI_PER_UNIT, 9)} ETH of debt is deducted` : ''}.`
            });
        } catch (failure) {
            const error = normalizeWalletError(failure);
            if (error.userOpSent) error.withdrawalNeedsAction = true;
            await this.refresh({ quiet: true });
            throw error;
        }
        return { ...outcome, balance };
    }

    /** The settlement of a forward from its bundle receipt: the paymaster's Settled / PayoutCredited for S. */
    async settleTransitForward(withdrawal, onStatus, { context, outcome, balance = null }) {
        const { pins } = context;
        const transit = withdrawal.transit;
        const S = transit.account;
        const settlement = settlementOf(outcome.receipt, { entryPoint: pins.entryPoint, paymaster: pins.paymaster, hash: outcome.hash, sender: S, payee: transit.payee });
        if (!settlement?.success) {
            const journaled = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId).catch(() => null) || withdrawal;
            await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
                forwardUserOp: null, forwardUserOpPhase: null,
                ...(settlement ? this.revertedRecordUserOpFields(journaled, 'forward', [outcome.hash, settlement.event?.userOpHash]) : {})
            }).catch(() => null);
            const error = gaslessError('gasless_op_reverted', { reason: settlement?.revert?.decoded?.code || null, transactionHash: outcome.transactionHash, userOpHash: outcome.hash });
            await this.refresh({ quiet: true });
            throw error;
        }
        const settled = settlement.settled;
        const credited = settlement.credited;
        const amounts = {
            receivedWei: settled?.received ?? balance ?? 0n, chargedWei: settled?.charged ?? 0n, owedPaidWei: settled?.owedPaid ?? 0n,
            paidOutWei: settled?.paidOut ?? 0n, paymasterCredited: Boolean(credited), paymasterCreditedWei: credited?.amount ?? null
        };
        await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
            ...journalValue(amounts),
            payoutVerified: !credited && amounts.paidOutWei > 0n,
            forwardUserOpHash: outcome.hash,
            forwardUserOpPhase: 'settled',
            forwardTransactionHash: outcome.transactionHash,
            fundsWaitingInTransit: false,
            transitBalanceWei: '0',
            error: null
        });
        await this.refresh();
        onStatus(this.gaslessSettledMessage(amounts, Boolean(credited)), { amounts: journalValue(amounts) });
        return { status: 'collected', recordId: withdrawal.recordId, userOpHash: outcome.hash, transactionHash: outcome.transactionHash,
            amounts: journalValue(amounts), ...(credited ? { paymasterCredited: true } : {}) };
    }

    /**
     * `sweepTransit(recordId, onStatus)`: the wallet-paid fallback for a
     * payout sitting in S: `factory.createAccount(owner, payee)` first when
     * S has no code, then `S.sweep()`, two transactions by any ETH-holding
     * account; the paymaster deducts what S owes and pushes the rest to Y.
     */
    async sweepTransit(recordId, onStatus = () => {}) {
        const record = await browserWalletRuntime.currentWithdrawal(recordId);
        if (!record) throw new Error('The withdrawal record was not found.');
        if (!isGaslessWithdrawal(record)) throw gaslessError('gasless_plan_mismatch', null, 'This withdrawal has no transit account to sweep.');
        // The journaled contracts, not the current profile's: a sweep keeps
        // working after the profile retires its gasless pins.
        const reader = this.gaslessReader();
        const transit = await this.journaledTransit(record, reader);
        const S = transit.account;
        onStatus('Connecting to MetaMask to sweep the transit account…');
        const from = await this.connectWallet();
        const balance = toBigInt(await reader({ method: 'eth_getBalance', params: [S, 'latest'] }), 'balance');
        if (balance === 0n) {
            await browserWalletRuntime.updateWithdrawal(recordId, { fundsWaitingInTransit: false, transitBalanceWei: '0' });
            await this.refresh({ quiet: true });
            return { status: 'empty', recordId, transitAccount: S };
        }
        const code = await reader({ method: 'eth_getCode', params: [S, 'latest'] });
        let createTransactionHash = record.transitCreateTransactionHash || null;
        if (!code || code === '0x') {
            onStatus('Confirm the transit account creation in MetaMask. Your account pays only gas.');
            const created = await this.sendContractTransaction(
                from,
                transit.factory,
                encodeCreateAccount(transit.owner, transit.payee),
                async hash => {
                    createTransactionHash = hash;
                    await browserWalletRuntime.updateWithdrawal(recordId, { transitCreateTransactionHash: hash });
                    onStatus(`Transit account creation submitted ${this.compact(hash)} · waiting for confirmation…`);
                },
                null,
                null,
                { kind: 'transit-create', submission: { recordId, noteId: Number(record.noteId), destination: S } }
            );
            createTransactionHash = created?.transactionHash || createTransactionHash;
        }
        onStatus('Confirm the sweep in MetaMask. Your account pays only gas; the paymaster pays the payout address.');
        let sweepTransactionHash = null;
        const receipt = await this.sendContractTransaction(
            from,
            S,
            encodeSweep(),
            async hash => {
                sweepTransactionHash = hash;
                const current = await browserWalletRuntime.currentWithdrawal(recordId);
                await browserWalletRuntime.updateWithdrawal(recordId, {
                    sweepTransactionHash: hash,
                    sweepTransactionHashes: [...new Set([...(current?.sweepTransactionHashes || []), hash])]
                });
                onStatus(`Sweep submitted ${this.compact(hash)} · waiting for confirmation…`);
            },
            null,
            null,
            { kind: 'transit-sweep', submission: { recordId, noteId: Number(record.noteId), destination: S } }
        );
        const collected = parseCollected(receipt, transit.paymaster, S);
        if (!collected) throw new Error('The sweep transaction succeeded, but the paymaster recorded no collection for this transit account.');
        const credited = parsePayoutCredited(receipt, transit.paymaster, transit.payee);
        const amounts = {
            receivedWei: collected.received, chargedWei: 0n, owedPaidWei: collected.owedPaid, paidOutWei: collected.paidOut,
            paymasterCredited: Boolean(credited), paymasterCreditedWei: credited?.amount ?? null
        };
        await browserWalletRuntime.updateWithdrawal(recordId, {
            ...journalValue(amounts),
            payoutVerified: !credited && collected.paidOut > 0n,
            sweepTransactionHash: sweepTransactionHash || receipt?.transactionHash || null,
            transitCreateTransactionHash: createTransactionHash,
            fundsWaitingInTransit: false,
            transitBalanceWei: '0',
            error: null
        });
        await this.refresh();
        onStatus(credited ? GASLESS_MESSAGES.payout_credited
            : `Transit account swept: ${formatUnits(collected.paidOut / NATIVE_WEI_PER_UNIT, 9)} ETH paid out${collected.owedPaid ? `, ${formatUnits(collected.owedPaid / NATIVE_WEI_PER_UNIT, 9)} ETH of debt paid` : ''}.`,
            { amounts: journalValue(amounts) });
        return { status: 'swept', recordId, transitAccount: S, transactionHash: sweepTransactionHash || receipt?.transactionHash || null,
            createTransactionHash, amounts: journalValue(amounts), ...(credited ? { paymasterCredited: true } : {}) };
    }

    /**
     * `claimGaslessCredit(payee, onStatus)`: the wallet-paid
     * `P.claimCredit(payee)` for a payout the paymaster credited because its
     * push to the payee failed. Anyone may call it; only the payee is paid.
     * P is the paymaster journaled with this browser's sponsored records of
     * that payee (so a claim keeps working after the profile retires its
     * gasless pins or names another paymaster), else the pinned one; the
     * first of them that holds a credit for the payee is claimed.
     */
    async claimGaslessCredit(payee, onStatus = () => {}) {
        const destination = normalizeWithdrawalDestination(payee, this.config?.funding);
        if (!destination) throw new TypeError('Choose the payout address whose credit to claim.');
        let pins = null;
        try {
            pins = this.requireGaslessPins();
        } catch (error) {
            if (error?.data?.reason !== 'not_pinned') throw error;
        }
        const records = (await browserWalletRuntime.currentWithdrawals()).filter(record => isGaslessWithdrawal(record)
            && String(record.payout || '').toLowerCase() === destination
            && /^0x[0-9a-fA-F]{40}$/.test(String(record.transit?.paymaster || '')));
        // Credited records first, then any other record of the payee, then the pins.
        const journaled = [...records.filter(record => record.paymasterCredited === true), ...records]
            .map(record => record.transit.paymaster.toLowerCase());
        const paymasters = [...new Set([...journaled, ...(pins ? [pins.paymaster.toLowerCase()] : [])])];
        if (!paymasters.length) throw gaslessError('gasless_unavailable', { reason: 'not_pinned' });
        const reader = this.gaslessReader();
        if (pins && paymasters.includes(pins.paymaster.toLowerCase())) await this.assertGaslessDeployment(pins, reader);
        onStatus('Checking the payout the paymaster holds for this address…');
        let paymaster = null;
        let credit = 0n;
        for (const candidate of paymasters) {
            const held = decodeWord(await this.gaslessCall(reader, candidate, encodeCredits(destination)), 'credits');
            if (held > 0n) {
                paymaster = candidate;
                credit = held;
                break;
            }
        }
        if (credit === 0n) {
            for (const candidate of paymasters) await this.markGaslessCreditsDelivered(destination, null, candidate);
            return { status: 'nothing_to_claim', payee: destination, amount: '0' };
        }
        onStatus('Connecting to MetaMask to deliver the credited payout…');
        const from = await this.connectWallet();
        onStatus('Confirm the credit claim in MetaMask. Your account pays only gas; the paymaster pays the payout address.');
        let transactionHash = null;
        const receipt = await this.sendContractTransaction(
            from,
            paymaster,
            encodeClaimCredit(destination),
            async hash => {
                transactionHash = hash;
                onStatus(`Credit claim submitted ${this.compact(hash)} · waiting for confirmation…`);
            },
            null,
            null,
            { kind: 'gasless-credit-claim', submission: { destination } }
        );
        const claimed = parseCreditClaimed(receipt, paymaster, destination);
        if (!claimed) throw new Error('The claim transaction succeeded, but it did not pay this address.');
        await this.markGaslessCreditsDelivered(destination, transactionHash || receipt?.transactionHash || null, paymaster);
        await this.refresh();
        onStatus(`Credited payout delivered: ${formatUnits(claimed.amount / NATIVE_WEI_PER_UNIT, 9)} ETH.`);
        return { status: 'claimed', payee: destination, amount: claimed.amount.toString(), transactionHash: transactionHash || receipt?.transactionHash || null,
            paymaster };
    }

    /** Mark the credited records of `payee` under `paymaster` (any paymaster when null) delivered. */
    async markGaslessCreditsDelivered(payee, transactionHash, paymaster = null) {
        for (const record of await browserWalletRuntime.currentWithdrawals()) {
            if (record.paymasterCredited === true && String(record.payout || '').toLowerCase() === payee
                && (!paymaster || !record.transit?.paymaster || sameAddress(record.transit.paymaster, paymaster))) {
                await browserWalletRuntime.updateWithdrawal(record.recordId, {
                    paymasterCredited: false, payoutVerified: true, creditClaimTransactionHash: transactionHash
                }).catch(() => null);
            }
        }
    }

    /** The closed sponsored records whose payout the paymaster still holds as a credit. */
    get paymasterCreditedPayouts() {
        return this.withdrawals.filter(record => record.paymasterCredited === true).map(record => ({
            recordId: record.recordId, noteId: record.noteId, payout: record.payout, creditedWei: record.paymasterCreditedWei ?? null
        }));
    }

    /**
     * `gaslessAvailability({ mode, destination, owner })`: the pre-flight of
     * §3.1 without any proof: { available, reason, message, bundlerUrl,
     * paymasterDepositWei, policy, attemptsLeft, transitAccount }.
     */
    async gaslessAvailability({ mode = 'mutual', destination = null, owner = null, bundlerUrl = null } = {}) {
        const kind = mode === 'escape' ? KIND.escape : mode === 'finalize' ? KIND.finalize : mode === 'forward' ? KIND.forward : KIND.close;
        const account = owner || this.walletAddress || null;
        const unavailable = (reason, message, extra = {}) => ({ available: false, reason, message: message || GASLESS_MESSAGES[reason] || reason,
            bundlerUrl: browserWalletRuntime.effectiveBundlerUrl?.() ?? null, paymasterDepositWei: null, policy: null, attemptsLeft: null,
            transitAccount: null, ...extra });
        let context;
        try {
            if (!account) {
                const pins = this.requireGaslessPins();
                const reader = this.gaslessReader();
                await this.assertGaslessDeployment(pins, reader);
                const payoutAddress = destination ? normalizeWithdrawalDestination(destination, this.config?.funding) : null;
                context = { pins, reader, transit: { account: null }, payout: payoutAddress, bundler: browserWalletRuntime.bundlerRpc(bundlerUrl || undefined), bundlerUrl: bundlerUrl || browserWalletRuntime.effectiveBundlerUrl(), kind };
            } else {
                const payout = (destination ? normalizeWithdrawalDestination(destination, this.config?.funding) : null) || account.toLowerCase();
                context = await this.gaslessContext({ from: account, payout, owner: account, bundlerUrl, kind });
            }
        } catch (error) {
            return unavailable(error?.code || 'gasless_unavailable', error?.shortMessage || error?.message, { data: error?.data || null });
        }
        let key = null;
        if (context.transit.account && this.note) {
            const noteId = Number(this.note.note_id);
            if (kind === KIND.close) {
                const nullifier = await browserWalletRuntime.currentWithdrawalNullifier().catch(() => null);
                key = nullifier ? attemptsKey(KIND.close, { nullifier }) : null;
            } else if (kind === KIND.forward) key = attemptsKey(KIND.forward, { sender: context.transit.account });
            else key = attemptsKey(kind, { noteId });
        }
        const preflight = await this.gaslessPreflight(context, { kind, key });
        return {
            available: preflight.verdict.available,
            reason: preflight.verdict.reason,
            message: preflight.verdict.message,
            data: preflight.verdict.data,
            bundlerUrl: context.bundlerUrl,
            paymasterDepositWei: preflight.status.paymaster_deposit_wei,
            policy: preflight.status.policy,
            attemptsLeft: preflight.status.attempts_left,
            owedWei: preflight.state.owed.toString(),
            transitAccount: context.transit.account,
            privacy: GASLESS_PRIVACY_NOTE
        };
    }

    /**
     * `gaslessWithdrawalQuote(mode, { destination, owner, feeCapWei,
     * allowExpensiveGas })`: the amounts of a sponsored withdrawal of the
     * selected balance before anything binds: never proves, never prompts.
     */
    async gaslessWithdrawalQuote(mode = 'mutual', { destination = null, owner = null, feeCapWei = null, allowExpensiveGas = false, bundlerUrl = null } = {}) {
        const note = this.note;
        if (!note) throw new Error('There is no active private note to withdraw.');
        if (!['mutual', 'escape'].includes(mode)) throw new Error('Choose a valid withdrawal mode.');
        const kind = mode === 'mutual' ? KIND.close : KIND.escape;
        let account = owner || this.walletAddress || null;
        if (!account && this.ethereum) {
            try {
                account = (await this.ethereum.request({ method: 'eth_accounts' }))?.[0] || null;
            } catch {
                account = null;
            }
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(account || '')) throw new Error('Connect a wallet, or pass the owner account, to quote a sponsored withdrawal.');
        const payout = (destination ? normalizeWithdrawalDestination(destination, this.config?.funding) : null) || account.toLowerCase();
        const noteId = Number(note.note_id);
        const payoutWei = BigInt(note.current_balance) * NATIVE_WEI_PER_UNIT;
        const refusal = (reason, message, extra = {}) => ({ available: false, reason, message: message || GASLESS_MESSAGES[reason] || reason, mode, kind,
            owner: account.toLowerCase(), payout, payoutWei: payoutWei.toString(), concededUnknown: mode === 'escape', privacy: GASLESS_PRIVACY_NOTE, ...extra });
        let context;
        try {
            context = await this.gaslessContext({ from: account, payout, owner: account, bundlerUrl, kind });
        } catch (error) {
            return refusal(error?.code || 'gasless_unavailable', error?.shortMessage || error?.message, { data: error?.data || null });
        }
        const nullifier = await browserWalletRuntime.currentWithdrawalNullifier().catch(() => null);
        const key = kind === KIND.close ? (nullifier ? attemptsKey(KIND.close, { nullifier }) : null) : attemptsKey(KIND.escape, { noteId });
        const preflight = await this.gaslessPreflight(context, { kind, key });
        const base = {
            mode, kind, owner: account.toLowerCase(), payout, transitAccount: context.transit.account, payoutWei: payoutWei.toString(),
            bundlerUrl: context.bundlerUrl, paymasterDepositWei: preflight.status.paymaster_deposit_wei, policy: preflight.status.policy,
            attemptsLeft: preflight.status.attempts_left, concededUnknown: mode === 'escape', privacy: GASLESS_PRIVACY_NOTE
        };
        if (!preflight.verdict.available) return { ...base, available: false, reason: preflight.verdict.reason, message: preflight.verdict.message, data: preflight.verdict.data };
        try {
            const built = await this.buildGaslessOperation(context, {
                kind, vaultCall: WORST_CASE_EXIT_CALL, nullifier: nullifier ?? 0n, noteId, payoutWei, feeCapWei, allowExpensiveGas, state: preflight.state
            });
            const code = await context.reader({ method: 'eth_getCode', params: [payout, 'latest'] }).catch(() => '0x');
            return {
                ...base, available: true, reason: null, message: null, transitExists: !built.withInitCode,
                amounts: journalValue(built.amounts), fees: journalValue(built.fees), gas: journalValue(built.gas), maxCost: built.maxCost.toString(),
                flatFeeWei: built.amounts.flatFee.toString(), owedWei: built.amounts.owed.toString(), minimumReceivedWei: weiString(built.amounts.minimumReceived),
                estimatedReceivedWei: weiString(built.amounts.estimatedReceived),
                uneconomic: built.amounts.uneconomic, payoutHasCode: Boolean(code && code !== '0x'),
                ...(code && code !== '0x' ? { payoutWarning: GASLESS_PAYOUT_CONTRACT_WARNING } : {})
            };
        } catch (error) {
            return { ...base, available: false, reason: error?.code || 'gasless_unavailable', message: error?.shortMessage || error?.message,
                data: journalValue(error?.data || null) };
        }
    }

    setBundlerUrl(url) {
        const saved = browserWalletRuntime.setBundlerUrl(url);
        this.emitChange('bundler');
        return saved;
    }

    getBundlerUrl() {
        return browserWalletRuntime.getBundlerUrl();
    }

    /**
     * Background recovery of a sponsored operation journaled before its bundle
     * transaction was known (§3.2): the chain's logs by every hash, then, when
     * the nonce has not moved, the identical bytes re-sent (no prompt), or,
     * when it has, the inclusion found by sender and nonce. Returns the bundle
     * transaction hash once known.
     */
    async recoverGaslessSubmission(prepared, onStatus = () => {}) {
        if (!isGaslessWithdrawal(prepared)) return null;
        // A plan whose operation was released (a re-proof, a rebuild) keeps
        // the hashes of what it sent in `staleUserOpHashes`: a late inclusion
        // of one of them still settles the record.
        const hashes = [...new Set([...(prepared.userOpHashes || []), ...(prepared.staleUserOpHashes || []), prepared.userOpHash]
            .filter(Boolean).map(hash => String(hash).toLowerCase()))];
        if (!prepared.userOp && !hashes.length) return null;
        if (this.withdrawPromise) return null;
        const timing = this.gaslessTiming;
        if (prepared.submissionId && browserWalletRuntime.gaslessClaimLive({
            submissionId: prepared.submissionId, owner: prepared.submissionOwner,
            lastActiveAt: Math.max(Number(prepared.submissionStartedAt || 0), Number(prepared.userOpSubmittedAt || 0),
                Number(prepared.userOpFollowedAt || 0))
        }, timing.resendAfterMs)) return null;
        const kind = prepared.mode === 'mutual' ? KIND.close : KIND.escape;
        let context;
        let unpinned = false;
        try {
            context = await this.gaslessContext({
                from: prepared.transit.owner, payout: prepared.payout, owner: prepared.transit.owner, expectedAccount: prepared.transit.account,
                bundlerUrl: prepared.bundlerUrl || null, kind, record: prepared
            });
        } catch (error) {
            // The current profile no longer sponsors this plan's paymaster:
            // its inclusion is still looked for through the journaled
            // EntryPoint (read-only, no bundler), but nothing is re-sent;
            // an operation not included is released below.
            if (error?.code !== 'gasless_record_not_pinned') throw error;
            context = this.recordReaderContext(prepared);
            if (!context) throw error;
            unpinned = true;
        }
        // From the earliest block any of the plan's operations was tracked from.
        const fromBlock = earliestBlock(prepared.submittedAtBlock, prepared.staleSubmittedAtBlock);
        let found = await this.findUserOperationInclusion(context, hashes, fromBlock);
        // Without an operation to re-send there is nothing to claim unless an inclusion was found.
        if (!found && !prepared.userOp) return null;
        const submission = prepared.submissionId ? {
            operationId: prepared.operationId, submissionId: prepared.submissionId, noteId: Number(prepared.noteId ?? prepared.public_inputs?.note_id),
            mode: prepared.mode, destination: prepared.destination, deploymentId: browserWalletRuntime.manifest.deployment_id,
            chainId: Number(this.config.funding.chain_id), contractAddress: this.config.funding.contract_address
        } : (await browserWalletRuntime.claimPreparedWithdrawalUserOp({ liveWindowMs: timing.resendAfterMs }));
        // The background pass follows the claim only for these few calls.
        if (!prepared.submissionId) browserWalletRuntime.endGaslessClaim(submission?.submissionId);
        if (!found && prepared.userOp) {
            const op = userOperationFromJson(prepared.userOp);
            const { key, sequence } = unpackNonce(op.nonce);
            const current = unpackNonce(decodeWord(await this.gaslessCall(context.reader, context.pins.entryPoint,
                encodeGetNonce(context.transit.account, key)), 'getNonce')).sequence;
            if (current > sequence) {
                found = await this.findUserOperationInclusion(context, null, fromBlock, { sender: context.transit.account, nonce: op.nonce });
            } else if (context.bundler && Number(prepared.public_inputs?.valid_until || 0) - timing.stopBeforeValidUntilSeconds > Date.now() / 1_000) {
                try {
                    const bundlerHash = await context.bundler.sendUserOperation(userOperationJson(op), context.pins.entryPoint);
                    await browserWalletRuntime.rememberPreparedWithdrawalUserOpSubmission(submission, { hash: bundlerHash, ambiguous: bundlerHash !== prepared.userOpHash });
                    onStatus(`The sponsored operation ${this.compact(prepared.userOpHash)} was sent to the bundler again.`);
                } catch (error) {
                    if (!this.gaslessAlreadyKnown(error)) onStatus(`The bundler did not take the sponsored operation again (${error?.shortMessage || error?.message}).`);
                }
            }
        }
        if (!found && unpinned) {
            // Not re-sent under a profile that no longer pins its paymaster:
            // once a bundler would have included it (the re-send window from
            // its last activity), or its proof is about to expire, it is
            // released with the plan's claim, so the wallet-paid close or
            // escape (fees: 'wallet') can proceed. Its hashes stay in
            // staleUserOpHashes: a late inclusion is still settled.
            const lastActiveAt = Math.max(Number(prepared.submissionStartedAt || 0), Number(prepared.userOpBuiltAt || 0),
                Number(prepared.userOpSubmittedAt || 0), Number(prepared.userOpFollowedAt || 0));
            const expiring = Number(prepared.public_inputs?.valid_until || 0) - timing.stopBeforeValidUntilSeconds <= Date.now() / 1_000;
            if (expiring || Date.now() - lastActiveAt >= timing.resendAfterMs) {
                await browserWalletRuntime.releasePreparedWithdrawalUserOp(submission);
                if (submission?.operationId && submission.submissionId) {
                    await browserWalletRuntime.markPreparedWithdrawalRetryable(null, submission);
                }
                onStatus('The sponsored operation sent earlier was not included and is no longer sponsored; it was released. Pay the fee from a wallet to finish this withdrawal.');
            }
            return null;
        }
        if (!found) return null;
        await browserWalletRuntime.rememberPreparedWithdrawalTransaction(found.transactionHash, submission, null);
        onStatus(`The sponsored operation was included in ${this.compact(found.transactionHash)}.`);
        return found.transactionHash;
    }

    /**
     * The inclusion of a record's own journaled operation under `prefix`
     * ('finalize' / 'forward'): the EntryPoint's logs by every hash it was
     * journaled under, then, when S's nonce at the op's key moved past it, by
     * (S, nonce); from the block it was built at. null when none is found.
     */
    async recordUserOpInclusion(context, record, prefix) {
        const hashes = this.recordUserOpHashes(record, prefix);
        if (!hashes.length) return null;
        const fromBlock = record[`${prefix}UserOpBlock`] ?? record.startBlockNumber ?? null;
        let found = await this.findUserOperationInclusion(context, hashes, fromBlock);
        if (!found && record[`${prefix}UserOp`]) {
            try {
                const op = userOperationFromJson(record[`${prefix}UserOp`]);
                const { key, sequence } = unpackNonce(op.nonce);
                const current = unpackNonce(decodeWord(await this.gaslessCall(context.reader, context.pins.entryPoint,
                    encodeGetNonce(context.transit.account, key)), 'getNonce')).sequence;
                if (current > sequence) {
                    found = await this.findUserOperationInclusion(context, null, fromBlock, { sender: context.transit.account, nonce: op.nonce });
                }
            } catch {
                found = null;
            }
        }
        return found;
    }

    /**
     * The hashes a record's journaled operation under `prefix` may have been
     * included under (the op body may be released already); those of an
     * operation whose inclusion already settled as reverted
     * (`${prefix}RevertedUserOpHashes`) are not looked for again.
     */
    recordUserOpHashes(record, prefix) {
        const reverted = new Set((record?.[`${prefix}RevertedUserOpHashes`] || []).map(hash => String(hash).toLowerCase()));
        return [...new Set([...(record?.[`${prefix}UserOpHashes`] || []), record?.[`${prefix}UserOpHash`]].filter(Boolean)
            .map(hash => String(hash).toLowerCase()))].filter(hash => !reverted.has(hash));
    }

    /**
     * The fields that set a record's operation under `prefix` aside as
     * reverted: every hash it was journaled under (one nonce: none of them
     * can land any more) and `extra`, so a retry builds a new operation.
     */
    revertedRecordUserOpFields(record, prefix, extra = []) {
        const hashes = [...this.recordUserOpHashes(record, prefix), ...extra.filter(Boolean).map(hash => String(hash).toLowerCase())];
        return {
            [`${prefix}RevertedUserOpHashes`]: [...new Set([...(record?.[`${prefix}RevertedUserOpHashes`] || []).map(hash => String(hash).toLowerCase()),
                ...hashes])]
        };
    }

    /** Whether a record's finalization or forward operation was journaled but its bundle transaction is not known yet. */
    recordUserOpUnresolved(record, prefix) {
        // 'reverted': its inclusion was found and released (nothing to record
        // again); 'settled': its settlement is recorded (finality later drops
        // the bundle transaction hash, not the outcome).
        return this.recordUserOpHashes(record, prefix).length > 0 && !['reverted', 'settled'].includes(record[`${prefix}UserOpPhase`])
            && !record[`${prefix}TransactionHash`]
            && !(record[`${prefix}TransactionHashes`] || []).length;
    }

    /**
     * The EntryPoint and paymaster a gasless record's operations ran under:
     * those journaled with its transit account, else (a record without them)
     * the current pins; null when neither names them.
     */
    recordGaslessContracts(record) {
        const transit = record?.transit || {};
        const valid = value => /^0x[0-9a-fA-F]{40}$/.test(String(value || ''));
        if (valid(transit.entryPoint) && valid(transit.paymaster)) {
            return { entryPoint: transit.entryPoint.toLowerCase(), paymaster: transit.paymaster.toLowerCase() };
        }
        const pins = browserWalletRuntime.gaslessPins();
        return pins ? { entryPoint: pins.entryPoint, paymaster: pins.paymaster } : null;
    }

    /**
     * The settlement fields of a record's sponsored finalization or forward
     * from its bundle receipt (the paymaster's Settled / PayoutCredited for
     * S and the payee, §3.2 amounts table), read through the gasless reader;
     * null when the receipt carries no operation of S.
     */
    async gaslessRecordSettlement(record, transactionHash, { reader = null, hash = null, receipt = null } = {}) {
        if (!isGaslessWithdrawal(record)) return null;
        const contracts = this.recordGaslessContracts(record);
        if (!contracts) return null;
        let bundle = receipt;
        if (!bundle) {
            try {
                bundle = await (reader || this.gaslessReader())({ method: 'eth_getTransactionReceipt', params: [transactionHash] });
            } catch {
                return null;
            }
        }
        if (!bundle || BigInt(bundle.status || '0x0') !== 1n) return null;
        const settlement = settlementOf(bundle, {
            entryPoint: contracts.entryPoint, paymaster: contracts.paymaster, hash, sender: record.transit.account, payee: record.payout
        });
        if (!settlement) return null;
        const settled = settlement.settled;
        const credited = settlement.credited;
        return {
            settlement,
            userOpHash: settlement.event.userOpHash,
            success: settlement.success,
            payoutVerified: settlement.success && !credited && (settled?.paidOut ?? 0n) > 0n,
            amounts: {
                receivedWei: settled?.received ?? 0n, chargedWei: settled?.charged ?? 0n, owedPaidWei: settled?.owedPaid ?? 0n,
                paidOutWei: settled?.paidOut ?? 0n, paymasterCredited: Boolean(credited), paymasterCreditedWei: credited?.amount ?? null
            }
        };
    }

    /**
     * The read-only context of a gasless record's own operations: its
     * journaled EntryPoint and paymaster (recordGaslessContracts), its
     * transit account, and the gasless reader; no pins are required and no
     * bundler is resolved. null when the record names no contracts.
     */
    recordReaderContext(record, reader = this.gaslessReader()) {
        const contracts = this.recordGaslessContracts(record);
        const account = String(record?.transit?.account || '');
        if (!contracts || !/^0x[0-9a-fA-F]{40}$/.test(account)) return null;
        return { pins: contracts, reader, transit: { account: account.toLowerCase() }, bundler: null };
    }

    /**
     * Record the inclusion `found` of a record's own finalization or forward
     * operation (prefix 'finalize' / 'forward'): its bundle transaction under
     * the record's finalization claim (or the forward's hashes) and, when the
     * bundle carries it, the paymaster's settlement.
     */
    async rememberRecordUserOpInclusion(record, prefix, found, reader) {
        const settlement = await this.gaslessRecordSettlement(record, found.transactionHash, { reader, hash: found.userOpHash });
        const settled = settlement ? {
            ...journalValue(settlement.amounts),
            [`${prefix}UserOpHash`]: settlement.userOpHash,
            [`${prefix}UserOpPhase`]: settlement.success ? 'settled' : 'reverted',
            ...(settlement.success ? { payoutVerified: settlement.payoutVerified } : {})
        } : {};
        if (prefix === 'finalize' && !record.finalizeSubmissionId && !FINALIZATION_CLAIMABLE_PHASES.has(record.phase)) {
            // Past finality there is no finalization left to claim: only the
            // outcome is recorded, so the record is not looked at again.
            await browserWalletRuntime.updateWithdrawal(record.recordId, {
                [`${prefix}UserOpPhase`]: found.success === false ? 'reverted' : 'settled', ...settled
            });
        } else if (prefix === 'finalize') {
            const claim = record.finalizeSubmissionId ? {
                recordId: record.recordId, submissionId: record.finalizeSubmissionId, operationId: record.finalizeOperationId,
                generation: record.finalizeGeneration, deploymentId: record.deploymentId, chainId: record.chainId,
                contractAddress: record.contractAddress, noteId: record.noteId, destination: record.destination
            } : await browserWalletRuntime.claimWithdrawalFinalization(record.recordId);
            await browserWalletRuntime.rememberWithdrawalFinalization(record.recordId, found.transactionHash, claim, null);
            if (Object.keys(settled).length) await browserWalletRuntime.updateWithdrawal(record.recordId, settled);
        } else {
            await browserWalletRuntime.updateWithdrawal(record.recordId, {
                forwardTransactionHash: found.transactionHash,
                forwardTransactionHashes: [...new Set([...(record.forwardTransactionHashes || []), found.transactionHash])],
                ...settled,
                ...(settlement?.success ? { fundsWaitingInTransit: false, transitBalanceWei: '0' } : {})
            });
        }
    }

    /**
     * Background pass: the bundle transactions of journaled finalization and
     * forward operations, from the EntryPoint's logs (by every hash the
     * record names, whether or not the op body is still journaled), then the
     * settlement amounts of that bundle (§3.2), all through the gasless reader.
     */
    async recoverGaslessRecordOperations() {
        const records = (await browserWalletRuntime.currentWithdrawals()).filter(record => isGaslessWithdrawal(record)
            && (this.recordUserOpUnresolved(record, 'finalize') || this.recordUserOpUnresolved(record, 'forward')));
        if (!records.length || this.finalizePromise) return;
        // A look on chain only: the record's journaled EntryPoint and
        // paymaster through the read RPC, never the current pins nor a
        // bundler, so a late inclusion is still recorded after the profile
        // retires its gasless pins or names another paymaster (as clientd's
        // lateUserOperation does).
        const reader = this.gaslessReader();
        for (const record of records) {
            const context = this.recordReaderContext(record, reader);
            if (!context) continue;
            // Each operation on its own: a finalization that cannot be
            // recorded never keeps the forward from being looked for.
            for (const prefix of ['finalize', 'forward']) {
                if (!this.recordUserOpUnresolved(record, prefix)) continue;
                try {
                    const fromBlock = record[`${prefix}UserOpBlock`] ?? record.startBlockNumber ?? null;
                    const found = await this.findUserOperationInclusion(context, this.recordUserOpHashes(record, prefix), fromBlock);
                    if (!found) continue;
                    await this.rememberRecordUserOpInclusion(record, prefix, found, reader);
                } catch (error) {
                    console.warn(`Unable to recover the sponsored ${prefix} operation of ${record.recordId}.`, error);
                }
            }
        }
    }

    async recoverUnknownWithdrawal(onStatus = () => {}) {

        await browserWalletRuntime.markPreparedWithdrawalUnknown();
        await this.refresh();
        onStatus('The old wallet prompt was marked unresolved. Check the vault before retrying.');
        return this.withdrawal;
    }

    async retryUnknownWithdrawal(onStatus = () => {}) {

        const prepared = this.config?.prepared_withdrawal;
        if (prepared?.phase !== 'ambiguous') {
            throw new Error('There is no unresolved withdrawal request to retry.');
        }
        await browserWalletRuntime.authorizePreparedWithdrawalRetry();
        await this.refresh({ quiet: true });
        onStatus('Retry authorized. Opening a new MetaMask request…');
        return this.withdraw(prepared.mode, onStatus);
    }

    async retryDroppedWithdrawal(onStatus = () => {}) {

        const current = await browserWalletRuntime.currentPreparedWithdrawal();
        if (!current || current.phase !== 'dropped_or_pending') {
            throw new Error('Check the withdrawal before replacing it.');
        }
        await this.assertBalanceNotClaimed(current.noteId ?? current.public_inputs?.note_id ?? this.note?.note_id);
        onStatus('Connecting to the MetaMask account that submitted this withdrawal…');
        const from = await this.connectWallet();
        const submission = await browserWalletRuntime.claimPreparedWithdrawalReplacement(from);
        const plan = submission.plan;
        const mode = plan.mode === 'mutual' ? 'mutual' : 'escape';
        let submittedHash = null;
        let submissionMetadata = {
            from: submission.replacementFrom,
            nonce: Number(submission.replacementNonce)
        };
        try {
            onStatus('Confirm the exact same withdrawal in MetaMask. It reuses the original nonce, so only one version can execute.');
            await this.sendContractTransaction(
                from,
                this.config.funding.contract_address,
                encodeWithdrawal(
                    plan,
                    mode,
                    plan.destination,
                    this.config.funding.contract_address
                ),
                async hash => {
                    submittedHash = hash;
                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                        hash,
                        submission,
                        submissionMetadata
                    );
                    onStatus(`Replacement submitted ${this.compact(hash)} · checking confirmation…`);
                },
                async metadata => {
                    submissionMetadata = metadata;
                    await browserWalletRuntime.rememberPreparedWithdrawalSubmissionMetadata(
                        submission,
                        metadata
                    );
                },
                submission.replacementNonce,
                { kind: 'withdrawal', submission }
            );
        } catch (error) {
            await this.recoverFailedWithdrawalSubmission({
                mode,
                error,
                submittedHash,
                submission,
                submissionMetadata,
                from
            });
            throw error;
        }
        await this.refresh({ quiet: true });
        return this.syncWithdrawal(onStatus);
    }

    async withdrawBackground(recordId, onStatus = () => {}) {

        this.backgroundWithdrawalPromises ||= new Map();
        if (this.backgroundWithdrawalPromises.has(recordId)) {
            return this.backgroundWithdrawalPromises.get(recordId);
        }
        const operation = this.performBackgroundWithdrawal(recordId, onStatus);
        this.backgroundWithdrawalPromises.set(recordId, operation);
        try {
            return await operation;
        } finally {
            if (this.backgroundWithdrawalPromises.get(recordId) === operation) {
                this.backgroundWithdrawalPromises.delete(recordId);
            }
        }
    }

    async cancelBackgroundWithdrawalPreparation(recordId, onStatus = () => {}) {

        await browserWalletRuntime.cancelBackgroundWithdrawalPreparation(recordId);
        await this.refresh({ quiet: true });
        onStatus('Preparation canceled. The set-aside balance is ready to withdraw again.');
    }

    async performBackgroundWithdrawal(recordId, onStatus) {
        onStatus('Checking the set-aside balance…', 'preparing');
        await this.syncEscapeWithdrawals(() => {}, recordId);
        const record = await browserWalletRuntime.currentWithdrawal(recordId);
        if (!record || record.mode !== 'mutual'
            || !['parked', 'restored'].includes(record.phase)) {
            throw new Error('Check this withdrawal’s status before trying to finish it.');
        }
        // This path deliberately never selects the old note or settles the
        // current chat. The retained destination receives the old balance;
        // the connected account only authorizes and pays for this transaction.
        const noteId = Number(record.noteId);
        const destination = record.destination;
        await this.assertBalanceNotClaimed(noteId);
        onStatus('Connecting to MetaMask for the set-aside balance…');
        const from = await this.connectWallet();
        let receipt;
        let plan;
        let submittedHash = null;
        // After UnknownRoot the next close proof takes a path at another root
        // (E4.1); a path failure then falls back to the saved one, whose
        // simulation refusal only warns on the last attempt (E4.5).
        let refusedRoot = null;
        const walletRequest = request => this.ethereum.request(request);
        for (let attempt = 0; attempt < 3; attempt += 1) {
            let submission = null;
            let metadata = null;
            try {
                const canonical = await this.readBrowserWithdrawalStatus(noteId);
                if (canonical.status !== 'active' || Number(canonical.observed_block || 0)
                    < Math.max(Number(record.startBlockNumber || 0), Number(record.lastObservedBlock || 0))) {
                    await this.syncEscapeWithdrawals(() => {}, recordId);
                    throw new Error('The vault state changed. Check this withdrawal’s status before retrying.');
                }
                onStatus(attempt === 0
                    ? 'Preparing the old balance’s withdrawal proof…'
                    : 'The vault changed. Updating the old balance’s proof…', 'preparing');
                const expectedActiveRoot = await this.readContractUint(
                    this.config.funding.contract_address, `0x${ABI.currentRoot}`
                );
                try {
                    plan = await browserWalletRuntime.prepareBackgroundWithdrawal(recordId, { expectedActiveRoot,
                        walletRequest, ...(refusedRoot != null ? { refusedRoot } : {}) });
                } catch (error) {
                    if (refusedRoot == null || error?.data?.exit_path_unavailable !== true) throw error;
                    onStatus(`No Merkle path at another root was found (${error.message}). The saved path is used again.`, 'preparing');
                    refusedRoot = null;
                    plan = await browserWalletRuntime.prepareBackgroundWithdrawal(recordId, { expectedActiveRoot, walletRequest });
                }
                if (plan.mode !== 'mutual' || Number(plan.public_inputs?.note_id) !== noteId
                    || plan.destination?.toLowerCase() !== destination?.toLowerCase()
                    || Number(plan.public_inputs?.final_balance) !== Number(record.finalBalance)) {
                    throw new Error('The withdrawal proof does not match this set-aside balance.');
                }
                const calldata = encodeWithdrawal(plan, 'mutual', destination, this.config.funding.contract_address);
                submission = await browserWalletRuntime.claimBackgroundWithdrawalSubmission(recordId, plan.operationId);
                onStatus('Confirm the set-aside withdrawal in MetaMask. Your current balance is unchanged.', 'wallet');
                receipt = await this.sendContractTransaction(
                    from, this.config.funding.contract_address, calldata,
                    async hash => {
                        submittedHash = hash;
                        await browserWalletRuntime.rememberBackgroundWithdrawalTransaction(hash, submission, metadata);
                        onStatus('Withdrawal submitted. Checking confirmation…', 'confirming');
                    },
                    async value => {
                        metadata = value;
                        await browserWalletRuntime.rememberBackgroundWithdrawalSubmissionMetadata(submission, value);
                    },
                    null,
                    { kind: 'background-withdrawal', submission },
                    0n,
                    {
                        // A root refusal re-proves while attempts remain;
                        // otherwise the simulation only warns (E4.5).
                        exitEstimate: {
                            blocking: error => ['stale_root', 'unknown_root'].includes(error?.code) && attempt < 2,
                            alternative: transaction => browserWalletRuntime.exitRpcEstimateGas(transaction),
                            onAdvisory: error => onStatus(`Your wallet’s simulation refused this withdrawal (${error.message}). It can still be submitted, with a fixed gas limit.`, 'wallet')
                        }
                    }
                );
                break;
            } catch (failure) {
                const error = normalizeWalletError(failure);
                submittedHash = submittedHash || error.transactionHash || null;
                if (submission && submittedHash) {
                    // A returned hash owns recovery even if its first journal
                    // write or the receipt poll failed. Never prepare a new
                    // proof/nonce after this boundary.
                    try {
                        await browserWalletRuntime.rememberBackgroundWithdrawalTransaction(submittedHash, submission, metadata);
                    } catch (journalError) {
                        error.journalRecoveryError = journalError;
                    }
                    error.shortMessage = 'The submitted withdrawal is saved for recovery. Check its status; your current balance is unchanged.';
                } else if (submission && (error.broadcastPossible === false || isWalletRejection(error))) {
                    await browserWalletRuntime.releaseBackgroundWithdrawalSubmission(submission);
                    // The background flow always re-proves (reusing its
                    // persisted clearance), so either root rejection retries,
                    // and an UnknownRoot one at another root.
                    if (['stale_root', 'unknown_root'].includes(error.code) && attempt < 2) {
                        if (error.code === 'unknown_root') refusedRoot = plan?.public_inputs?.active_root ?? null;
                        continue;
                    }
                    if (isWalletRejection(error)) {
                        error.shortMessage = 'Canceled. The old balance is still set aside and can be withdrawn later.';
                    }
                } else if (submission) {
                    await browserWalletRuntime.markBackgroundWithdrawalAmbiguous(submission, error.message);
                    error.shortMessage = 'MetaMask did not return a transaction ID. Check this withdrawal’s status before retrying; your current balance is unchanged.';
                }
                await this.refresh({ quiet: true });
                throw error;
            }
        }
        const event = parseWithdrawalReceipt(receipt, this.config.funding.contract_address, 'mutual');
        if (!event || event.noteId !== BigInt(noteId)
            || event.destination.toLowerCase() !== destination.toLowerCase()
            || event.finalBalance !== BigInt(plan.public_inputs.final_balance)) {
            throw new Error('The transaction receipt did not match the set-aside withdrawal. Its transaction remains saved for checking.');
        }
        const confirmed = await this.confirmMinedWithdrawalStatus(noteId, receipt);
        if (confirmed.status !== 'closed'
            || Number(confirmed.observed_block || 0) < Number(BigInt(receipt.blockNumber || '0x0'))) {
            const error = new Error('The withdrawal transaction was mined. Its current vault status is still being checked.');
            error.withdrawalConfirmationPending = true;
            throw error;
        }
        // Reconciliation validates the same receipt and updates only the
        // background record. Recovery material is retained until finality.
        await this.syncEscapeWithdrawals(() => {}, recordId);
        await this.refresh({ quiet: true });
        onStatus(`${this.formatMoney(event.finalBalance)} returned. Your current balance is unchanged.`);
        return { status: 'closed', event, receipt, recordId };
    }

    async retryDroppedBackgroundWithdrawal(recordId, onStatus = () => {}) {

        const current = await browserWalletRuntime.currentWithdrawal(recordId);
        const hasReplaceableLiveClaim = Boolean(current?.startSubmissionId
            && /^0x[0-9a-fA-F]{40}$/.test(current.startSubmissionFrom || '')
            && Number.isSafeInteger(Number(current.startSubmissionNonce))
            && Number(current.startSubmissionNonce) >= 0);
        const hasSavedRetryIdentity = Boolean(!current?.startSubmissionId
            && /^0x[0-9a-fA-F]{40}$/.test(current?.startRetryFrom || '')
            && Number.isSafeInteger(Number(current?.startRetryNonce))
            && Number(current.startRetryNonce) >= 0);
        if (!current || current.phase !== 'submitted_unconfirmed'
            || current.chainStatus !== 'active'
            || (!hasReplaceableLiveClaim && !hasSavedRetryIdentity
                && !['receipt_missing', 'replacement_result_unknown']
                    .includes(current.startSubmissionOutcome))) {
            throw new Error('Check the background withdrawal before replacing it.');
        }
        await this.assertBalanceNotClaimed(current.noteId);
        onStatus('Connecting to the MetaMask account that submitted this withdrawal…');
        const from = await this.connectWallet();
        const submission = await browserWalletRuntime
            .claimBackgroundWithdrawalStartReplacement(recordId, from);
        const plan = submission.plan;
        const mode = plan.mode === 'mutual' ? 'mutual' : 'escape';
        let submittedHash = null;
        const submissionMetadata = {
            from: submission.replacementFrom,
            nonce: Number(submission.replacementNonce)
        };
        try {
            onStatus('Confirm the same background withdrawal in MetaMask. It reuses the original nonce, so only one version can execute.');
            await this.sendContractTransaction(
                from,
                this.config.funding.contract_address,
                encodeWithdrawal(
                    plan,
                    mode,
                    plan.destination,
                    this.config.funding.contract_address
                ),
                async hash => {
                    submittedHash = hash;
                    // The selected slot may contain a fresh note. Journal this
                    // returned hash as a late attempt; the background reconciler
                    // atomically joins it to the retained old-note record.
                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                        hash,
                        submission,
                        submissionMetadata
                    );
                    onStatus(`Background replacement submitted ${this.compact(hash)} · checking confirmation…`);
                },
                null,
                submission.replacementNonce,
                { kind: 'background-replacement', submission }
            );
        } catch (error) {
            if (error?.transactionHash) {
                submittedHash = error.transactionHash;
                try {
                    await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                        submittedHash,
                        submission,
                        submissionMetadata
                    );
                } catch (journalError) {
                    error.journalRecoveryError = journalError;
                }
                error.shortMessage = 'The replacement transaction remains saved in the background and will keep being checked.';
            } else {
                const replacementUnknown = error?.broadcastPossible !== false
                    && !isWalletRejection(error);
                await browserWalletRuntime.releaseBackgroundWithdrawalStartSubmission(
                    submission,
                    {
                        replacementUnknown,
                        message: error?.message
                            || 'MetaMask did not return a background replacement transaction ID.'
                    }
                );
                error.shortMessage = error?.broadcastPossible === false || isWalletRejection(error)
                    ? 'The background replacement was canceled before broadcast. Its original transaction remains saved and can be replaced again.'
                    : 'MetaMask did not return a replacement transaction ID. The original background transaction remains saved, and the same nonce can be retried.';
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        await this.refresh({ quiet: true });
        const lateResults = await this.syncLateWithdrawalAttempts(onStatus);
        const backgroundResults = await this.syncEscapeWithdrawals(onStatus, recordId);
        return backgroundResults[0]
            || lateResults.find(result => result?.attempt?.operationId === submission.operationId)
            || { status: 'submitted', transaction_hash: submittedHash };
    }

    async settleActiveLease(onStatus = () => {}, { sessionId = null } = {}) {
        const hasPendingRequest = Boolean(this.activeLease || this.wallet?.pending_request);
        const activityId = hasPendingRequest ? this.beginActivity('settlement', {
            phase: 'settling',
            title: 'Finishing previous chat',
            message: 'Closing its temporary key…',
            sessionId: this.activeLease?.session_id || null,
            blocksSend: true
        }) : null;
        const report = (phase, message) => {
            if (activityId) this.updateActivity(activityId, { phase, message });
            onStatus(message);
        };
        if (hasPendingRequest) {
            report('settling', 'Finishing the active chat and confirming its usage…');
        }
        try {
            const settled = sessionId
                ? await browserWalletRuntime.settleSessionLease(sessionId, report)
                : await browserWalletRuntime.settleActiveLease(report);
            await this.refresh({ quiet: true });
            if (sessionId ? await this.getPendingLeaseOwner() === sessionId
                : this.activeLease || this.wallet?.pending_request) {
                throw new Error('The private key usage is still settling. Try again shortly.');
            }
            if (hasPendingRequest) {
                report('complete', 'Previous chat finished. Balance updated.');
                this.completeActivity(activityId, { message: 'Previous chat finished. Balance updated.' });
            }
            return settled;
        } catch (error) {
            if (activityId) this.failActivity(activityId, error, { blocksSend: true });
            throw error;
        }
    }

    async hasPendingLease() {
        if (!this.initialized) await this.init();
        return browserWalletRuntime.hasPendingLease();
    }

    async getPendingLeaseOwner() {
        await this.init();
        return browserWalletRuntime.getPendingLeaseOwner();
    }

    async syncLateWithdrawalAttempts(onStatus = () => {}) {
        const terminal = new Set([
            'closed',
            'detached',
            'reverted',
            'challenged',
            'superseded',
            'quarantined'
        ]);
        const attempts = (await browserWalletRuntime.currentLateWithdrawalAttempts())
            .filter(attempt => !terminal.has(attempt.status));
        const results = [];
        let changed = false;
        const transferCanonicalAttempt = async (attempt, canonical, metadata = {}) => {
            const mode = attempt.mode === 'mutual' ? 'mutual' : 'escape';
            const recordId = browserWalletRuntime.withdrawalRecordId(attempt.noteId);
            const background = await browserWalletRuntime.currentWithdrawal(recordId);
            const selectedState = browserWalletRuntime.snapshot().runtime?.state;
            const selectedOwns = Number(selectedState?.note_id) === Number(attempt.noteId);
            const destination = canonical.destination
                || background?.destination
                || attempt.destination
                || null;
            const finalBalance = Number(canonical.final_balance
                ?? background?.finalBalance
                ?? attempt.finalBalance
                ?? (selectedOwns ? selectedState?.current_balance : NaN));
            if (!/^0x[0-9a-fA-F]{40}$/.test(destination || '')
                || !Number.isSafeInteger(finalBalance)) {
                return null;
            }
            if (canonical.status === 'closed') {
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode,
                    phase: 'closed_unconfirmed',
                    chainStatus: 'closed',
                    payoutVerified: false,
                    noteId: Number(attempt.noteId),
                    destination,
                    finalBalance,
                    transactionHash: background?.transactionHash || attempt.transactionHash,
                    closeBlockNumber: Math.max(
                        Number(background?.closeBlockNumber || 0),
                        Number(metadata.receiptBlock || 0),
                        Number(canonical.observed_block || 0)
                    ),
                    lastObservedBlock: Math.max(
                        Number(background?.lastObservedBlock || 0),
                        Number(canonical.observed_block || 0)
                    ),
                    canonicalRecovery: true,
                    clearanceReserved: attempt.clearanceReserved === true || mode === 'mutual',
                    closedAt: Number(background?.closedAt || Date.now()),
                    error: metadata.error || null
                });
                return { ...canonical, attempt, recoveredByCanonicalState: true };
            }
            if (canonical.status === 'pending_withdrawal' && mode === 'escape') {
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode: 'escape',
                    phase: 'pending',
                    chainStatus: 'pending_withdrawal',
                    noteId: Number(attempt.noteId),
                    destination,
                    finalBalance,
                    challengeDeadline: Number(canonical.challenge_deadline),
                    transactionHash: background?.transactionHash || attempt.transactionHash,
                    startBlockNumber: Math.max(
                        Number(background?.startBlockNumber || 0),
                        Number(metadata.receiptBlock || 0)
                    ),
                    lastObservedBlock: Math.max(
                        Number(background?.lastObservedBlock || 0),
                        Number(canonical.observed_block || 0)
                    ),
                    canonicalRecovery: true,
                    clearanceReserved: attempt.clearanceReserved === true,
                    error: metadata.error || null
                });
                return { ...canonical, attempt, recoveredByCanonicalState: true };
            }
            if (canonical.status === 'active' && metadata.allowActive === true
                && ((selectedOwns && !background) || background?.state)) {
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode,
                    phase: 'submitted_unconfirmed',
                    chainStatus: 'active',
                    noteId: Number(attempt.noteId),
                    destination,
                    finalBalance,
                    transactionHash: attempt.transactionHash,
                    lastObservedBlock: Number(canonical.observed_block || 0),
                    clearanceReserved: attempt.clearanceReserved === true || mode === 'mutual',
                    error: null
                });
                return {
                    ...canonical,
                    status: 'submitted_unconfirmed',
                    attempt,
                    recordId,
                    movedToBackground: true
                };
            }
            return null;
        };
        const resolveFinalizedReplacement = async (attempt, canonical) => {
            if (canonical.status !== 'active') return null;
            const nonceStatus = await this.browserTransactionNonceConsumed(
                attempt,
                attempt.noteId,
                'active',
                Number(canonical.observed_block || 0)
            );
            if (!nonceStatus.consumed) return null;
            if (attempt.clearanceReserved === true || attempt.mode === 'mutual') {
                await browserWalletRuntime.resolveLateChallengedWithdrawalAttempt(attempt);
            } else {
                await browserWalletRuntime.updateLateWithdrawalAttempt(
                    attempt.operationId,
                    attempt.transactionHash,
                    {
                        status: 'superseded',
                        resolvedAt: Date.now(),
                        resolution: 'finalized_nonce_consumed',
                        finalityCheckedBlock: nonceStatus.checkedBlock,
                        finalitySource: nonceStatus.source,
                        error: null
                    },
                    { expectedStatus: attempt.status }
                );
            }
            return {
                status: 'replaced_or_canceled',
                canonicalStatus: canonical.status,
                finalityCheckedBlock: nonceStatus.checkedBlock,
                attempt
            };
        };

        for (const attempt of attempts) {
            try {
            const sameDeployment = attempt.deploymentId === browserWalletRuntime.manifest?.deployment_id
                && Number(attempt.chainId) === Number(this.config?.funding?.chain_id)
                && String(attempt.contractAddress || '').toLowerCase()
                    === String(this.config?.funding?.contract_address || '').toLowerCase();
            if (!sameDeployment || !/^0x[0-9a-fA-F]{64}$/.test(attempt.transactionHash || '')) {
                await browserWalletRuntime.updateLateWithdrawalAttempt(
                    attempt.operationId,
                    attempt.transactionHash,
                    {
                        status: 'quarantined',
                        resolvedAt: Date.now(),
                        error: 'This saved wallet callback did not match the active zkAPI deployment.'
                    },
                    { expectedStatus: attempt.status }
                );
                results.push({ status: 'invalid_identity', attempt });
                changed = true;
                continue;
            }

            let receipt = null;
            try {
                receipt = await this.ethereum.request({
                    method: 'eth_getTransactionReceipt',
                    params: [attempt.transactionHash]
                });
            } catch (error) {
                // A wallet can throw for a pruned or replaced hash even while
                // ordinary vault reads still work. Canonical note state can
                // safely recover a replacement that moved this exact note.
                try {
                    const canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
                    const recovered = await transferCanonicalAttempt(attempt, canonical, {
                        error: `The saved transaction hash was unavailable: ${error.message}`,
                        allowActive: true
                    });
                    if (recovered) {
                        results.push({ ...recovered, replaced: true });
                        changed = true;
                        continue;
                    }
                    const resolvedReplacement = await resolveFinalizedReplacement(
                        attempt,
                        canonical
                    );
                    if (resolvedReplacement) {
                        results.push(resolvedReplacement);
                        changed = true;
                        continue;
                    }
                    results.push({
                        status: 'provider_unavailable',
                        canonicalStatus: canonical.status,
                        attempt,
                        error: error.message
                    });
                } catch (canonicalError) {
                    results.push({
                        status: 'provider_unavailable',
                        attempt,
                        error: `${error.message}; vault check failed: ${canonicalError.message}`
                    });
                }
                continue;
            }
            const mode = attempt.mode === 'mutual' ? 'mutual' : 'escape';
            if (!receipt) {
                // MetaMask replacement/speed-up transactions use a new hash.
                // The original hash may therefore have no receipt even though
                // the exact note has already moved on-chain. Canonical vault
                // state is sufficient to transfer the recovery material; the
                // closed state is still retained through Ethereum finality.
                const canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
                const resolvedReplacement = await resolveFinalizedReplacement(
                    attempt,
                    canonical
                );
                if (resolvedReplacement) {
                    results.push(resolvedReplacement);
                    changed = true;
                    continue;
                }
                const recovered = await transferCanonicalAttempt(attempt, canonical, {
                    allowActive: true
                });
                if (recovered) {
                    results.push({ ...recovered, replaced: true });
                    changed = true;
                    continue;
                }
                results.push({ status: 'submitted', canonicalStatus: canonical.status, attempt });
                continue;
            }
            if (BigInt(receipt.status || '0x0') !== 1n) {
                const finality = await this.browserRevertedReceiptFinality(
                    attempt.transactionHash,
                    receipt
                );
                await browserWalletRuntime.updateLateWithdrawalAttempt(
                    attempt.operationId,
                    attempt.transactionHash,
                    {
                        status: finality.finalized
                            ? 'reverted'
                            : 'reverted_unconfirmed',
                        receiptBlockNumber: receipt.blockNumber
                            ? Number(BigInt(receipt.blockNumber))
                            : null,
                        receiptBlockHash: receipt.blockHash || null,
                        finalityCheckedBlock: Number(finality.checkedBlock || 0),
                        finalitySource: finality.source,
                        resolvedAt: finality.finalized ? Date.now() : null,
                        error: null
                    },
                    { expectedStatus: attempt.status }
                );
                results.push({
                    status: finality.finalized ? 'reverted' : 'reverted_unconfirmed',
                    attempt,
                    finalityPending: !finality.finalized
                });
                changed = true;
                continue;
            }
            const event = parseWithdrawalReceipt(
                receipt,
                this.config.funding.contract_address,
                mode
            );
            const expectedFinalBalance = Number(attempt.finalBalance);
            if (!event || event.noteId !== BigInt(attempt.noteId)
                || event.destination.toLowerCase() !== String(attempt.destination || '').toLowerCase()
                || (Number.isSafeInteger(expectedFinalBalance)
                    && event.finalBalance !== BigInt(expectedFinalBalance))) {
                const receiptBlock = Number(BigInt(receipt.blockNumber || '0x0'));
                let canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
                if (Number(canonical.observed_block || 0) < receiptBlock) {
                    canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
                }
                if (Number(canonical.observed_block || 0) >= receiptBlock) {
                    const recoveryError = 'The saved transaction receipt did not match this withdrawal; the canonical vault state was used for recovery.';
                    const recovered = await transferCanonicalAttempt(attempt, canonical, {
                        receiptBlock,
                        error: recoveryError
                    });
                    if (recovered) {
                        results.push(recovered);
                        changed = true;
                        continue;
                    }
                    if (canonical.status === 'active') {
                        await browserWalletRuntime.updateLateWithdrawalAttempt(
                            attempt.operationId,
                            attempt.transactionHash,
                            {
                                status: 'superseded',
                                resolvedAt: Date.now(),
                                error: null
                            },
                            { expectedStatus: attempt.status }
                        );
                        results.push({ status: 'unrelated_transaction', attempt });
                        changed = true;
                        continue;
                    }
                }
                await browserWalletRuntime.updateLateWithdrawalAttempt(
                    attempt.operationId,
                    attempt.transactionHash,
                    {
                        status: 'receipt_mismatch',
                        error: 'The transaction receipt does not match its saved withdrawal identity.'
                    },
                    { expectedStatus: attempt.status }
                );
                results.push({ status: 'receipt_mismatch', attempt });
                changed = true;
                continue;
            }

            const receiptBlock = Number(BigInt(receipt.blockNumber || '0x0'));
            let canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
            if (Number(canonical.observed_block || 0) < receiptBlock) {
                canonical = await this.readBrowserWithdrawalStatus(attempt.noteId);
            }
            if (Number(canonical.observed_block || 0) < receiptBlock) {
                results.push({ status: 'rpc_behind', attempt });
                continue;
            }

            const recordId = browserWalletRuntime.withdrawalRecordId(attempt.noteId);
            const background = await browserWalletRuntime.currentWithdrawal(recordId);
            if (canonical.status === 'closed') {
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode,
                    phase: 'closed_unconfirmed',
                    chainStatus: 'closed',
                    noteId: Number(attempt.noteId),
                    destination: event.destination,
                    finalBalance: Number(event.finalBalance),
                    payoutVerified: mode === 'mutual',
                    transactionHash: background?.transactionHash || attempt.transactionHash,
                    closeBlockNumber: Math.max(
                        Number(background?.closeBlockNumber || 0),
                        mode === 'mutual' ? receiptBlock : Number(canonical.observed_block)
                    ),
                    lastObservedBlock: Math.max(
                        Number(background?.lastObservedBlock || 0),
                        Number(canonical.observed_block)
                    ),
                    clearanceReserved: attempt.clearanceReserved === true || mode === 'mutual',
                    closedAt: Number(background?.closedAt || Date.now()),
                    error: null
                });
                results.push({ ...canonical, attempt });
                changed = true;
                continue;
            }

            if (canonical.status === 'pending_withdrawal' && mode === 'escape') {
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode: 'escape',
                    phase: 'pending',
                    chainStatus: 'pending_withdrawal',
                    noteId: Number(attempt.noteId),
                    destination: canonical.destination || background?.destination || event.destination,
                    finalBalance: Number(canonical.final_balance
                        ?? background?.finalBalance
                        ?? event.finalBalance),
                    challengeDeadline: Number(canonical.challenge_deadline),
                    transactionHash: background?.transactionHash || attempt.transactionHash,
                    startBlockNumber: Math.max(
                        Number(background?.startBlockNumber || 0),
                        receiptBlock
                    ),
                    lastObservedBlock: Math.max(
                        Number(background?.lastObservedBlock || 0),
                        Number(canonical.observed_block)
                    ),
                    clearanceReserved: attempt.clearanceReserved === true,
                    error: null
                });
                changed = true;
                results.push({ ...canonical, attempt });
                continue;
            }

            if (canonical.status === 'active' && mode === 'escape') {
                const selectedOwns = Number(browserWalletRuntime.snapshot().runtime?.state?.note_id)
                    === Number(attempt.noteId);
                if (!selectedOwns && !background?.state) {
                    results.push({ status: 'missing_recovery_state', attempt });
                    continue;
                }
                await browserWalletRuntime.transferLateWithdrawalAttempt(attempt, {
                    recordId,
                    mode: 'escape',
                    phase: 'challenged_unconfirmed',
                    chainStatus: 'active',
                    noteId: Number(attempt.noteId),
                    destination: background?.destination || event.destination,
                    finalBalance: Number(background?.finalBalance ?? event.finalBalance),
                    transactionHash: background?.transactionHash || attempt.transactionHash,
                    startBlockNumber: Math.max(
                        Number(background?.startBlockNumber || 0),
                        receiptBlock
                    ),
                    challengeObservedBlock: Number(canonical.observed_block),
                    lastObservedBlock: Math.max(
                        Number(background?.lastObservedBlock || 0),
                        Number(canonical.observed_block)
                    ),
                    clearanceReserved: attempt.clearanceReserved === true,
                    error: null
                });
                results.push({ ...canonical, attempt, finalityPending: true });
                changed = true;
                continue;
            }

            results.push({ ...canonical, attempt });
            } catch (error) {
                if (error?.code === 'wrong_network') throw error;
                results.push({
                    status: 'error',
                    attempt,
                    error: error?.message || String(error)
                });
                // A single damaged or temporarily unreadable late receipt must
                // stay visible, but it must not prevent later independent
                // attempts from reconciling during every future poll.
                try {
                    await browserWalletRuntime.updateLateWithdrawalAttempt(
                        attempt.operationId,
                        attempt.transactionHash,
                        { error: error?.message || String(error) },
                        { expectedStatus: attempt.status }
                    );
                    changed = true;
                } catch (updateError) {
                    if (!/changed|no longer available/i.test(updateError?.message || '')) {
                        console.warn('Unable to retain a late withdrawal recovery error.', updateError);
                    }
                }
            }
        }

        if (changed) await this.refresh({ quiet: true });
        if (attempts.length) {
            const needsAttention = results.some(entry => [
                'error',
                'receipt_mismatch',
                'invalid_identity',
                'missing_recovery_state'
            ].includes(entry.status));
            const stillChecking = results.some(entry => [
                'submitted',
                'submitted_unconfirmed',
                'reverted_unconfirmed',
                'provider_unavailable',
                'rpc_behind'
            ].includes(entry.status));
            onStatus(needsAttention
                ? 'This withdrawal still needs attention. Open Payment history for details.'
                : stillChecking
                    ? 'The withdrawal from another tab is still being checked.'
                    : 'Withdrawal recovery is up to date.');
        }
        return results;
    }

    async syncWithdrawal(onStatus = () => {}) {

        if (this.activeLateWithdrawal) {
            onStatus('Checking the transaction returned by the earlier MetaMask window…');
            const results = await this.syncLateWithdrawalAttempts(onStatus);
            await this.refresh({ quiet: true });
            // A stale/pruned hash must not hide the canonical state of the
            // selected note. If late recovery already detached the note, the
            // background record owns it now; otherwise continue below and
            // reconcile the selected durable withdrawal directly.
            if (!this.note) {
                return results.find(entry => Number(entry.attempt?.noteId)
                    === Number(this.activeLateWithdrawal?.note_id))
                    || results[0]
                    || { status: 'submitted' };
            }
        }

        if (!this.note) {
            const synced = await this.syncEscapeWithdrawals(onStatus);
            return synced[0]?.status ? synced[0] : { status: 'no_note' };
        }

        onStatus('Checking the vault’s canonical note status…');
        const noteId = Number(this.note.note_id);
        const before = this.withdrawal;
        const prepared = this.config?.prepared_withdrawal;
        // A sponsored plan (design §3.2) is read through the exit RPC and the
        // pinned RPC, never the wallet provider; a wallet-paid one as before.
        const sponsoredSync = prepared?.fee_payer === 'payout';
        const chainRead = sponsoredSync ? this.gaslessReader() : (payload => this.ethereum.request(payload));
        const readStatus = block => this.readBrowserWithdrawalStatus(noteId, block, sponsoredSync ? { request: chainRead } : {});
        if (sponsoredSync) {
            // A sponsored operation journaled before its bundle transaction
            // was known (op_built / op_submitted): find it on chain or re-send
            // the identical bytes, never with a prompt (design §3.2), so the
            // branches below see its transaction hash.
            const journaled = await browserWalletRuntime.currentPreparedWithdrawal();
            if (isGaslessWithdrawal(journaled) && (journaled.userOp || journaled.staleUserOpHashes?.length)
                && !(journaled.transactionHashes?.length || journaled.transactionHash)) {
                try {
                    await this.recoverGaslessSubmission(journaled, onStatus);
                } catch (error) {
                    console.warn('Unable to recover the sponsored operation.', error);
                }
            }
        }
        const result = await readStatus(null);
        if (result.status === 'closed') {
            const durable = await browserWalletRuntime.currentPreparedWithdrawal();
            const mode = durable?.mode || prepared?.mode || before?.mode || 'mutual';
            const destination = durable?.destination || prepared?.destination || before?.destination;
            const finalBalance = Number(durable?.public_inputs?.final_balance
                ?? this.note.current_balance);
            const transactionHash = durable?.transactionHash
                || prepared?.transaction_hash
                || before?.transactionHash
                || null;
            let closeBlockNumber = Number(result.observed_block || 0);
            let payoutVerified = false;
            if (transactionHash && mode === 'mutual') {
                try {
                    const receipt = await chainRead({
                        method: 'eth_getTransactionReceipt',
                        params: [transactionHash]
                    });
                    const event = receipt && BigInt(receipt.status || '0x0') === 1n
                        ? parseWithdrawalReceipt(receipt, this.config.funding.contract_address, mode, { noteId })
                        : null;
                    const receiptBlock = Number(BigInt(receipt?.blockNumber || '0x0'));
                    if (String(receipt?.transactionHash || '').toLowerCase() === transactionHash.toLowerCase()
                        && event?.noteId === BigInt(noteId)
                        && event.destination.toLowerCase() === String(destination || '').toLowerCase()
                        && event.finalBalance === BigInt(finalBalance)
                        && Number.isSafeInteger(receiptBlock) && receiptBlock > 0
                        && receiptBlock <= closeBlockNumber) {
                        // Reloading long after payment must not restart the
                        // finality window at the current head. Only a matching
                        // mined withdrawal can supply the earlier checkpoint.
                        closeBlockNumber = receiptBlock;
                        payoutVerified = true;
                    }
                } catch {
                    // The canonical Closed observation is still sufficient
                    // for background recovery; retain its conservative block.
                }
            }
            // A sponsored plan's payout reached its transit account: it is
            // paid out only by the paymaster's settlement in the bundle
            // receipt (read here, or journaled earlier), else it waits there.
            let sponsoredClose = {};
            if (isGaslessWithdrawal(durable)) {
                let transitBalanceWei = null;
                try {
                    transitBalanceWei = BigInt(await chainRead({ method: 'eth_getBalance', params: [durable.transit.account, 'latest'] }));
                } catch {
                    transitBalanceWei = null;
                }
                let settlement = null;
                const contracts = this.recordGaslessContracts(durable);
                // The settlement of S's operation in the bundle: by the
                // journaled hash, or (an operation released before its late
                // inclusion was found) by S as the sender.
                if (transactionHash && contracts) {
                    try {
                        const bundle = await chainRead({ method: 'eth_getTransactionReceipt', params: [transactionHash] });
                        settlement = bundle && BigInt(bundle.status || '0x0') === 1n ? settlementOf(bundle, {
                            entryPoint: contracts.entryPoint, paymaster: contracts.paymaster, hash: durable.userOpHash || null,
                            sender: durable.transit.account, payee: durable.payout
                        }) : null;
                    } catch {
                        settlement = null;
                    }
                }
                const settled = settlement?.settled;
                const success = settlement ? settlement.success : durable.userOpSuccess === true;
                const credited = settlement ? Boolean(settlement.credited) : durable.paymasterCredited === true;
                const settledHash = settlement?.event?.userOpHash || durable.userOpHash || null;
                sponsoredClose = {
                    ...gaslessRecordFields(durable),
                    ...(settledHash ? { userOpHash: settledHash, userOpHashes: [...new Set([...(durable.userOpHashes || []), settledHash])] } : {}),
                    payoutVerified: success && !credited && (settled ? settled.paidOut > 0n : durable.userOpSuccess === true),
                    fundsWaitingInTransit: transitBalanceWei == null ? !success : transitBalanceWei > 0n,
                    ...(transitBalanceWei == null ? {} : { transitBalanceWei: transitBalanceWei.toString() }),
                    ...(settlement ? {
                        userOpSuccess: settlement.success,
                        receivedWei: settled?.received ?? 0n, chargedWei: settled?.charged ?? 0n, owedPaidWei: settled?.owedPaid ?? 0n,
                        paidOutWei: settled?.paidOut ?? 0n, paymasterCredited: credited, paymasterCreditedWei: settlement.credited?.amount ?? null
                    } : {})
                };
            }
            await browserWalletRuntime.detachClosedWithdrawal({
                mode,
                noteId,
                destination,
                finalBalance,
                transactionHash,
                closeBlockNumber,
                payoutVerified,
                lastObservedBlock: Number(result.observed_block || 0),
                clearanceReserved: durable?.clearanceReserved === true
                    || durable?.mode === 'mutual',
                ...sponsoredClose
            });
            this.rememberWithdrawal(null);
            onStatus(sponsoredClose.fundsWaitingInTransit
                ? `This balance is closed to its transit account. ${await this.transitFundsMessage(durable)}`
                : payoutVerified || sponsoredClose.payoutVerified
                    ? 'Withdrawal returned. Finality is being checked safely in the background.'
                    : 'This balance is closed. Its payment is being checked in Payment history.');
        } else if (result.status === 'pending_withdrawal') {
            const destination = result.destination
                || before?.destination
                || prepared?.destination;
            if (!destination) {
                throw new Error('The vault did not return the escape payout destination.');
            }
            const record = await browserWalletRuntime.detachEscapeWithdrawal({
                noteId,
                destination,
                finalBalance: Number(result.final_balance),
                challengeDeadline: Number(result.challenge_deadline),
                transactionHash: prepared?.transaction_hash || before?.transactionHash || null,
                lastObservedBlock: Number(result.observed_block || 0)
            });
            this.rememberWithdrawal(null);
            result.recordId = record.recordId;
            onStatus('Escape confirmed. You can add a new private balance while it waits.');
        } else {
            // Reconcile the durable write-ahead journal, not its localStorage
            // mirror. A late hash from another tab must win over a stale
            // "Active" read and can never be discarded as a canceled prompt.
            await browserWalletRuntime.recoverPreparedWithdrawalSubmissionClaim();
            let durable = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal || null;
            // A sponsored operation journaled before its bundle transaction
            // was known (op_built / op_submitted): find it on chain or re-send
            // the identical bytes, never with a prompt (design §3.2).
            if (isGaslessWithdrawal(durable) && (durable.userOp || durable.staleUserOpHashes?.length)
                && !(durable.transactionHashes?.length || durable.transactionHash)) {
                try {
                    await this.recoverGaslessSubmission(durable, onStatus);
                } catch (error) {
                    console.warn('Unable to recover the sponsored operation.', error);
                }
                durable = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal || null;
            }
            const hashes = Array.isArray(durable?.transactionHashes)
                ? durable.transactionHashes
                : durable?.transactionHash ? [durable.transactionHash] : [];
            const pendingHashes = [];
            const missingReceiptHashes = [];
            let successfulAttempts = [];
            for (const hash of hashes) {
                let receipt = null;
                try {
                    receipt = await chainRead({
                        method: 'eth_getTransactionReceipt',
                        params: [hash]
                    });
                } catch {
                    // A pruned/replaced hash can still be resolved below from
                    // its finalized sender nonce and canonical note state.
                }
                if (!receipt) {
                    const transactionAttempt = (durable?.transactionAttempts || []).find(attempt =>
                        String(attempt.hash || '').toLowerCase() === String(hash).toLowerCase());
                    const nonceStatus = await this.browserTransactionNonceConsumed(
                        transactionAttempt,
                        noteId,
                        'active',
                        Number(result.observed_block || 0)
                    );
                    if (nonceStatus.consumed) {
                        await browserWalletRuntime.markPreparedWithdrawalRetryable(hash);
                    } else {
                        pendingHashes.push(hash);
                        missingReceiptHashes.push(hash);
                    }
                } else if (BigInt(receipt.status || '0x0') === 1n) {
                    successfulAttempts.push({ hash, receipt });
                } else {
                    const finality = await this.browserRevertedReceiptFinality(hash, receipt);
                    if (finality.finalized) {
                        await browserWalletRuntime.markPreparedWithdrawalRetryable(hash);
                    } else {
                        pendingHashes.push(hash);
                    }
                }
            }
            durable = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal || null;
            const clearanceReserved = durable?.clearanceReserved === true
                || durable?.mode === 'mutual'
                || prepared?.clearance_reserved === true
                || before?.clearanceReserved === true;
            const durableMode = durable?.mode || prepared?.mode || before?.mode;
            if (successfulAttempts.length && durableMode) {
                const matchingAttempts = [];
                for (const attempt of successfulAttempts) {
                    const { receipt, hash } = attempt;
                    const event = parseWithdrawalReceipt(
                        receipt,
                        this.config.funding.contract_address,
                        durableMode,
                        { noteId }
                    );
                    if (!event || event.noteId !== BigInt(noteId)
                        || event.destination.toLowerCase() !== durable?.destination?.toLowerCase()
                        || (durable?.public_inputs?.final_balance != null
                            && event.finalBalance !== BigInt(durable.public_inputs.final_balance))) {
                        // A malformed/stale sibling hash must not poison a
                        // valid withdrawal saved for the same note. Its mined
                        // receipt conclusively cannot later become this plan.
                        await browserWalletRuntime.markPreparedWithdrawalRetryable(hash);
                        continue;
                    }
                    matchingAttempts.push(attempt);
                }
                successfulAttempts = matchingAttempts;
            }
            if (successfulAttempts.length && durableMode) {
                const receiptBlock = successfulAttempts.reduce((highest, attempt) => {
                    const value = Number(BigInt(attempt.receipt.blockNumber || '0x0'));
                    return Math.max(highest, value);
                }, 0);
                let consistent = result;
                if (Number(result.observed_block || 0) < receiptBlock) {
                    consistent = await readStatus(null);
                }
                if (Number(consistent.observed_block || 0) < receiptBlock) {
                    const transactionHash = pendingHashes[0] || successfulAttempts[0].hash;
                    onStatus('The chain receipt is newer than the vault snapshot. Check again shortly.');
                    await this.refresh();
                    return { ...result, status: 'submitted', transaction_hash: transactionHash };
                }
                if (consistent.status === 'closed') {
                    const matchedEvent = parseWithdrawalReceipt(
                        successfulAttempts[0].receipt,
                        this.config.funding.contract_address,
                        durableMode,
                        { noteId }
                    );
                    await browserWalletRuntime.detachClosedWithdrawal({
                        mode: durableMode,
                        payoutVerified: durableMode === 'mutual',
                        noteId,
                        destination: durable?.destination || matchedEvent.destination,
                        finalBalance: Number(durable?.public_inputs?.final_balance
                            ?? matchedEvent.finalBalance),
                        transactionHash: successfulAttempts[0].hash,
                        closeBlockNumber: durableMode === 'mutual'
                            ? receiptBlock
                            : Number(consistent.observed_block),
                        lastObservedBlock: Number(consistent.observed_block),
                        clearanceReserved,
                        createdAt: durable?.createdAt
                    });
                    this.rememberWithdrawal(null);
                    await this.refresh();
                    onStatus(durableMode === 'mutual'
                        ? 'Withdrawal returned. Finality is being checked safely in the background.'
                        : 'This balance is closed. Its payment is being checked in Payment history.');
                    return consistent;
                }
                if (consistent.status === 'pending_withdrawal') {
                    const destination = consistent.destination || durable?.destination;
                    const record = await browserWalletRuntime.detachEscapeWithdrawal({
                        noteId,
                        destination,
                        finalBalance: Number(consistent.final_balance),
                        challengeDeadline: Number(consistent.challenge_deadline),
                        transactionHash: successfulAttempts[0].hash,
                        startBlockNumber: receiptBlock,
                        lastObservedBlock: Number(consistent.observed_block)
                    });
                    this.rememberWithdrawal(null);
                    await this.refresh();
                    onStatus('Escape confirmed. You can add a new private balance while it waits.');
                    return { ...consistent, recordId: record.recordId };
                }
                // Active at/after a successful escape-start receipt means the
                // escape was challenged (or its short-lived block reorged).
                // Move the complete note into a nonblocking background record
                // until a finalized historical read proves which case won.
                if (durableMode === 'escape') {
                    if (durable?.submissionId) {
                        // Another MetaMask window may still return a second
                        // hash. Never erase its write-ahead claim merely
                        // because an earlier escape was challenged.
                        onStatus('The earlier escape was challenged, but another MetaMask request is still open. Close or finish that prompt before this balance is released.');
                        await this.refresh();
                        return {
                            ...consistent,
                            status: durable.phase === 'ambiguous'
                                ? 'ambiguous'
                                : 'awaiting_wallet'
                        };
                    }
                    const matchedEvent = parseWithdrawalReceipt(
                        successfulAttempts[0].receipt,
                        this.config.funding.contract_address,
                        'escape',
                        { noteId }
                    );
                    const record = await browserWalletRuntime.detachEscapeWithdrawal({
                        phase: 'challenged_unconfirmed',
                        chainStatus: 'active',
                        noteId,
                        destination: durable?.destination || matchedEvent.destination,
                        finalBalance: Number(durable?.public_inputs?.final_balance
                            ?? matchedEvent.finalBalance),
                        transactionHash: successfulAttempts[0].hash,
                        startBlockNumber: receiptBlock,
                        challengeObservedBlock: Number(consistent.observed_block),
                        lastObservedBlock: Number(consistent.observed_block),
                        clearanceReserved,
                        createdAt: durable?.createdAt
                    });
                    this.rememberWithdrawal(null);
                    await this.refresh();
                    onStatus('The escape was challenged. Its final chain status is being checked in the background, and you can add a new private balance now.');
                    return { ...consistent, recordId: record.recordId, finalityPending: true };
                }
            }
            if (pendingHashes.length) {
                const transactionHash = pendingHashes[0];
                const currentHashes = Array.isArray(durable?.transactionHashes)
                    ? durable.transactionHashes
                    : durable?.transactionHash ? [durable.transactionHash] : [];
                const missingSet = new Set(missingReceiptHashes.map(hash => hash.toLowerCase()));
                const allReceiptsMissing = currentHashes.length > 0
                    && currentHashes.every(hash => missingSet.has(hash.toLowerCase()));
                let marked = durable;
                if (allReceiptsMissing) {
                    marked = await browserWalletRuntime.markPreparedWithdrawalMissingReceipts(
                        currentHashes
                    );
                }
                const replacementIdentities = new Set((marked?.transactionAttempts || [])
                    .filter(attempt => /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                        && Number.isSafeInteger(Number(attempt.nonce))
                        && Number(attempt.nonce) >= 0)
                    .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
                const replacementAvailable = allReceiptsMissing
                    && replacementIdentities.size === 1
                    && !marked?.submissionId;
                onStatus(allReceiptsMissing
                    ? replacementAvailable
                        ? 'No receipt was found. The exact withdrawal can be safely resubmitted with its original nonce.'
                        : 'No receipt was found. Check or cancel the pending transaction in MetaMask, then check again.'
                    : `Transaction ${this.compact(transactionHash)} is not final yet.`);
                await this.refresh();
                return {
                    ...result,
                    status: allReceiptsMissing
                        ? (marked?.submissionId ? 'awaiting_wallet' : 'dropped_or_pending')
                        : 'submitted',
                    transaction_hash: transactionHash,
                    replacement_available: replacementAvailable
                };
            }
            if (durable?.submissionId && durable.submissionFrom
                && Number.isSafeInteger(Number(durable.submissionNonce))) {
                const nonceStatus = await this.browserTransactionNonceConsumed({
                    from: durable.submissionFrom,
                    nonce: Number(durable.submissionNonce)
                }, noteId, 'active', Number(result.observed_block || 0));
                if (nonceStatus.consumed) {
                    await browserWalletRuntime.markPreparedWithdrawalRetryable(null, {
                        operationId: durable.operationId,
                        submissionId: durable.submissionId
                    });
                    durable = browserWalletRuntime.snapshot().runtime?.preparedWithdrawal || null;
                }
            }
            if (durable?.submissionId) {
                const ambiguous = durable.phase === 'ambiguous';
                onStatus(ambiguous
                    ? 'MetaMask did not return a transaction ID. The balance is held safely until you check or explicitly retry.'
                    : 'MetaMask may still be open in this or another tab. No transaction ID has been returned yet.');
                await this.refresh();
                return { ...result, status: ambiguous ? 'ambiguous' : 'awaiting_wallet' };
            }
            if (durableMode === 'escape' && !clearanceReserved) {
                await browserWalletRuntime.clearPreparedWithdrawal();
                // E6: its proof was released, so the exit lock holds the
                // balance until that proof is dead; another escape is allowed.
                onStatus('No escape transaction was submitted. This balance stays withdrawal-only until its escape proof expires; you can escape again.');
                this.rememberWithdrawal(null);
            } else if (successfulAttempts.length) {
                onStatus('A mutual-close transaction mined, but the latest vault state has not caught up yet. Check again shortly.');
            } else {
                onStatus('No transaction is moving. This balance is ready to withdraw by mutual close or escape hatch.');
            }
        }
        await this.refresh();
        return result;
    }

    async browserWithdrawalStateFinality(
        noteId,
        expectedStatus,
        transitionBlockNumber,
        observedBlock = 0,
        { request = null } = {}
    ) {
        // A sponsored record reads through the gasless reader (design §3.1).
        const read = request || (payload => this.ethereum.request(payload));
        const transitionBlock = Number(transitionBlockNumber || 0);
        if (!['active', 'closed'].includes(expectedStatus)
            || !Number.isSafeInteger(transitionBlock) || transitionBlock <= 0) {
            return { finalized: false, checkedBlock: 0, source: 'unknown' };
        }

        let finalityTag = null;
        let source = 'finalized';
        try {
            const finalizedBlock = await read({
                method: 'eth_getBlockByNumber',
                params: ['finalized', false]
            });
            if (finalizedBlock?.number
                && /^0x[0-9a-fA-F]+$/.test(String(finalizedBlock.number))) {
                finalityTag = finalizedBlock.number;
            }
        } catch {
            // Some injected providers do not expose Ethereum's finalized tag.
            // Fall back to a conservative historical confirmation checkpoint.
        }

        if (!finalityTag) {
            source = 'confirmations';
            let head = Number(observedBlock || 0);
            try {
                const latest = await read({ method: 'eth_blockNumber' });
                if (/^0x[0-9a-fA-F]+$/.test(String(latest || ''))) {
                    head = Math.max(head, Number(BigInt(latest)));
                }
            } catch {
                // The already-observed chain head is sufficient for a bounded
                // fallback check; otherwise recovery simply remains retained.
            }
            const checkpoint = head - CLOSE_FINALITY_FALLBACK_BLOCKS;
            if (checkpoint < transitionBlock) {
                return { finalized: false, checkedBlock: Math.max(0, checkpoint), source };
            }
            finalityTag = `0x${checkpoint.toString(16)}`;
        }

        const checkedBlock = Number(BigInt(finalityTag));
        if (checkedBlock < transitionBlock) {
            return { finalized: false, checkedBlock, source };
        }
        try {
            const status = await this.readBrowserWithdrawalStatus(noteId, finalityTag, { request });
            return {
                finalized: status.status === expectedStatus,
                checkedBlock,
                source,
                status
            };
        } catch {
            // Archive only when a historical canonical read proves the note is
            // closed. An RPC without archive-state support keeps the encrypted
            // recovery material in the background instead of risking loss.
            return { finalized: false, checkedBlock, source };
        }
    }

    /**
     * Find a finalized EscapeWithdrawalChallenged(noteId indexed, nullifier,
     * restoredRoot) log for a background escape record, between its start
     * block and a finalized checkpoint. Read failures yield no evidence.
     */
    async finalizedEscapeChallenge(record, finalizedBlock, { request = null } = {}) {
        const startBlock = Number(record?.startBlockNumber || 0);
        if (record?.mode !== 'escape' || record.withdrawalNullifier == null
            || !Number.isSafeInteger(startBlock) || startBlock <= 0
            || !Number.isSafeInteger(finalizedBlock) || finalizedBlock < startBlock) return null;
        const vault = String(this.config?.funding?.contract_address || '').toLowerCase();
        let logs;
        try {
            logs = await (request || (payload => this.ethereum.request(payload)))({
                method: 'eth_getLogs',
                params: [{
                    address: this.config.funding.contract_address,
                    topics: [ABI.escapeChallengedEvent, `0x${abiWord(record.noteId)}`],
                    fromBlock: `0x${startBlock.toString(16)}`,
                    toBlock: `0x${finalizedBlock.toString(16)}`
                }]
            });
        } catch {
            return null;
        }
        for (const log of Array.isArray(logs) ? logs : []) {
            try {
                const data = String(log?.data || '').replace(/^0x/, '');
                const blockNumber = Number(BigInt(log?.blockNumber || '0x0'));
                if (log?.removed === true || String(log?.address || '').toLowerCase() !== vault
                    || String(log?.topics?.[0] || '').toLowerCase() !== ABI.escapeChallengedEvent
                    || BigInt(log.topics[1]) !== BigInt(record.noteId)
                    || blockNumber < startBlock || blockNumber > finalizedBlock
                    || !/^[0-9a-fA-F]{128,}$/.test(data)
                    || BigInt(`0x${data.slice(0, 64)}`) !== BigInt(record.withdrawalNullifier)) continue;
                return {
                    noteId: Number(record.noteId),
                    nullifier: `0x${data.slice(0, 64).toLowerCase()}`,
                    transactionHash: /^0x[0-9a-fA-F]{64}$/.test(log.transactionHash || '')
                        ? log.transactionHash.toLowerCase() : null,
                    blockNumber,
                    finalizedBlock,
                    observedAt: Date.now()
                };
            } catch {
                // A malformed log is never evidence.
            }
        }
        return null;
    }

    async browserWithdrawalCloseFinality(noteId, closeBlockNumber, observedBlock = 0, { request = null } = {}) {
        return this.browserWithdrawalStateFinality(
            noteId,
            'closed',
            closeBlockNumber,
            observedBlock,
            { request }
        );
    }

    async browserRevertedReceiptFinality(transactionHash, receipt, { request = null } = {}) {
        const read = request || (payload => this.ethereum.request(payload));
        const receiptBlock = receipt?.blockNumber
            && /^0x[0-9a-fA-F]+$/.test(String(receipt.blockNumber))
            ? Number(BigInt(receipt.blockNumber))
            : 0;
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')
            || !Number.isSafeInteger(receiptBlock) || receiptBlock <= 0
            || BigInt(receipt?.status || '0x1') === 1n) {
            return { finalized: false, checkedBlock: 0, source: 'invalid_receipt' };
        }

        let checkedBlock = 0;
        let source = 'finalized';
        try {
            const finalizedBlock = await read({
                method: 'eth_getBlockByNumber',
                params: ['finalized', false]
            });
            if (finalizedBlock?.number
                && /^0x[0-9a-fA-F]+$/.test(String(finalizedBlock.number))) {
                checkedBlock = Number(BigInt(finalizedBlock.number));
            }
        } catch {
            // Fall through to a conservative confirmation-depth checkpoint.
        }
        if (!checkedBlock) {
            source = 'confirmations';
            try {
                const latest = await read({ method: 'eth_blockNumber' });
                if (/^0x[0-9a-fA-F]+$/.test(String(latest || ''))) {
                    checkedBlock = Math.max(
                        0,
                        Number(BigInt(latest)) - CLOSE_FINALITY_FALLBACK_BLOCKS
                    );
                }
            } catch {
                // Missing finality evidence deliberately leaves the WAL live.
            }
        }
        if (checkedBlock < receiptBlock) {
            return { finalized: false, checkedBlock, source };
        }

        try {
            const canonicalReceipt = await read({
                method: 'eth_getTransactionReceipt',
                params: [transactionHash]
            });
            const sameBlock = canonicalReceipt
                && Number(BigInt(canonicalReceipt.blockNumber || '0x0')) === receiptBlock
                && (!receipt.blockHash || !canonicalReceipt.blockHash
                    || String(canonicalReceipt.blockHash).toLowerCase()
                        === String(receipt.blockHash).toLowerCase());
            return {
                finalized: Boolean(sameBlock
                    && BigInt(canonicalReceipt.status || '0x1') !== 1n),
                checkedBlock,
                source,
                receipt: canonicalReceipt || null
            };
        } catch {
            // A missing/replaced receipt may reappear on the canonical chain.
            // Never discard its recovery record without positive finality.
            return { finalized: false, checkedBlock, source };
        }
    }

    async browserTransactionNonceConsumed(
        transactionAttempt,
        noteId,
        expectedStatus,
        observedBlock = 0,
        { request = null } = {}
    ) {
        const read = request || (payload => this.ethereum.request(payload));
        const from = transactionAttempt?.from;
        const nonce = Number(transactionAttempt?.nonce);
        const expectedStatuses = Array.isArray(expectedStatus)
            ? expectedStatus
            : [expectedStatus];
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || transactionAttempt?.nonce == null || !Number.isSafeInteger(nonce) || nonce < 0
            || !expectedStatuses.length
            || expectedStatuses.some(status =>
                !['active', 'pending_withdrawal'].includes(status))) {
            return { consumed: false, checkedBlock: 0, source: 'missing_metadata' };
        }

        let blockTag = null;
        let source = 'finalized';
        try {
            const finalizedBlock = await read({
                method: 'eth_getBlockByNumber',
                params: ['finalized', false]
            });
            if (finalizedBlock?.number
                && /^0x[0-9a-fA-F]+$/.test(String(finalizedBlock.number))) {
                blockTag = finalizedBlock.number;
            }
        } catch {
            // Use a conservative confirmation checkpoint below.
        }
        if (!blockTag) {
            source = 'confirmations';
            let head = Number(observedBlock || 0);
            try {
                const latest = await read({ method: 'eth_blockNumber' });
                if (/^0x[0-9a-fA-F]+$/.test(String(latest || ''))) {
                    head = Math.max(head, Number(BigInt(latest)));
                }
            } catch {
                // Keep the best already-observed head.
            }
            const checkpoint = head - CLOSE_FINALITY_FALLBACK_BLOCKS;
            if (checkpoint <= 0) {
                return { consumed: false, checkedBlock: Math.max(0, checkpoint), source };
            }
            blockTag = `0x${checkpoint.toString(16)}`;
        }

        try {
            const [transactionCount, status] = await Promise.all([
                read({
                    method: 'eth_getTransactionCount',
                    params: [from, blockTag]
                }),
                this.readBrowserWithdrawalStatus(noteId, blockTag, { request })
            ]);
            const finalizedNonce = walletNonceNumber(transactionCount);
            if (finalizedNonce == null) {
                return { consumed: false, checkedBlock: Number(BigInt(blockTag)), source };
            }
            const consumed = finalizedNonce > nonce
                && expectedStatuses.includes(status.status);
            return {
                consumed,
                checkedBlock: Number(BigInt(blockTag)),
                source,
                status
            };
        } catch {
            // Never release a transaction merely because its metadata check
            // was unavailable; the durable hash remains recoverable.
            return { consumed: false, checkedBlock: Number(BigInt(blockTag)), source };
        }
    }

    async browserDepositNonceConsumed(transactionAttempt, noteId) {
        const from = transactionAttempt?.from;
        const nonce = Number(transactionAttempt?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            return { consumed: false, checkedBlock: 0, source: 'missing_metadata' };
        }
        let blockTag = null;
        let source = 'finalized';
        try {
            const finalizedBlock = await this.ethereum.request({
                method: 'eth_getBlockByNumber',
                params: ['finalized', false]
            });
            if (finalizedBlock?.number
                && /^0x[0-9a-fA-F]+$/.test(String(finalizedBlock.number))) {
                blockTag = finalizedBlock.number;
            }
        } catch {
            // Retain the deposit unless the conservative fallback below works.
        }
        if (!blockTag) {
            source = 'confirmations';
            let head = 0;
            try {
                const latest = await this.ethereum.request({ method: 'eth_blockNumber' });
                if (/^0x[0-9a-fA-F]+$/.test(String(latest || ''))) {
                    head = Number(BigInt(latest));
                }
            } catch {
                // Missing finality information keeps the WAL intact.
            }
            const checkpoint = head - CLOSE_FINALITY_FALLBACK_BLOCKS;
            if (checkpoint <= 0) {
                return { consumed: false, checkedBlock: Math.max(0, checkpoint), source };
            }
            blockTag = `0x${checkpoint.toString(16)}`;
        }
        try {
            const [transactionCount, note] = await Promise.all([
                this.ethereum.request({
                    method: 'eth_getTransactionCount',
                    params: [from, blockTag]
                }),
                this.readBrowserNote(noteId, blockTag)
            ]);
            const finalizedNonce = walletNonceNumber(transactionCount);
            const consumed = finalizedNonce != null
                && finalizedNonce > nonce
                && note.status === 0;
            return {
                consumed,
                checkedBlock: Number(BigInt(blockTag)),
                source,
                note
            };
        } catch {
            return { consumed: false, checkedBlock: Number(BigInt(blockTag)), source };
        }
    }

    async browserDepositSlotConflictFinality(plan) {
        let blockTag = null;
        let source = 'finalized';
        try {
            const finalizedBlock = await this.ethereum.request({
                method: 'eth_getBlockByNumber',
                params: ['finalized', false]
            });
            if (finalizedBlock?.number
                && /^0x[0-9a-fA-F]+$/.test(String(finalizedBlock.number))) {
                blockTag = finalizedBlock.number;
            }
        } catch {
            // Use a conservative confirmation checkpoint below.
        }
        if (!blockTag) {
            source = 'confirmations';
            try {
                const latest = await this.ethereum.request({ method: 'eth_blockNumber' });
                if (/^0x[0-9a-fA-F]+$/.test(String(latest || ''))) {
                    const checkpoint = Number(BigInt(latest)) - CLOSE_FINALITY_FALLBACK_BLOCKS;
                    if (checkpoint > 0) blockTag = `0x${checkpoint.toString(16)}`;
                }
            } catch {
                // Missing historical state keeps the original slot recoverable.
            }
        }
        if (!blockTag) return { finalized: false, checkedBlock: 0, source };
        try {
            const note = await this.readBrowserNote(Number(plan.next_note_id), blockTag);
            const sameCommitment = note.status !== 0
                && note.amount === BigInt(plan.amount)
                && BigInt(note.commitment) === BigInt(plan.commitment);
            return {
                finalized: note.status !== 0 && !sameCommitment,
                checkedBlock: Number(BigInt(blockTag)),
                source,
                note
            };
        } catch {
            return {
                finalized: false,
                checkedBlock: Number(BigInt(blockTag)),
                source
            };
        }
    }

    async syncEscapeWithdrawals(onStatus = () => {}, recordId = null) {
        // Sponsored finalizations and forwards journaled before their bundle
        // transaction was known are found by the EntryPoint's logs first
        // (design §3.2); the hashes then take the existing receipt path.
        if (this.withdrawals.some(record => isGaslessWithdrawal(record)
            && (this.recordUserOpUnresolved(record, 'finalize') || this.recordUserOpUnresolved(record, 'forward')))) {
            await this.recoverGaslessRecordOperations();
            await this.refresh({ quiet: true });
        }

        const records = this.withdrawals.filter(record => (record.phase !== 'closed'
                || record.finalizeTransactionHash
                || record.finalizeSubmissionId)
            && (!recordId || record.recordId === recordId));
        const results = [];
        let changed = false;
        let failures = 0;
        let creditedPayouts = 0;
        for (const listedRecord of records) {
            // Reconciliation needs the retained prepared plan to decide
            // whether a missing hash can be replaced by that exact proof. The
            // public snapshot intentionally strips this private material.
            let record = await browserWalletRuntime.currentWithdrawal(
                listedRecord.recordId
            ) || listedRecord;
            // A sponsored record (§3.1) is read through the exit RPC and the
            // pinned RPC, never the wallet provider: its bundle receipts and
            // logs name the transit account and the payout address.
            const sponsored = isGaslessWithdrawal(record);
            const read = sponsored ? this.gaslessReader() : (payload => this.ethereum.request(payload));
            const readOptions = sponsored ? { request: read } : {};
            try {
                let status = await this.readBrowserWithdrawalStatus(record.noteId, null, readOptions);
                let payoutVerified = false;
                // A matching finalization receipt that also carries the
                // vault's EscapePayoutDeferred log: closed, but only credited.
                let payoutCredit = null;
                // The matched finalized amount (E5), after any raise.
                let payoutMatch = null;
                // A sponsored finalization's settlement from its bundle (§3.2 amounts).
                let sponsoredFinalize = {};
                let minimumObservedBlock = Math.max(
                    Number(record.startBlockNumber || 0),
                    Number(record.lastObservedBlock || 0)
                );
                const savedStartHashes = [...new Set([record, record.preparedWithdrawal].flatMap(value => value ? [
                    ...(value.transactionHash ? [value.transactionHash] : []), ...(value.transactionHashes || []),
                    ...(value.transactionAttempts || []).map(attempt => attempt.hash)
                ] : []).filter(Boolean).map(hash => String(hash).toLowerCase()))];
                const startClaims = backgroundWithdrawalClaims(record);
                const tracksStartRecovery = record.startRecoveryPending === true
                    || record.phase === 'submitted_unconfirmed'
                    || Boolean(record.startSubmissionId) || savedStartHashes.length > 0
                    || startClaims.length > 0
                    || (record.startSubmissionOutcome === 'resolved'
                        && (record.resolvedStartClaims?.length > 0 || record.startResolutionBlock > 0));
                let unresolvedStart = false;
                let unresolvedStartHashCount = 0;
                const resolvedStartHashes = new Set();
                const resolvedStartClaims = [...(record.resolvedStartClaims || [])];
                let resolvedStartBlock = Number(record.startResolutionBlock || 0);
                const startNonceChecks = new Map();
                const checkStartNonce = async attempt => {
                    const key = `${String(attempt?.from || '').toLowerCase()}:${attempt?.nonce}`;
                    if (!startNonceChecks.has(key)) startNonceChecks.set(key,
                        this.browserTransactionNonceConsumed(attempt, record.noteId,
                            'active', Number(status.observed_block || 0), readOptions));
                    return startNonceChecks.get(key);
                };
                const rememberResolvedStart = (hash, resolution) => {
                    if (hash) resolvedStartHashes.add(hash.toLowerCase());
                    resolvedStartBlock = Math.max(resolvedStartBlock, Number(resolution.checkedBlock || 0));
                };
                const missingStartHashes = [];
                // A canonical Pending observation does not make concurrently
                // submitted starts disappear. Keep checking every migrated WAL
                // hash even after the display phase advances, so a later
                // challenge cannot restore/delete a note while a distinct start
                // proof or MetaMask prompt can still execute.
                const startHashes = tracksStartRecovery ? savedStartHashes : [];
                for (const startHash of startHashes) {
                    let startReceipt = null;
                    try {
                        startReceipt = await read({
                            method: 'eth_getTransactionReceipt',
                            params: [startHash]
                        });
                    } catch {
                        // A pruned hash can still be retired from its finalized
                        // account nonce below. Otherwise it remains unresolved.
                    }
                    if (!startReceipt) {
                        const transactionAttempt = [
                            ...(record.transactionAttempts || []),
                            ...(record.preparedWithdrawal?.transactionAttempts || [])
                        ].find(attempt =>
                            String(attempt.hash || '').toLowerCase()
                                === String(startHash).toLowerCase());
                        const nonceStatus = await checkStartNonce(transactionAttempt);
                        if (!nonceStatus.consumed) {
                            unresolvedStart = true;
                            unresolvedStartHashCount += 1;
                            missingStartHashes.push(startHash);
                        } else rememberResolvedStart(startHash, nonceStatus);
                    } else if (startReceipt && BigInt(startReceipt.status || '0x0') === 1n) {
                        const event = parseWithdrawalReceipt(
                            startReceipt,
                            this.config.funding.contract_address,
                            record.mode === 'mutual' ? 'mutual' : 'escape',
                            { noteId: record.noteId }
                        );
                        if (!event || event.noteId !== BigInt(record.noteId)
                            || event.destination.toLowerCase() !== record.destination.toLowerCase()
                            || event.finalBalance !== startFinalBalance(record)) {
                            // Keep the recovery record, but do not let one bad
                            // audit hash suppress canonical status recovery.
                            startReceipt = null;
                            const transactionAttempt = [
                                ...(record.transactionAttempts || []),
                                ...(record.preparedWithdrawal?.transactionAttempts || [])
                            ].find(attempt => String(attempt.hash || '').toLowerCase()
                                === String(startHash).toLowerCase());
                            const nonceStatus = await checkStartNonce(transactionAttempt);
                            if (!nonceStatus.consumed) {
                                unresolvedStart = true;
                                unresolvedStartHashCount += 1;
                            } else rememberResolvedStart(startHash, nonceStatus);
                        } else {
                            if (record.mode === 'mutual') payoutVerified = true;
                            minimumObservedBlock = Math.max(
                                minimumObservedBlock,
                                Number(BigInt(startReceipt.blockNumber || '0x0'))
                            );
                        }
                    } else if (startReceipt) {
                        const finality = await this.browserRevertedReceiptFinality(
                            startHash,
                            startReceipt,
                            readOptions
                        );
                        if (!finality.finalized) {
                            unresolvedStart = true;
                            unresolvedStartHashCount += 1;
                        } else rememberResolvedStart(startHash, finality);
                    }
                }
                for (const claim of startClaims) {
                    if (/^0x[0-9a-fA-F]{40}$/.test(claim.from || '')
                        && claim.nonce != null && Number.isSafeInteger(Number(claim.nonce))
                        && Number(claim.nonce) >= 0) {
                        const nonceStatus = await checkStartNonce({
                            from: claim.from,
                            nonce: Number(claim.nonce)
                        });
                        if (!nonceStatus.consumed) unresolvedStart = true;
                        else {
                            rememberResolvedStart(null, nonceStatus);
                            if (claim.submissionId && !resolvedStartClaims.some(saved =>
                                saved.submissionId === claim.submissionId && saved.operationId === claim.operationId)) {
                                resolvedStartClaims.push({ submissionId: claim.submissionId,
                                    operationId: claim.operationId, from: claim.from.toLowerCase(), nonce: Number(claim.nonce) });
                            }
                        }
                    } else {
                        // Another tab may still have a hashless MetaMask prompt
                        // for this note. Keeping it in the background is safe;
                        // restoring it while the prompt is live is not.
                        unresolvedStart = true;
                    }
                }
                if (tracksStartRecovery && !unresolvedStart
                    && (record.startRecoveryPending !== false || record.startSubmissionId || startClaims.length
                        || record.chainStatus !== status.status)) {
                    const resolvedPrepared = record.preparedWithdrawal
                        ? { ...record.preparedWithdrawal }
                        : null;
                    if (resolvedPrepared && (resolvedPrepared.submissionId === record.startSubmissionId
                        || resolvedStartClaims.some(claim => claim.submissionId === resolvedPrepared?.submissionId
                            && claim.operationId === resolvedPrepared?.operationId))) {
                        delete resolvedPrepared.submissionId;
                        delete resolvedPrepared.submissionOwner;
                        delete resolvedPrepared.submissionStartedAt;
                        delete resolvedPrepared.submissionFrom;
                        delete resolvedPrepared.submissionNonce;
                        delete resolvedPrepared.submissionNonceJournalRequired;
                        delete resolvedPrepared.submissionError;
                    }
                    const patch = {
                        startRecoveryPending: false,
                        chainStatus: status.status,
                        startSubmissionId: null,
                        startOperationId: null,
                        startSubmissionOwner: null,
                        startSubmissionStartedAt: null,
                        startSubmissionFrom: null,
                        startSubmissionNonce: null,
                        startSubmissionOutcome: 'resolved',
                        startMissingTransactionHashes: [],
                        startReplacementTransactionHashes: [],
                        startRetryFrom: null,
                        startRetryNonce: null,
                        startRetryOperationId: null,
                        startRecoveryResolvedAt: Date.now(),
                        resolvedStartClaims,
                        startResolutionBlock: resolvedStartBlock,
                        ...(resolvedPrepared ? { preparedWithdrawal: resolvedPrepared } : {})
                    };
                    await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                        expectedRevision: record.revision
                    });
                    changed = true;
                    record = await browserWalletRuntime.currentWithdrawal(record.recordId);
                }
                if (Number(status.observed_block || 0) < minimumObservedBlock) {
                    status = await this.readBrowserWithdrawalStatus(record.noteId, null, readOptions);
                }
                if (Number(status.observed_block || 0) < minimumObservedBlock) {
                    throw new Error('The connected RPC has not caught up to this withdrawal yet.');
                }
                if (status.status === 'active' && tracksStartRecovery && unresolvedStart) {
                    const allUnresolvedHashesMissing = unresolvedStartHashCount > 0
                        && missingStartHashes.length === unresolvedStartHashCount;
                    const canMarkReplacement = !record.startSubmissionId;
                    const hadReplacementMarker = ['receipt_missing', 'replacement_result_unknown']
                        .includes(record.startSubmissionOutcome);
                    const preparedHashSet = new Set((Array.isArray(
                        record.preparedWithdrawal?.transactionHashes
                    )
                        ? record.preparedWithdrawal.transactionHashes
                        : record.preparedWithdrawal?.transactionHash
                            ? [record.preparedWithdrawal.transactionHash]
                            : [])
                        .map(hash => String(hash).toLowerCase()));
                    const preparedOperationId = record.preparedWithdrawal?.operationId;
                    const replaceableMissingHashes = [...new Set(missingStartHashes
                        .map(hash => String(hash).toLowerCase())
                        .filter(hash => preparedHashSet.has(hash)
                            && (record.transactionAttempts || []).some(attempt =>
                                String(attempt.hash || '').toLowerCase() === hash
                                && attempt.operationId === preparedOperationId)))];
                    const patch = {
                        phase: 'submitted_unconfirmed',
                        chainStatus: 'active',
                        lastObservedBlock: Math.max(
                            Number(record.lastObservedBlock || 0),
                            Number(status.observed_block || 0)
                        ),
                        error: null,
                        ...(canMarkReplacement && allUnresolvedHashesMissing ? {
                            startSubmissionOutcome: 'receipt_missing',
                            startMissingTransactionHashes: [...new Set(
                                missingStartHashes.map(hash => String(hash).toLowerCase())
                            )],
                            startReplacementTransactionHashes: replaceableMissingHashes,
                            startMissingReceiptCheckedAt: Date.now()
                        } : canMarkReplacement && hadReplacementMarker ? {
                            startSubmissionOutcome: null,
                            startMissingTransactionHashes: [],
                            startReplacementTransactionHashes: []
                        } : {})
                    };
                    if (Object.entries(patch).some(([key, value]) => record[key] !== value)) {
                        await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                            expectedRevision: record.revision
                        });
                        changed = true;
                    }
                    results.push({
                        ...status,
                        status: 'submitted_unconfirmed',
                        recordId: record.recordId
                    });
                    continue;
                }

                // Reconcile every known finalization hash before interpreting
                // an Active note. A still-live wallet prompt must never be
                // erased merely because the escape was challenged.
                let finalizeHashes = Array.isArray(record.finalizeTransactionHashes)
                    ? record.finalizeTransactionHashes
                    : record.finalizeTransactionHash ? [record.finalizeTransactionHash] : [];
                if (!finalizeHashes.length && record.finalizeSubmissionId
                    && record.finalizeSubmissionFrom
                    && Number.isSafeInteger(Number(record.finalizeSubmissionNonce))) {
                    const nonceStatus = await this.browserTransactionNonceConsumed({
                        from: record.finalizeSubmissionFrom,
                        nonce: Number(record.finalizeSubmissionNonce)
                    }, record.noteId, ['pending_withdrawal', 'active'], Number(status.observed_block || 0), readOptions);
                    if (nonceStatus.consumed) {
                        await browserWalletRuntime.releaseWithdrawalFinalization(record.recordId, {
                            submission: {
                                recordId: record.recordId,
                                submissionId: record.finalizeSubmissionId,
                                operationId: record.finalizeOperationId,
                                generation: Number(record.finalizeGeneration || 0),
                                deploymentId: record.deploymentId,
                                chainId: Number(record.chainId),
                                contractAddress: record.contractAddress,
                                noteId: Number(record.noteId),
                                destination: record.destination
                            }
                        });
                        changed = true;
                        record = await browserWalletRuntime.currentWithdrawal(record.recordId);
                        finalizeHashes = [];
                    }
                }
                const successfulFinalizeHashes = [];
                const missingFinalizeHashes = [];
                for (const hash of finalizeHashes) {
                    let receipt = null;
                    try {
                        receipt = await read({
                            method: 'eth_getTransactionReceipt',
                            params: [hash]
                        });
                    } catch {
                        // Unknown remains durable and visible.
                    }
                    if (!receipt) {
                        const transactionAttempt = (record.finalizeAttempts || []).find(attempt =>
                            String(attempt.hash || '').toLowerCase() === String(hash).toLowerCase());
                        const nonceStatus = await this.browserTransactionNonceConsumed(
                            transactionAttempt,
                            record.noteId,
                            ['pending_withdrawal', 'active'],
                            Number(status.observed_block || 0),
                            readOptions
                        );
                        if (nonceStatus.consumed) {
                            await browserWalletRuntime.releaseWithdrawalFinalization(record.recordId, {
                                transactionHash: hash
                            });
                            changed = true;
                        } else {
                            missingFinalizeHashes.push(hash);
                        }
                    } else if (BigInt(receipt.status || '0x0') !== 1n) {
                        const finality = await this.browserRevertedReceiptFinality(hash, receipt, readOptions);
                        if (finality.finalized) {
                            await browserWalletRuntime.releaseWithdrawalFinalization(record.recordId, {
                                transactionHash: hash
                            });
                            changed = true;
                        }
                    } else if (receipt) {
                        const event = parseWithdrawalReceipt(
                            receipt,
                            this.config.funding.contract_address,
                            'finalize',
                            { noteId: record.noteId }
                        );
                        const receiptBlock = Number(BigInt(receipt.blockNumber || '0x0'));
                        // E5: after raises the vault pays B − c_final.
                        const match = event ? await this.escapePayoutMatch(record, event.finalBalance, receiptBlock, readOptions) : null;
                        if (!event || event.noteId !== BigInt(record.noteId)
                            || event.destination.toLowerCase() !== record.destination.toLowerCase()
                            || !match?.accepted) {
                            await browserWalletRuntime.releaseWithdrawalFinalization(record.recordId, {
                                transactionHash: hash
                            });
                            changed = true;
                            continue;
                        }
                        payoutMatch = { amount: Number(event.finalBalance), match };
                        if (Number(status.observed_block || 0) < receiptBlock) {
                            status = await this.readBrowserWithdrawalStatus(record.noteId, null, readOptions);
                        }
                        if (Number(status.observed_block || 0) >= receiptBlock
                            && status.status === 'closed') {
                            successfulFinalizeHashes.push(hash);
                            if (event.payoutCredited) {
                                payoutCredit = {
                                    amount: Number(event.creditedAmount),
                                    evidence: 'receipt'
                                };
                            } else if (sponsored) {
                                // The vault paid S: only the paymaster's
                                // Settled in this bundle (paidOut > 0 and no
                                // PayoutCredited) proves the payee was paid;
                                // a wallet-paid finalization of a sponsored
                                // escape leaves the payout in S.
                                const settlement = await this.gaslessRecordSettlement(record, hash,
                                    { reader: read, hash: record.finalizeUserOpHash || null, receipt });
                                if (settlement?.success) {
                                    sponsoredFinalize = {
                                        ...journalValue(settlement.amounts),
                                        finalizeUserOpHash: settlement.userOpHash,
                                        finalizeUserOpPhase: 'settled'
                                    };
                                    if (settlement.payoutVerified) payoutVerified = true;
                                }
                            } else payoutVerified = true;
                        }
                    }
                }
                record = await browserWalletRuntime.currentWithdrawal(record.recordId) || record;
                const currentFinalizeHashes = Array.isArray(record.finalizeTransactionHashes)
                    ? record.finalizeTransactionHashes
                    : record.finalizeTransactionHash ? [record.finalizeTransactionHash] : [];
                const missingFinalizeSet = new Set(
                    missingFinalizeHashes.map(hash => String(hash).toLowerCase())
                );
                const allFinalizeReceiptsMissing = currentFinalizeHashes.length > 0
                    && currentFinalizeHashes.every(hash =>
                        missingFinalizeSet.has(String(hash).toLowerCase()));
                if (status.status === 'pending_withdrawal'
                    && allFinalizeReceiptsMissing
                    && !record.finalizeSubmissionId) {
                    const previousRevision = Number(record.revision || 0);
                    record = await browserWalletRuntime.markWithdrawalFinalizationMissingReceipts(
                        record.recordId,
                        currentFinalizeHashes
                    ) || record;
                    if (Number(record.revision || 0) !== previousRevision) changed = true;
                }
                if (status.status !== 'closed' && Number(status.observed_block || 0) >= minimumObservedBlock
                    && (record.payoutVerified === true || record.payoutCredited === true
                        || record.payoutClaimed === true)) {
                    // The note reads open again at or after the block where
                    // it was seen Closed (minimumObservedBlock): that close
                    // was reorganized away, and its payout reading with it.
                    await browserWalletRuntime.updateWithdrawal(record.recordId, REOPENED_PAYOUT_FIELDS, {
                        expectedRevision: record.revision
                    });
                    changed = true;
                    record = await browserWalletRuntime.currentWithdrawal(record.recordId) || record;
                }
                if (status.status === 'closed' && record.mode === 'escape'
                    && !payoutVerified && !payoutCredit && record.payoutCredited !== true
                    && record.payoutVerified !== true) {
                    // Another device or a third party may have finalized this
                    // escape. Without its receipt, a credit the hardened vault
                    // holds for the destination is the conservative reading.
                    // (A push an earlier pass proved is not re-read.)
                    payoutCredit = await this.observedEscapePayoutCredit(record, status, readOptions);
                }
                const payout = {
                    ...sponsoredFinalize,
                    ...closedWithdrawalPayout({ ...record, ...sponsoredFinalize }, payoutVerified, payoutCredit),
                    ...(payoutMatch ? this.payoutMatchFields(payoutMatch, onStatus) : {})
                };
                if (payoutCredit && record.payoutCredited !== true) {
                    creditedPayouts += 1;
                    onStatus(ESCAPE_PAYOUT_CREDITED_MESSAGE);
                }
                results.push({
                    ...status,
                    recordId: record.recordId,
                    ...(status.status === 'closed' && payout.payoutCredited ? { payout_credited: true } : {})
                });
                if (status.status === 'closed') {
                    try {
                        // A sponsored escape closed without a settlement of
                        // its own finalization (a third party's, or a
                        // wallet-paid one) leaves the payout in S until a
                        // FORWARD or a sweep collects it (§3.1 scheduling).
                        let transitFields = {};
                        if (sponsored && payout.payoutVerified !== true && payout.paymasterCredited !== true
                            && record.paymasterCredited !== true) {
                            try {
                                const balance = toBigInt(await read({ method: 'eth_getBalance', params: [record.transit.account, 'latest'] }), 'balance');
                                transitFields = { fundsWaitingInTransit: balance > 0n, transitBalanceWei: balance.toString() };
                                if (balance > 0n && record.fundsWaitingInTransit !== true) onStatus(await this.transitFundsMessage(record, { reader: read }));
                            } catch {
                                transitFields = {};
                            }
                        }
                        const finalizeReceiptBlocks = [];
                        for (const hash of successfulFinalizeHashes) {
                            const receipt = await read({
                                method: 'eth_getTransactionReceipt',
                                params: [hash]
                            });
                            if (receipt?.blockNumber) {
                                finalizeReceiptBlocks.push(Number(BigInt(receipt.blockNumber)));
                            }
                        }
                        const closeBlockNumber = Math.max(
                            Number(record.closeBlockNumber || 0),
                            ...finalizeReceiptBlocks,
                            record.phase === 'closed_unconfirmed'
                                ? 0
                                : Number(status.observed_block || 0)
                        );
                        const finality = await this.browserWithdrawalCloseFinality(
                            record.noteId,
                            closeBlockNumber,
                            Number(status.observed_block || 0),
                            readOptions
                        );
                        if (!finality.finalized) {
                            const patch = {
                                phase: 'closed_unconfirmed',
                                chainStatus: 'closed',
                                ...payout,
                                ...transitFields,
                                closedAt: Number(record.closedAt || Date.now()),
                                closeBlockNumber,
                                lastObservedBlock: Math.max(
                                    minimumObservedBlock,
                                    Number(status.observed_block || 0)
                                ),
                                finalityCheckedBlock: Number(finality.checkedBlock || 0),
                                finalitySource: finality.source,
                                error: null
                            };
                            if (Object.entries(patch).some(([key, value]) => record[key] !== value)) {
                                await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                                    expectedRevision: record.revision
                                });
                                changed = true;
                            }
                            continue;
                        }

                        // Only now is it safe to forget every finalization
                        // prompt/hash and erase the private note recovery data.
                        // One record update makes that terminal transition
                        // atomic for other tabs observing IndexedDB.
                        await browserWalletRuntime.updateWithdrawal(record.recordId, {
                            phase: 'closed',
                            chainStatus: 'closed',
                            ...payout,
                            ...transitFields,
                            closedAt: Date.now(),
                            closeBlockNumber,
                            finalizedBlockNumber: Number(finality.checkedBlock),
                            finalitySource: finality.source,
                            lastObservedBlock: Math.max(
                                minimumObservedBlock,
                                Number(status.observed_block || 0)
                            ),
                            error: null
                        }, { sanitize: true, expectedRevision: record.revision });
                        changed = true;
                    } catch (error) {
                        if (!/changed|different phase|completed withdrawal/i.test(error.message)) throw error;
                    }
                } else if (status.status === 'pending_withdrawal') {
                    const stillFinalizing = Boolean(record.finalizeTransactionHash
                        || record.finalizeSubmissionId);
                    // E5: an EscapeConcessionRaised lowers the payout in place;
                    // pendingWithdrawals and pendingConcessions show it.
                    if (status.conceded != null && record.concededCurrent != null
                        && BigInt(status.conceded) > BigInt(record.concededCurrent)) {
                        onStatus(`The operator raised this escape’s concession; it now pays ${this.formatMoney(Number(status.final_balance))}.`);
                    }
                    const patch = {
                        mode: 'escape',
                        phase: record.phase === 'ambiguous'
                            ? 'ambiguous'
                            : stillFinalizing
                                ? (record.finalizeTransactionHash ? 'finalizing' : 'awaiting_wallet')
                                : 'pending',
                        chainStatus: 'pending_withdrawal',
                        challengeDeadline: Number(status.challenge_deadline),
                        destination: status.destination || record.destination,
                        finalBalance: Number(status.final_balance ?? record.finalBalance),
                        ...(status.conceded != null ? { concededCurrent: String(status.conceded) } : {}),
                        lastObservedBlock: Math.max(
                            minimumObservedBlock,
                            Number(status.observed_block || 0)
                        ),
                        error: null
                    };
                    if (Object.entries(patch).some(([key, value]) => record[key] !== value)) {
                        try {
                            await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                                expectedRevision: record.revision,
                                expectedPhase: [
                                    'pending',
                                    'submitted_unconfirmed',
                                    'challenged_unconfirmed',
                                    'recovery_unconfirmed',
                                    'finalizing',
                                    'awaiting_wallet',
                                    'ambiguous',
                                    'restored',
                                    'parked',
                                    'closed_unconfirmed'
                                ]
                            });
                            changed = true;
                        } catch (error) {
                            if (!/changed|different phase|completed withdrawal/i.test(error.message)) throw error;
                        }
                    }
                } else if (status.status === 'active') {
                    if (isUnsubmittedParkedMutualWithdrawal(
                        record, await browserWalletRuntime.currentLateWithdrawalAttempts()
                    )) {
                        // Cancel + Set Aside never started a chain transition.
                        // Repair records mislabeled by earlier clients without
                        // delaying the retry until an unrelated head finalizes.
                        const repaired = await browserWalletRuntime.repairUnsubmittedBackgroundWithdrawal(
                            record.recordId, Number(status.observed_block || 0), record.revision
                        );
                        if (repaired) {
                            changed ||= repaired.revision !== record.revision;
                            continue;
                        }
                        // A wallet claim/late hash raced the public read. Do
                        // not classify the stale record; the next pass owns it.
                        continue;
                    }
                    const unresolvedFinalization = Boolean(record.finalizeTransactionHash
                        || record.finalizeSubmissionId);
                    if (unresolvedFinalization) {
                        const patch = {
                            lastObservedBlock: Math.max(
                                minimumObservedBlock,
                                Number(status.observed_block || 0)
                            ),
                            chainStatus: 'active'
                        };
                        if (Object.entries(patch).some(([key, value]) => record[key] !== value)) {
                            await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                                expectedRevision: record.revision
                            });
                            changed = true;
                        }
                    } else {
                        const withdrawalOnly = record.clearanceReserved === true
                            || record.preparedWithdrawal?.clearanceReserved === true;
                        const challengeObservedBlock = Number(
                            record.challengeObservedBlock
                            || status.observed_block
                            || record.lastObservedBlock
                            || record.startBlockNumber
                            || 0
                        );
                        const finality = await this.browserWithdrawalStateFinality(
                            record.noteId,
                            'active',
                            Math.max(
                                Number(record.startBlockNumber || 0),
                                challengeObservedBlock,
                                resolvedStartBlock
                            ),
                            Number(status.observed_block || 0),
                            readOptions
                        );
                        if (!finality.finalized) {
                            const patch = {
                                phase: record.mode === 'escape' ? 'challenged_unconfirmed' : 'recovery_unconfirmed',
                                chainStatus: 'active',
                                challengeObservedBlock,
                                lastObservedBlock: Math.max(
                                    minimumObservedBlock,
                                    Number(status.observed_block || 0)
                                ),
                                finalityCheckedBlock: Number(finality.checkedBlock || 0),
                                finalitySource: finality.source,
                                error: null
                            };
                            if (Object.entries(patch).some(([key, value]) => record[key] !== value)) {
                                await browserWalletRuntime.updateWithdrawal(record.recordId, patch, {
                                    expectedRevision: record.revision
                                });
                                changed = true;
                            }
                            continue;
                        }
                        if (record.mode === 'mutual' && tracksStartRecovery
                            && !unresolvedStart && resolvedStartHashes.size === startHashes.length
                            && record.startSubmissionOutcome === 'resolved') {
                            // A reverted receipt alone cannot establish that
                            // the wallet's originally journaled nonce is spent
                            // (a provider might have returned an unrelated
                            // hash). Check every saved sender/nonce too.
                            for (const hash of startHashes) {
                                const attempt = [
                                    ...(record.transactionAttempts || []),
                                    ...(record.preparedWithdrawal?.transactionAttempts || [])
                                ].find(entry => String(entry.hash || '').toLowerCase() === hash);
                                const nonce = await checkStartNonce(attempt);
                                if (!nonce.consumed) {
                                    throw new Error('The saved wallet nonce is not finalized yet. Keep this withdrawal saved and check its status again.');
                                }
                                if (Number(nonce.checkedBlock) > Number(finality.checkedBlock)) {
                                    throw new Error('The vault checkpoint advanced while checking this withdrawal. Check its status again.');
                                }
                            }
                            await browserWalletRuntime.resolveBackgroundWithdrawalForRetry(record.recordId, {
                                expectedRevision: record.revision,
                                resolvedTransactionHashes: [...resolvedStartHashes],
                                finalizedBlock: Number(finality.checkedBlock),
                                observedBlock: Number(status.observed_block || 0)
                            });
                            changed = true;
                            continue;
                        }
                        const phase = withdrawalOnly ? 'parked' : 'restored';
                        // Challenge evidence comes only from a finalized
                        // EscapeWithdrawalChallenged log for this exact note
                        // and nullifier. A reorged-out start or a canceled
                        // transaction leaves no such log.
                        const challengeEvidence = record.challengeEvidence
                            || await this.finalizedEscapeChallenge(record, Number(finality.checkedBlock), readOptions);
                        if (record.phase !== phase || record.chainStatus !== 'active'
                            || (challengeEvidence && !record.challengeEvidence)) {
                            try {
                                await browserWalletRuntime.updateWithdrawal(record.recordId, {
                                    phase,
                                    chainStatus: 'active',
                                    restoredAt: Date.now(),
                                    finalizedBlockNumber: Number(finality.checkedBlock),
                                    finalitySource: finality.source,
                                    lastObservedBlock: Math.max(
                                        minimumObservedBlock,
                                        Number(status.observed_block || 0)
                                    ),
                                    ...(challengeEvidence ? { challengeEvidence, deviceNotNewest: true } : {}),
                                    // A defeat needs a request from this state's
                                    // successor: this device is not the newest.
                                    error: challengeEvidence ? DEVICE_NOT_NEWEST_MESSAGE
                                        : withdrawalOnly && record.mode === 'escape'
                                            ? 'The escape was defeated. This balance remains withdrawal-only because its close authorization was already reserved.'
                                            : null
                                }, { expectedRevision: record.revision });
                                changed = true;
                            } catch (error) {
                                if (!/changed|different phase|completed withdrawal/i.test(error.message)) throw error;
                            }
                        }
                    }
                }
            } catch (error) {
                if (error?.code === 'wrong_network') throw error;
                if (/not found|no longer available|changed|different phase|completed withdrawal/i.test(error?.message || '')) {
                    continue;
                }
                failures += 1;
                results.push({ status: 'error', recordId: record.recordId, error: error.message });
                try {
                    await browserWalletRuntime.updateWithdrawal(record.recordId, {
                        error: error.message
                    }, { expectedRevision: record.revision });
                    changed = true;
                } catch (updateError) {
                    if (!/not found|changed|different phase|completed withdrawal/i.test(updateError?.message || '')) {
                        throw updateError;
                    }
                }
            }
        }
        if (changed) await this.refresh({ quiet: true });
        if (failures) {
            const message = records.length === 1
                ? 'This withdrawal still needs attention.'
                : `Checked ${records.length} withdrawals; ${failures} need attention.`;
            onStatus(message);
            if (recordId) throw new Error(results.find(entry => entry.status === 'error')?.error || message);
        } else if (creditedPayouts) {
            onStatus(ESCAPE_PAYOUT_CREDITED_MESSAGE);
        } else if (records.length) {
            onStatus('Withdrawal status is up to date.');
        }
        return results;
    }

    async parkPreparedWithdrawal(onStatus = () => {}) {

        const record = await browserWalletRuntime.parkPreparedWithdrawal();
        this.rememberWithdrawal(null);
        await this.refresh();
        onStatus('Balance set aside safely. You can add a new private balance now.');
        return record;
    }

    async cancelPreparedWithdrawal(onStatus = () => {}) {

        const prepared = this.config?.prepared_withdrawal;
        if (!prepared && !this.config?.exit?.lock) return false;
        if (prepared && (prepared.mode === 'mutual' || prepared.clearance_reserved === true)) {
            throw new Error(prepared.clearance_granted === true
                ? 'This balance already has a mutual-close authorization. Finish it, use the escape hatch, or set it aside before funding another balance.'
                : 'This balance already sent its ownership proof, so it can only be withdrawn. Finish the withdrawal (the escape hatch needs nothing from the server) before funding another balance.');
        }
        if (prepared?.transaction_hash) {
            throw new Error('This transaction was already submitted. Check its on-chain status instead of canceling it.');
        }
        if (prepared) await browserWalletRuntime.clearPreparedWithdrawal();
        this.rememberWithdrawal(null);
        // E6: the exit lock is released now only if no escape or close proof
        // was released; otherwise once every released proof is dead, read
        // through the wallet provider before the pinned RPC.
        const provider = this.ethereum;
        try {
            await browserWalletRuntime.cancelExit(typeof provider?.request === 'function'
                ? { walletRequest: request => provider.request(request) }
                : {});
        } catch (error) {
            if (error?.code !== 'exit_locked') throw error;
            await this.refresh();
            const after = Number(error.data?.releasable_after);
            onStatus(Number.isSafeInteger(after)
                ? `Withdrawal canceled. Its escape proof was already released, so this balance stays withdrawal-only until ${new Date(after * 1_000).toLocaleString()}; you can still escape.`
                : 'Withdrawal canceled. Its escape proof was already released, so this balance stays withdrawal-only until that proof expires; you can still escape.');
            return true;
        }
        await this.refresh();
        onStatus('Withdrawal canceled. Your private balance is ready to use.');
        return true;
    }

    /** E7: an encrypted exit kit of the selected balance (JSON) for the user to keep. */
    async exportExitKit(passphrase) {
        await this.init();
        return browserWalletRuntime.exportExitKit({ passphrase });
    }

    /** The user's own exit RPC (design §6.4 E0, §6.6), persisted for this origin; null clears it. */
    setExitRpcUrl(url) {
        const saved = browserWalletRuntime.setExitRpcUrl(url);
        this.emitChange('exit-rpc');
        return saved;
    }

    async restoreWithdrawal(recordId, onStatus = () => {}) {

        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) throw new Error('The recoverable private balance is no longer available.');
        onStatus('Checking the vault before restoring this balance…');
        const canonical = await this.readBrowserWithdrawalStatus(record.noteId);
        const minimumObservedBlock = Math.max(
            Number(record.startBlockNumber || 0),
            Number(record.lastObservedBlock || 0)
        );
        if (Number(canonical.observed_block || 0) < minimumObservedBlock) {
            throw new Error('The connected RPC has not caught up to this withdrawal yet. Check again shortly.');
        }
        if (canonical.status !== 'active') {
            await this.syncEscapeWithdrawals(() => {}, recordId);
            throw new Error(canonical.status === 'pending_withdrawal'
                ? 'This escape is still active on-chain and cannot be selected as a chat balance.'
                : 'This withdrawal is already closed on-chain.');
        }
        onStatus('Restoring the selected private balance…');
        await browserWalletRuntime.restoreWithdrawal(recordId, {
            expectedRevision: record.revision,
            observedBlock: Number(canonical.observed_block || 0)
        });
        // A receipt the server finalized for the restored state (the reason a
        // challenge succeeded) installs at once, so the user can withdraw
        // from the signed next state. Quiet: restoration already succeeded.
        try {
            await browserWalletRuntime.recoverPending({ quiet: true, sweep: true });
        } catch (error) {
            console.warn('Unable to recover a settled receipt for the restored balance.', error);
        }
        await this.refresh();
        onStatus('Private balance restored.');
        return this.wallet;
    }

    async recoverUnknownFinalization(recordId, onStatus = () => {}) {

        await browserWalletRuntime.markWithdrawalFinalizationUnknown(recordId);
        await this.refresh();
        onStatus('The old wallet prompt was marked unresolved. Check the escape before retrying.');
        return this.withdrawals.find(record => record.recordId === recordId) || null;
    }

    async resolveChallengedFinalization(recordId, onStatus = () => {}) {

        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record || record.chainStatus !== 'active' || !record.finalizeSubmissionId
            || record.finalizeTransactionHash) {
            throw new Error('There is no challenged, hashless MetaMask prompt to release.');
        }
        onStatus('Confirming that the escape is still challenged…');
        const canonical = await this.readBrowserWithdrawalStatus(record.noteId);
        const chainFloor = Math.max(
            Number(record.startBlockNumber || 0),
            Number(record.lastObservedBlock || 0)
        );
        if (canonical.status !== 'active'
            || Number(canonical.observed_block || 0) < chainFloor) {
            throw new Error('The latest vault state does not safely confirm a challenged escape. Check the transaction again.');
        }
        await browserWalletRuntime.resolveChallengedWithdrawalFinalization(recordId, {
            expectedRevision: record.revision,
            observedBlock: Number(canonical.observed_block)
        });
        await this.refresh();
        onStatus('Old MetaMask prompt released. This balance can be selected again.');
        return this.withdrawals.find(entry => entry.recordId === recordId) || null;
    }

    async retryUnknownFinalization(recordId, onStatus = () => {}) {

        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (record?.phase !== 'ambiguous') {
            throw new Error('There is no unresolved finalization request to retry.');
        }
        if (record.chainStatus === 'active') {
            throw new Error('This escape was challenged. Close the old MetaMask prompt instead of retrying finalization.');
        }
        await browserWalletRuntime.authorizeWithdrawalFinalizationRetry(recordId);
        await this.refresh({ quiet: true });
        onStatus('Retry authorized. Opening a new MetaMask request…');
        return this.finalizeEscape(recordId, onStatus);
    }

    async retryDroppedFinalization(recordId, onStatus = () => {}) {

        const current = await browserWalletRuntime.currentWithdrawal(recordId);
        if (!current || current.phase !== 'finalizing'
            || !['receipt_missing', 'replacement_result_unknown']
                .includes(current.finalizeSubmissionOutcome)) {
            throw new Error('Check the pending escape before replacing its finalization.');
        }
        onStatus('Connecting to the MetaMask account that submitted this finalization…');
        const from = await this.connectWallet();
        const submission = await browserWalletRuntime.claimWithdrawalFinalizationReplacement(
            recordId,
            from
        );
        let submittedHash = null;
        let submissionMetadata = {
            from: submission.replacementFrom,
            nonce: Number(submission.replacementNonce)
        };
        try {
            onStatus('Confirm the exact same finalization in MetaMask. It reuses the original nonce, so only one version can execute.');
            await this.sendContractTransaction(
                from,
                this.config.funding.contract_address,
                encodeFinalizeEscape(submission.noteId),
                async hash => {
                    submittedHash = hash;
                    await browserWalletRuntime.rememberWithdrawalFinalization(
                        recordId,
                        hash,
                        submission,
                        submissionMetadata
                    );
                    onStatus(`Finalization replacement submitted ${this.compact(hash)} · checking confirmation…`);
                },
                async metadata => {
                    submissionMetadata = metadata;
                    await browserWalletRuntime.rememberWithdrawalFinalizationSubmissionMetadata(
                        recordId,
                        submission,
                        metadata
                    );
                },
                submission.replacementNonce,
                { kind: 'finalization', submission }
            );
        } catch (error) {
            if (error?.transactionHash) {
                submittedHash = error.transactionHash;
                try {
                    await browserWalletRuntime.rememberWithdrawalFinalization(
                        recordId,
                        submittedHash,
                        submission,
                        submissionMetadata
                    );
                } catch (journalError) {
                    error.journalRecoveryError = journalError;
                }
            } else {
                await browserWalletRuntime.releaseWithdrawalFinalizationReplacementClaim(
                    recordId,
                    submission,
                    error?.message || 'MetaMask did not return a finalization replacement transaction ID.'
                );
                error.shortMessage = error?.broadcastPossible === false || isWalletRejection(error)
                    ? 'The finalization replacement was canceled before broadcast. The original transaction remains saved and can be replaced again.'
                    : 'MetaMask did not return a replacement transaction ID. The original finalization remains saved, and you can safely resubmit it with the same nonce.';
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        await this.refresh({ quiet: true });
        const results = await this.syncEscapeWithdrawals(onStatus, recordId);
        return results[0] || { status: 'submitted', transaction_hash: submittedHash };
    }

    async finalizeEscape(recordIdOrStatus = null, maybeStatus = () => {}, options = {}) {
        const key = typeof recordIdOrStatus === 'string' ? recordIdOrStatus : 'selected';
        if (this.finalizePromise) {
            if (this.finalizePromiseKey === key) return this.finalizePromise;
            throw new Error('A different escape finalization is already running.');
        }
        const operation = this.performFinalizeEscape(recordIdOrStatus, maybeStatus, options);
        this.finalizePromise = operation;
        this.finalizePromiseKey = key;
        try {
            return await operation;
        } finally {
            if (this.finalizePromise === operation) {
                this.finalizePromise = null;
                this.finalizePromiseKey = null;
            }
        }
    }

    /**
     * The sponsored finalization a gasless record journaled (its claim,
     * `finalizeUserOp`, its hashes) when the current profile no longer pins
     * the record's paymaster and factory (`gasless: null`, or other pins):
     * it is never re-sent, so the wallet-paid finalization must not wait on
     * its claim forever. It is looked for on chain through the journaled
     * EntryPoint (the read RPC only). Included and settled, its bundle
     * transaction and settlement are recorded and `{ result }` reports it
     * (nothing is signed). Included but reverted (its vault call failed),
     * it is released (claim and op body cleared, phase 'reverted', hashes
     * kept) and the vault is read again: closed by a third party, the record
     * is synced and `{ result }` reports the payout waiting in S for
     * sweepTransit; still pending, `{ record }` goes on to the wallet. Not included, it is given the re-send window from its last
     * activity (refused with `user_op_pending` meanwhile, or while a client
     * still follows it), then released: the claim and the op body are
     * cleared, its hashes stay journaled for the background pass's
     * late-inclusion look, and `{ record }` is what the wallet path claims.
     * A record whose pins still match, or with no journaled operation, is
     * returned as is.
     */
    async releaseUnpinnedFinalization(withdrawal, onStatus = () => {}) {
        const hashes = this.recordUserOpHashes(withdrawal, 'finalize');
        if (!withdrawal?.finalizeSubmissionId || !(withdrawal.finalizeUserOp || withdrawal.finalizeUserOpHash) || !hashes.length
            || withdrawal.finalizeTransactionHash || (withdrawal.finalizeTransactionHashes || []).length) return { record: withdrawal };
        try {
            this.requireRecordPins(withdrawal);
            return { record: withdrawal };
        } catch (error) {
            if (error?.code !== 'gasless_record_not_pinned') throw error;
        }
        const reader = this.gaslessReader();
        const context = this.recordReaderContext(withdrawal, reader);
        if (!context) return { record: withdrawal };
        onStatus('Looking on chain for the sponsored finalization sent earlier…');
        const found = await this.recordUserOpInclusion(context, withdrawal, 'finalize');
        const submission = {
            recordId: withdrawal.recordId, submissionId: withdrawal.finalizeSubmissionId, operationId: withdrawal.finalizeOperationId,
            generation: Number(withdrawal.finalizeGeneration || 0), deploymentId: withdrawal.deploymentId, chainId: Number(withdrawal.chainId),
            contractAddress: withdrawal.contractAddress, noteId: Number(withdrawal.noteId), destination: withdrawal.destination
        };
        // Included but reverted (its vault call failed, e.g. exits paused):
        // released as performGaslessFinalization releases it, never recorded
        // as this record's finalization, so the wallet path is not blocked.
        const settlement = found ? await this.gaslessRecordSettlement(withdrawal, found.transactionHash, { reader, hash: found.userOpHash }) : null;
        if (found && (settlement ? !settlement.success : found.success === false)) {
            await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, { submission });
            await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
                finalizeUserOp: null, finalizeUserOpPhase: 'reverted', finalizeUserOpSubmittedAt: null, finalizeUserOpFollowedAt: null,
                finalizeUserOpRevertedTransactionHash: found.transactionHash,
                ...this.revertedRecordUserOpFields(withdrawal, 'finalize', [found.userOpHash])
            });
            const released = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId) || withdrawal;
            const after = await this.readBrowserWithdrawalStatus(Number(withdrawal.noteId), null, { request: reader });
            if (after.status === 'closed') {
                // A third party finalized the escape first: the vault paid S,
                // where the payout waits for sweepTransit (wallet-paid).
                onStatus(`The sponsored finalization sent earlier reverted in ${this.compact(found.transactionHash)}; a third party finalized this escape first.`);
                await this.syncEscapeWithdrawals(onStatus, withdrawal.recordId);
                const closed = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId) || released;
                return { result: { status: 'closed', recordId: withdrawal.recordId, finalizedByThirdParty: true,
                    fundsWaitingInTransit: closed.fundsWaitingInTransit === true, transitAccount: context.transit.account } };
            }
            onStatus(`The sponsored finalization sent earlier reverted in ${this.compact(found.transactionHash)}; it was released.`);
            return { record: released };
        }
        if (found) {
            await this.rememberRecordUserOpInclusion(withdrawal, 'finalize', found, reader);
            await this.refresh({ quiet: true });
            onStatus(`The sponsored finalization sent earlier was included in ${this.compact(found.transactionHash)}. Nothing was signed; its settlement is checked in the background.`);
            return { result: { status: 'finalizing', recordId: withdrawal.recordId, sponsored: true, transactionHash: found.transactionHash,
                userOpHash: found.userOpHash } };
        }
        const resendAfterMs = this.gaslessTiming.resendAfterMs;
        const lastActiveAt = Math.max(Number(withdrawal.finalizeSubmissionStartedAt || 0), Number(withdrawal.finalizeUserOpBuiltAt || 0),
            Number(withdrawal.finalizeUserOpSubmittedAt || 0), Number(withdrawal.finalizeUserOpFollowedAt || 0));
        const followed = browserWalletRuntime.gaslessClaimLive({
            submissionId: withdrawal.finalizeSubmissionId, owner: withdrawal.finalizeSubmissionOwner, lastActiveAt
        }, resendAfterMs);
        if (followed || Date.now() - lastActiveAt < resendAfterMs) {
            throw gaslessError('user_op_pending', {
                userOpHash: withdrawal.finalizeUserOpHash || hashes.at(-1), retryAfterMs: Math.max(0, lastActiveAt + resendAfterMs - Date.now())
            }, 'The sponsored finalization sent earlier may still be included. This app no longer sponsors its paymaster, so it is not sent again; finalize from the wallet once it has had time to land.');
        }
        await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, { submission });
        await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
            finalizeUserOp: null, finalizeUserOpPhase: 'released', finalizeUserOpSubmittedAt: null, finalizeUserOpFollowedAt: null
        });
        onStatus('The sponsored finalization sent earlier was not included and is no longer sponsored; it was released. A late inclusion is still recorded.');
        return { record: await browserWalletRuntime.currentWithdrawal(withdrawal.recordId) || withdrawal };
    }

    async performFinalizeEscape(recordIdOrStatus = null, maybeStatus = () => {}, options = {}) {
        const hasRecordId = typeof recordIdOrStatus === 'string';
        const onStatus = typeof recordIdOrStatus === 'function' ? recordIdOrStatus : maybeStatus;
        let withdrawal = hasRecordId
            ? this.withdrawals.find(record => record.recordId === recordIdOrStatus)
            : this.withdrawals.find(record => record.mode === 'escape' && record.phase !== 'closed');
        if (withdrawal?.recordId) {
            withdrawal = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId);
        }
        const resumablePhases = ['pending', 'finalizing', 'awaiting_wallet'];
        // A sponsored escape a third party finalized (the background sync
        // closed the record without a settlement of S's own finalization)
        // leaves its payout in S: finalizing it means a FORWARD (§3.1 scheduling).
        if (isGaslessWithdrawal(withdrawal) && ['closed', 'closed_unconfirmed'].includes(withdrawal?.phase)
            && withdrawal.payoutVerified !== true && withdrawal.paymasterCredited !== true
            && (options?.fees ?? 'payout') === 'payout') {
            return this.performTransitForward(withdrawal, onStatus, options);
        }
        if (!resumablePhases.includes(withdrawal?.phase)) {
            throw new Error('There is no pending escape withdrawal.');
        }
        if (Date.now() < Number(withdrawal.challengeDeadline) * 1000) {
            throw new Error(`The safety window has ${this.formatExpiry(withdrawal.challengeDeadline)} remaining.`);
        }
        // A sponsored escape finalizes through the paymaster by default
        // (design §3.2); `fees: 'wallet'` pays from the connected account and
        // leaves the payout in the transit account for sweepTransit.
        const fees = options?.fees ?? (isGaslessWithdrawal(withdrawal) ? 'payout' : 'wallet');
        if (!['wallet', 'payout'].includes(fees)) throw new TypeError('Choose wallet or payout for the finalization fees.');
        if (fees === 'payout') return this.performGaslessFinalization(withdrawal, onStatus, options);
        const sponsoredRecord = isGaslessWithdrawal(withdrawal);
        if (sponsoredRecord) {
            // A sponsored finalization this record sent before the profile
            // stopped pinning its paymaster is followed on chain, then
            // released, before the wallet pays (it never blocks the wallet).
            const unpinned = await this.releaseUnpinnedFinalization(withdrawal, onStatus);
            if (unpinned.result) return unpinned.result;
            withdrawal = unpinned.record;
        }

        onStatus('Connecting to MetaMask for finalization…');
        const from = await this.connectWallet();
        let submittedHash = withdrawal.finalizeTransactionHash || null;
        let submission = null;
        let submissionMetadata = null;
        let receipt;
        try {
            const claim = await browserWalletRuntime.claimWithdrawalFinalization(
                withdrawal.recordId
            );
            submittedHash = claim.transactionHash || null;
            submission = claim;
            withdrawal = claim.record;
            if (submittedHash) {
                onStatus(`Checking submitted finalization ${this.compact(submittedHash)}…`);
                receipt = await this.waitForReceipt(submittedHash);
            } else {
                onStatus('Confirm finalization in MetaMask…');
                receipt = await this.sendContractTransaction(
                    from,
                    this.config.funding.contract_address,
                    encodeFinalizeEscape(withdrawal.noteId),
                    async hash => {
                            submittedHash = hash;
                            await browserWalletRuntime.rememberWithdrawalFinalization(
                                withdrawal.recordId,
                                hash,
                                submission,
                                submissionMetadata
                            );
                            const metadata = await this.submittedTransactionMetadata(hash, from);
                            if (metadata) {
                                await browserWalletRuntime.rememberWithdrawalFinalization(
                                    withdrawal.recordId,
                                    hash,
                                    submission,
                                    metadata
                                );
                            }
                            onStatus(`Finalization submitted ${this.compact(hash)} · waiting for confirmation…`);
                        },
                    async metadata => {
                            submissionMetadata = metadata;
                            await browserWalletRuntime.rememberWithdrawalFinalizationSubmissionMetadata(
                                withdrawal.recordId,
                                submission,
                                metadata
                            );
                        },
                    null,
                    { kind: 'finalization', submission }
                );
            }
        } catch (error) {
            if (error?.transactionHash) {
                submittedHash = error.transactionHash;
                try {
                    await browserWalletRuntime.rememberWithdrawalFinalization(
                        withdrawal.recordId,
                        submittedHash,
                        submission,
                        submissionMetadata
                    );
                    const metadata = await this.submittedTransactionMetadata(submittedHash, from);
                    if (metadata) {
                        await browserWalletRuntime.rememberWithdrawalFinalization(
                            withdrawal.recordId,
                            submittedHash,
                            submission,
                            metadata
                        );
                    }
                } catch (journalError) {
                    error.journalRecoveryError = journalError;
                }
            }
            let chainReceipt = null;
            if (submittedHash) {
                try {
                    chainReceipt = await this.ethereum.request({
                        method: 'eth_getTransactionReceipt',
                        params: [submittedHash]
                    });
                } catch {
                    // Preserve an ambiguous submitted hash for reload.
                }
            }
            if (chainReceipt && BigInt(chainReceipt.status || '0x0') !== 1n) {
                const finality = await this.browserRevertedReceiptFinality(
                    submittedHash,
                    chainReceipt
                );
                if (finality.finalized) {
                    await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, {
                        transactionHash: submittedHash
                    });
                    error.shortMessage = 'The finalization transaction reverted. The escape is still safe and ready to retry.';
                } else {
                    error.shortMessage = 'The finalization currently shows as reverted, but that block is not final yet. It remains tracked and will be checked automatically.';
                }
            } else if (!submittedHash && submission
                && (error?.broadcastPossible === false || isWalletRejection(error))) {
                await browserWalletRuntime.releaseWithdrawalFinalization(withdrawal.recordId, {
                    submission
                });
            } else if (!submittedHash && submission && error?.broadcastPossible === true) {
                await browserWalletRuntime.markWithdrawalFinalizationAmbiguous(
                    withdrawal.recordId,
                    submission,
                    error?.message || 'MetaMask did not return a transaction ID.'
                );
                error.shortMessage = 'MetaMask did not return a transaction ID. Check the escape status; retry only if it is still pending.';
            }
            if (!submittedHash && isWalletRejection(error)) {
                error.shortMessage = 'MetaMask canceled finalization. The withdrawal is still safe and can be finalized later.';
            }
            await this.refresh({ quiet: true });
            throw error;
        }
        const event = parseWithdrawalReceipt(receipt, this.config.funding.contract_address, 'finalize');
        // E5: after raises the vault pays B − c_final, not the amount the
        // escape started with.
        const match = event
            ? await this.escapePayoutMatch(withdrawal, event.finalBalance, Number(BigInt(receipt?.blockNumber || '0x0')))
            : null;
        if (!event || event.noteId !== BigInt(withdrawal.noteId)
            || event.destination.toLowerCase() !== withdrawal.destination.toLowerCase()
            || !match?.accepted) {
            throw new Error('The finalization event did not match the pending withdrawal.');
        }
        const confirmed = await this.confirmMinedWithdrawalStatus(withdrawal.noteId, receipt);
        if (confirmed.status !== 'closed') {
            throw new Error(`The vault reports ${confirmed.status} after finalization.`);
        }
        // EscapeWithdrawalFinalized alone does not prove the payout arrived:
        // with an EscapePayoutDeferred log the vault only credited it.
        const credited = event.payoutCredited === true;
        // A background pass may have read this close first, without the receipt.
        const current = await browserWalletRuntime.currentWithdrawal(withdrawal.recordId) || withdrawal;
        await browserWalletRuntime.updateWithdrawal(withdrawal.recordId, {
            phase: 'closed_unconfirmed',
            chainStatus: 'closed',
            ...closedWithdrawalPayout(current, !credited, credited ? {
                amount: Number(event.creditedAmount),
                evidence: 'receipt'
            } : null),
            ...this.payoutMatchFields({ amount: Number(event.finalBalance), match }, onStatus),
            closedAt: Date.now(),
            closeBlockNumber: Number(BigInt(receipt?.blockNumber || '0x0')),
            lastObservedBlock: Number(confirmed.observed_block || 0),
            error: null,
            // Paid from a wallet to a transit account: the vault pushed the
            // payout to the transit account, where it waits for sweepTransit.
            ...(sponsoredRecord && !credited ? { payoutVerified: false, fundsWaitingInTransit: true,
                transitBalanceWei: (event.finalBalance * NATIVE_WEI_PER_UNIT).toString() } : {})
        });
        await this.refresh();
        onStatus(credited
            ? `${ESCAPE_PAYOUT_CREDITED_MESSAGE} Finality is being checked safely in the background.`
            : sponsoredRecord
                ? `Escape finalized to its transit account. ${await this.transitFundsMessage(withdrawal)}`
                : 'Escape withdrawal returned. Finality is being checked safely in the background.');
        return { status: 'closed', event, receipt, ...(credited ? { payoutCredited: true } : {}),
            ...(sponsoredRecord && !credited ? { fundsWaitingInTransit: true, transitAccount: withdrawal.destination } : {}) };
    }

    /**
     * E5: whether an escape's finalized or credited amount matches its
     * record: f' == B − c_final after every EscapeConcessionRaised of the
     * note between initiation and `toBlock`, and B − b <= f' <= B − c_init
     * (below B − b the record still closes, with an alert). A record saved
     * before vault revision 3 (no B or c_init) must match exactly.
     */
    async escapePayoutMatch(record, amount, toBlock, { request = null } = {}) {
        if (record?.stateBalance == null || record?.concededAtInit == null) {
            const accepted = BigInt(amount) === BigInt(record?.finalBalance ?? -1);
            return { accepted, exact: true, concededFinal: null, alert: null };
        }
        const raises = await this.escapeConcessionRaisesFor(record, toBlock, { request });
        return matchEscapePayout({
            stateBalance: record.stateBalance,
            concededAtInit: record.concededAtInit,
            boundAtState: record.boundAtState ?? null,
            raises: raises == null ? null : [...raises, ...(record.concededCurrent != null ? [record.concededCurrent] : [])],
            amount
        });
    }

    /**
     * Every EscapeConcessionRaised log of this escape (its note and
     * nullifier) from its start block to `toBlock`, or null when the logs
     * cannot be read.
     */
    async escapeConcessionRaisesFor(record, toBlock, { request = null } = {}) {
        const fromBlock = Number(record.startBlockNumber || 0);
        const vault = this.config?.funding?.contract_address;
        if (!vault || !Number.isSafeInteger(fromBlock) || fromBlock <= 0
            || !Number.isSafeInteger(Number(toBlock)) || Number(toBlock) < fromBlock) return null;
        let logs;
        try {
            // A sponsored record reads through the read RPC (design §3.1).
            logs = await (request || (payload => this.ethereum.request(payload)))({
                method: 'eth_getLogs',
                params: [{ address: vault, topics: [ABI.escapeConcessionRaisedEvent, `0x${abiWord(record.noteId)}`],
                    fromBlock: rpcQuantity(fromBlock), toBlock: rpcQuantity(Number(toBlock)) }]
            });
        } catch {
            return null;
        }
        if (!Array.isArray(logs)) return null;
        const raises = [];
        for (const log of logs) {
            let event;
            try {
                event = decodeVaultEvent(log, vault);
            } catch {
                return null;
            }
            if (event?.event !== 'EscapeConcessionRaised' || event.noteId !== BigInt(record.noteId)) continue;
            if (record.withdrawalNullifier != null && event.nullifier !== BigInt(record.withdrawalNullifier)) continue;
            raises.push({ conceded: event.conceded, finalBalance: event.finalBalance });
        }
        return raises;
    }

    /** The record fields of a matched payout: its amount, c_final and any alert. */
    payoutMatchFields({ amount, match }, onStatus = () => {}) {
        if (!match || match.concededFinal == null) return {};
        if (match.alert) onStatus(CONCESSION_EXCEEDED_BOUND_MESSAGE);
        return {
            finalBalance: Number(amount),
            concededFinal: String(match.concededFinal),
            ...(match.alert ? { payoutAlert: match.alert } : {})
        };
    }

    /** Credited escape payouts this browser has not yet seen delivered. */
    get creditedEscapePayouts() {
        return this.withdrawals.filter(record => record.payoutCredited === true
            && record.payoutClaimed !== true
            && ['closed_unconfirmed', 'closed'].includes(record.phase));
    }

    /**
     * escapePayoutCredits(destination) on the hardened vault: the escape
     * payouts (in vault units) that it holds for `destination`.
     */
    async readEscapePayoutCredit(destination, blockTag = 'latest', { request = null } = {}) {
        const vault = this.config?.funding?.contract_address;
        if (!vault) throw new Error('Initialize the wallet before reading escape payouts.');
        // The gasless reader is chain-checked itself; the wallet provider is asked otherwise.
        if (!request) await this.assertFundingChain();
        const word = await (request || (payload => this.ethereum.request(payload)))({
            method: 'eth_call',
            params: [{
                to: vault,
                data: encodeEscapePayoutCredits(destination)
            }, blockTag]
        });
        if (!/^0x[0-9a-fA-F]{64}$/.test(word || '')) {
            throw Object.assign(new Error('The vault did not return an escape payout credit. This build expects a concession vault (revision 3), which holds escape payouts.'), {
                code: 'vault_value_invalid'
            });
        }
        return BigInt(word);
    }

    // A closed escape without its own finalization receipt: a nonzero credit
    // for the destination on a hardened vault is reported as credited (the
    // claim delivers it either way). Read failures leave the record unchanged.
    async observedEscapePayoutCredit(record, status, { request = null } = {}) {
        if (Number(record.finalBalance || 0) <= 0
            || !/^0x[0-9a-fA-F]{40}$/.test(record.destination || '')) return null;
        const observedBlock = Number(status.observed_block || 0);
        try {
            const credit = await this.readEscapePayoutCredit(record.destination,
                observedBlock > 0 ? rpcQuantity(observedBlock) : 'latest', { request });
            return credit > 0n ? { amount: null, evidence: 'vault_credit' } : null;
        } catch (error) {
            if (error?.code === 'wrong_network') throw error;
            return null;
        }
    }

    /**
     * Delivers the escape payout a hardened vault holds for a credited
     * withdrawal record's destination: reads escapePayoutCredits(destination)
     * and sends claimEscapePayout(destination), which pays that address all
     * its credits. Only an EscapePayoutClaimed log for the destination (or a
     * zero credit once the note is closed) marks the payout delivered. The
     * connected account only pays gas; it receives nothing.
     */
    async claimEscapePayout(recordId, onStatus = () => {}) {
        if (this.payoutClaimPromise) {
            if (this.payoutClaimPromiseKey === recordId) return this.payoutClaimPromise;
            throw new Error('A different escape payout claim is already running.');
        }
        const operation = this.performClaimEscapePayout(recordId, onStatus);
        this.payoutClaimPromise = operation;
        this.payoutClaimPromiseKey = recordId;
        try {
            return await operation;
        } finally {
            if (this.payoutClaimPromise === operation) {
                this.payoutClaimPromise = null;
                this.payoutClaimPromiseKey = null;
            }
        }
    }

    async creditedEscapePayoutRecord(recordId) {
        const record = await browserWalletRuntime.currentWithdrawal(recordId);
        if (!record || record.payoutCredited !== true
            || !['closed_unconfirmed', 'closed'].includes(record.phase)
            || !/^0x[0-9a-fA-F]{40}$/.test(record.destination || '')) {
            throw new Error('The vault holds no escape payout for this withdrawal.');
        }
        return record;
    }

    async performClaimEscapePayout(recordId, onStatus = () => {}) {
        const vault = this.config?.funding?.contract_address;
        if (!vault) throw new Error('Initialize the wallet before claiming an escape payout.');
        const record = await this.creditedEscapePayoutRecord(recordId);
        const destination = record.destination.toLowerCase();
        const delivered = () => ({ status: 'claimed', recordId, destination,
            transactionHash: record.payoutClaimTransactionHash || null });
        if (record.payoutClaimed === true) {
            onStatus('This escape payout was already delivered to its destination.');
            return delivered();
        }

        // Claims sent earlier for this destination: before a reload, by a
        // manual signer, or from another credited record of the same address
        // (one claim pays all of the destination's credits).
        const sentHashes = [...new Set((await this.unclaimedEscapeCredits(destination))
            .flatMap(entry => entry.payoutClaimTransactionHashes || [])
            .map(hash => String(hash).toLowerCase()))];
        for (const hash of sentHashes) {
            let receipt = null;
            try {
                receipt = await this.ethereum.request({ method: 'eth_getTransactionReceipt', params: [hash] });
            } catch {
                // An unreadable receipt proves nothing; the vault is read below.
            }
            const claim = receipt && BigInt(receipt.status || '0x0') === 1n
                ? parseEscapePayoutClaim(receipt, vault, destination) : null;
            if (claim) {
                const settled = await this.recordEscapePayoutClaim(destination, receipt, claim);
                if (settled.includes(recordId)) {
                    return this.escapePayoutClaimed(recordId, destination, receipt, claim, onStatus);
                }
                // That claim was mined before this record's credit existed.
                continue;
            }
            if (!receipt) {
                // Still in the mempool: it pays this credit too once mined,
                // and a second claim would only revert. A transaction the
                // node no longer knows was dropped.
                const transaction = await this.ethereum.request({
                    method: 'eth_getTransactionByHash',
                    params: [hash]
                }).catch(() => null);
                if (transaction) {
                    onStatus(`The payout claim ${this.compact(hash)} is still pending. Check again after it confirms.`);
                    return { status: 'pending', recordId, destination, transactionHash: hash };
                }
            }
        }

        onStatus('Checking the payout the vault holds for this address…');
        await this.assertFundingChain();
        const blockTag = await this.ethereum.request({ method: 'eth_blockNumber' });
        if (!/^0x[0-9a-fA-F]+$/.test(String(blockTag || ''))) {
            throw new Error('The wallet provider returned an invalid block number.');
        }
        if (await this.readEscapePayoutCredit(destination, blockTag) === 0n) {
            return this.recordClearedEscapePayout(recordId, destination, blockTag, onStatus);
        }

        onStatus('Connecting to MetaMask to deliver the payout…');
        const from = await this.connectWallet();
        let receipt;
        try {
            onStatus('Confirm the payout claim in MetaMask. Your account pays only gas; the vault pays the destination.');
            receipt = await this.sendContractTransaction(
                from,
                vault,
                encodeClaimEscapePayout(destination),
                async hash => {
                    await this.rememberEscapePayoutClaim(recordId, hash);
                    onStatus(`Payout claim submitted ${this.compact(hash)} · waiting for confirmation…`);
                },
                null,
                null,
                {
                    kind: 'escape-payout-claim',
                    submission: { recordId, noteId: Number(record.noteId), destination }
                }
            );
        } catch (error) {
            // Someone else delivered the credit first: the vault holds nothing
            // more for this destination (ZeroAmount, or a reverted claim).
            if (['zero_amount'].includes(error?.code) || error?.transactionReceipt) {
                const latest = await this.ethereum.request({ method: 'eth_blockNumber' }).catch(() => null);
                const remaining = /^0x[0-9a-fA-F]+$/.test(String(latest || ''))
                    ? await this.readEscapePayoutCredit(destination, latest).catch(() => null) : null;
                if (remaining === 0n) {
                    return this.recordClearedEscapePayout(recordId, destination, latest, onStatus);
                }
            }
            if (error?.code === 'native_transfer_failed') {
                error.shortMessage = ESCAPE_PAYOUT_STILL_REJECTED_MESSAGE;
            } else if (error?.transactionReceipt) {
                error.shortMessage = 'The payout claim reverted, so the vault keeps the payout for its destination. If it reverts again, the address still does not accept ETH.';
            } else if (isWalletRejection(error)) {
                error.shortMessage = 'MetaMask canceled the payout claim. The vault still holds the payout for its destination.';
            }
            throw error;
        }
        const claim = parseEscapePayoutClaim(receipt, vault, destination);
        if (!claim) {
            throw new Error('The claim transaction succeeded, but it did not pay this destination.');
        }
        const settled = await this.recordEscapePayoutClaim(destination, receipt, claim);
        if (!settled.includes(recordId)) {
            // Only a record without a usable close block gets here. A zero
            // credit at the claim's block settles it instead.
            const claimBlock = /^0x[0-9a-fA-F]+$/.test(String(receipt.blockNumber || ''))
                ? receipt.blockNumber : await this.ethereum.request({ method: 'eth_blockNumber' });
            if (await this.readEscapePayoutCredit(destination, claimBlock) === 0n) {
                return this.recordClearedEscapePayout(recordId, destination, claimBlock, onStatus);
            }
            throw new Error('The claim was mined, but the vault still holds a payout for this address. Claim again.');
        }
        return this.escapePayoutClaimed(recordId, destination, receipt, claim, onStatus);
    }

    // The credited records of `destination` whose payout this browser has not
    // seen delivered, re-read from storage.
    async unclaimedEscapeCredits(destination) {
        return (await browserWalletRuntime.currentWithdrawals()).filter(entry => entry.payoutCredited === true
            && entry.payoutClaimed !== true
            && ['closed_unconfirmed', 'closed'].includes(entry.phase)
            && sameAddress(entry.destination, destination));
    }

    async rememberEscapePayoutClaim(recordId, hash) {
        if (!/^0x[0-9a-fA-F]{64}$/.test(hash || '')) {
            throw new Error('MetaMask returned an invalid payout claim transaction hash.');
        }
        const current = await this.creditedEscapePayoutRecord(recordId);
        const hashes = [...new Set([...(current.payoutClaimTransactionHashes || []), hash.toLowerCase()])];
        await browserWalletRuntime.updateWithdrawal(recordId, { payoutClaimTransactionHashes: hashes });
    }

    // A mined claim pays the destination every credit the vault holds when it
    // executes. It therefore delivered each credited record of the destination
    // whose close, and so its credit, is in an earlier block. closeBlockNumber
    // is never earlier than the close (a receipt's block, or the block where
    // the note was first seen Closed). A record credited in the claim's block
    // or later keeps its credit for a later claim. Returns the settled ids.
    async recordEscapePayoutClaim(destination, receipt, claim) {
        const claimBlock = Number(BigInt(receipt.blockNumber || '0x0'));
        const settled = (await this.unclaimedEscapeCredits(destination))
            .filter(entry => Number(entry.closeBlockNumber) > 0 && Number(entry.closeBlockNumber) < claimBlock)
            .map(entry => entry.recordId);
        await this.markEscapePayoutsClaimed(settled, {
            payoutClaimed: true,
            payoutVerified: true,
            payoutClaimEvidence: 'claim_receipt',
            payoutClaimTransactionHash: String(receipt.transactionHash || '').toLowerCase() || null,
            payoutClaimBlockNumber: claimBlock,
            payoutClaimedAmount: Number(claim.amount)
        });
        return settled;
    }

    escapePayoutClaimed(recordId, destination, receipt, claim, onStatus) {
        onStatus(`Escape payout delivered to ${this.compact(destination)}.`);
        return { status: 'claimed', recordId, destination,
            transactionHash: String(receipt.transactionHash || '').toLowerCase() || null,
            amount: claim.amount, receipt };
    }

    // The vault holds nothing for the destination at blockTag. Credits only
    // leave the vault through a claim that pays the destination, so each
    // credited record whose note reads Closed at that block was delivered.
    async recordClearedEscapePayout(recordId, destination, blockTag, onStatus) {
        const observedBlock = Number(BigInt(blockTag));
        const settled = [];
        for (const entry of await this.unclaimedEscapeCredits(destination)) {
            const status = await this.readBrowserWithdrawalStatus(entry.noteId, blockTag);
            if (status.status === 'closed') settled.push(entry.recordId);
        }
        if (!settled.includes(recordId)) {
            throw new Error('The vault does not show this escape as closed at the latest block yet. Check again shortly.');
        }
        await this.markEscapePayoutsClaimed(settled, {
            payoutClaimed: true,
            payoutVerified: true,
            payoutClaimEvidence: 'credit_cleared',
            payoutClaimBlockNumber: observedBlock
        });
        onStatus('The vault no longer holds this payout: it was already delivered to its destination.');
        return { status: 'claimed', recordId, transactionHash: null, observedBlock };
    }

    async markEscapePayoutsClaimed(recordIds, evidence) {
        for (const id of recordIds) {
            try {
                await browserWalletRuntime.updateWithdrawal(id, { ...evidence, payoutClaimTransactionHashes: [] }, {
                    expectedPhase: ['closed_unconfirmed', 'closed']
                });
            } catch (error) {
                if (!/not found|different phase/i.test(error?.message || '')) throw error;
            }
        }
        await this.refresh({ quiet: true });
    }

    /**
     * Simulates the vault's escape payout push to `destination`: a plain ETH
     * transfer from the vault, limited to the payout gas on a hardened vault.
     * `accepts` is false when the destination would not be paid at
     * finalization (a hardened vault then only credits it; an older vault
     * cannot finalize the escape) and null when the RPC cannot tell. The
     * simulated value is `finalBalance` vault units, 1 by default, so the
     * check does not disclose the balance to the RPC.
     */
    async checkEscapeDestination(destination, { finalBalance = 1 } = {}) {
        const vault = this.config?.funding?.contract_address;
        if (!vault) throw new Error('Initialize the wallet before checking an escape destination.');
        const normalized = normalizeWithdrawalDestination(destination, this.config.funding);
        if (!normalized) throw new TypeError('Choose a valid nonzero Ethereum withdrawal address.');
        const units = BigInt(finalBalance);
        if (units <= 0n) return { destination: normalized, accepts: true, warning: null };
        await this.assertFundingChain();
        try {
            await this.ethereum.request({
                method: 'eth_call',
                params: [{
                    from: vault,
                    to: normalized,
                    value: rpcQuantity(units * NATIVE_WEI_PER_UNIT),
                    gas: rpcQuantity(ESCAPE_DESTINATION_CHECK_GAS)
                }, 'latest']
            });
            return { destination: normalized, accepts: true, warning: null };
        } catch (error) {
            if (error?.code === 'wrong_network') throw error;
            if (!executionFailure(error)) return { destination: normalized, accepts: null, warning: null };
            return {
                destination: normalized,
                accepts: false,
                warning: ESCAPE_DESTINATION_CREDIT_WARNING
            };
        }
    }

    async confirmMinedWithdrawalStatus(noteId, receipt, { request = null } = {}) {
        try {
            return await this.readBrowserWithdrawalStatus(noteId, null, { request });
        } catch (failure) {
            // Call only after validating the successful receipt's withdrawal
            // event. An unavailable second RPC is not a failed payout. Keep
            // the submitted journal intact for normal background/reload sync.
            const error = normalizeWalletError(failure);
            error.withdrawalConfirmationPending = true;
            error.transactionHash = receipt?.transactionHash || null;
            error.shortMessage = error.code === 'wrong_network'
                ? `Your withdrawal transaction was mined. Switch MetaMask back to ${this.networkName()} so the app can confirm its status.`
                : 'Your withdrawal transaction was mined. Its status will be checked automatically; you can close this window.';
            throw error;
        }
    }

    /**
     * The vault's canonical status of a note. By default through the wallet
     * provider on the vault's chain; with `request` through that read RPC
     * instead (the sponsored path reads the exit RPC or the pinned RPC, which
     * are chain-checked themselves, so the wallet is never asked).
     */
    async readBrowserWithdrawalStatus(noteId, requestedBlock = null, { request = null } = {}) {
        if (noteId == null) return { status: 'no_note', challenge_deadline: null };
        const read = request || (payload => this.ethereum.request(payload));
        if (!request) await this.assertFundingChain();
        const blockTag = requestedBlock || await read({ method: 'eth_blockNumber' });
        if (!/^0x[0-9a-fA-F]+$/.test(String(blockTag || ''))) {
            throw new Error('The wallet provider returned an invalid block number.');
        }
        const observedBlock = Number(BigInt(blockTag));
        const encodedNote = await read({
            method: 'eth_call',
            params: [{
                to: this.config.funding.contract_address,
                data: `0x9f18e4ed${abiWord(noteId)}`
            }, blockTag]
        });
        const words = String(encodedNote || '').replace(/^0x/, '').match(/.{64}/g) || [];
        if (words.length < 4) throw new Error('The vault returned a truncated note record.');
        const status = Number(BigInt(`0x${words[3]}`));
        if (status === 3) return { status: 'closed', note_id: Number(noteId), challenge_deadline: null, observed_block: observedBlock };
        if (status === 1) return { status: 'active', note_id: Number(noteId), challenge_deadline: null, observed_block: observedBlock };
        if (status !== 2) throw new Error(`The vault returned unknown note status ${status}.`);
        if (!request) await this.assertFundingChain();
        const encodedPending = await read({
            method: 'eth_call',
            params: [{
                to: this.config.funding.contract_address,
                data: `0xa2f9f1ce${abiWord(noteId)}`
            }, blockTag]
        });
        const pendingWords = String(encodedPending || '').replace(/^0x/, '').match(/.{64}/g) || [];
        if (pendingWords.length < 6 || BigInt(`0x${pendingWords[0]}`) !== 1n) {
            throw new Error('The vault pending-withdrawal record is missing.');
        }
        // Vault revision 3: the escape's concession at the same block
        // (pendingWithdrawals.finalBalance + conceded == stateBalance).
        let concession = null;
        try {
            const encodedConcession = await read({
                method: 'eth_call',
                params: [{ to: this.config.funding.contract_address, data: `0x${ABI.pendingConcessions}${abiWord(noteId)}` }, blockTag]
            });
            concession = decodePendingConcessions(encodedConcession);
            if (concession.stateBalance !== BigInt(`0x${pendingWords[3]}`) + concession.conceded) concession = null;
        } catch {
            concession = null;
        }
        return {
            status: 'pending_withdrawal',
            note_id: Number(noteId),
            active_root: `0x${pendingWords[1]}`,
            withdrawal_nullifier: `0x${pendingWords[2]}`,
            final_balance: Number(BigInt(`0x${pendingWords[3]}`)),
            destination: `0x${pendingWords[4].slice(-40)}`,
            challenge_deadline: Number(BigInt(`0x${pendingWords[5]}`)),
            ...(concession ? {
                next_nullifier: `0x${concession.nextNullifier.toString(16)}`,
                state_balance: Number(concession.stateBalance),
                conceded: Number(concession.conceded)
            } : {}),
            observed_block: observedBlock
        };
    }

    async confirmBrowserWithdrawal(noteId = this.note?.note_id) {
        const result = await this.readBrowserWithdrawalStatus(noteId);
        if (result.status === 'closed' && Number(this.note?.note_id) === Number(noteId)) {
            await browserWalletRuntime.archiveNote('withdrawn', noteId);
        }
        return result;
    }

    escapePeriodLabel() {
        return escapePeriodLabel(this.challengePeriodSeconds);
    }

    escapePeriodPhrase() {
        return escapePeriodPhrase(this.challengePeriodSeconds);
    }

    get testnetAuthenticated() { return browserWalletRuntime.testnetAuth?.authenticated === true; }

    async ensureTestnetAccess(options = {}) {
        await browserWalletRuntime.testnetAuth?.ensure(options);
    }

    escapePeriodBadge() {
        return escapePeriodBadge(this.challengePeriodSeconds);
    }

}

// Keep provider selection stable through every asynchronous client boundary,
// including intervals between nested reads and transaction journal commits.
// Applying the scope uniformly also covers newly added recovery entry points.
for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(ZkapiClient.prototype))) {
    const operation = descriptor.value;
    if (typeof operation !== 'function' || operation.constructor.name !== 'AsyncFunction') continue;
    Object.defineProperty(ZkapiClient.prototype, name, {
        ...descriptor,
        value: async function (...args) {
            const state = walletProviders.get(this);
            if (!state.operations) state.active = state.override || globalThis.ethereum;
            state.operations += 1;
            try {
                return await operation.apply(this, args);
            } finally {
                state.operations -= 1;
                if (!state.operations) state.active = null;
            }
        }
    });
}

const zkapiClient = new ZkapiClient();
globalThis.zkapiClient = zkapiClient;

export { ZkapiClient };
export default zkapiClient;
