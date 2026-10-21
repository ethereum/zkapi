// Gasless withdrawals over ERC-4337 (EntryPoint v0.7.0): the shared client
// logic of design §3.1, byte-checked against
// protocol/contracts/test/fixtures/transit-vectors.json. A withdrawal proof
// names a transit account S = CREATE2(factory, 0, creationCode ‖
// abi.encode(entryPoint, vault, paymaster, owner, payee)) as its destination;
// the user operation calls S.withdraw(vaultCall) from S, the paymaster P
// sponsors it after re-running every vault check, and P's postOp keeps a
// measured charge and pushes the rest to the payee. Nothing here signs or
// sends: the client (zkapiClient.js) owns the wallet prompt, the journal and
// the bundler conversation; this module owns every byte and every number.
//
// Every quantity is a bigint. Profile numbers may be decimal strings, safe
// integers or bigints; bundler JSON carries 0x hex quantities.

import { GASLESS_ABI, PACKED_USER_OPERATION_TUPLE, abiWord, callData } from '../wallet.js';
import { codehash, hexBytes, keccak256 } from './zkapiKeccak.mjs';
import { ENTRY_POINT_ERRORS, decodeContractRevert, decodeEntryPointRevert, entryPointError } from './zkapiContractError.mjs';

export { PACKED_USER_OPERATION_TUPLE, ENTRY_POINT_ERRORS };

/** Sponsored operation kinds, as the paymaster numbers them. */
export const KIND = Object.freeze({ close: 1, escape: 2, finalize: 3, forward: 4 });
export const KIND_NAMES = Object.freeze(['close', 'escape', 'finalize', 'forward']);
/** The canonical EntryPoint v0.7.0 and the SenderCreator it deployed (identical on every chain). */
export const CANONICAL_ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
export const CANONICAL_SENDER_CREATOR = '0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C';
export const ENTRY_POINT_V070_CODEHASH = '0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58';
export const SENDER_CREATOR_V070_CODEHASH = '0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689';
/** uint192(uint256(keccak256("zkapi.gasless.forward"))): the nonce key of a FORWARD operation. */
export const FORWARD_NONCE_KEY = BigInt(keccak256('zkapi.gasless.forward')) & ((1n << 192n) - 1n);
/** Sponsorships per key before the owner must release it (the paymaster's MAX_ATTEMPTS). */
export const MAX_ATTEMPTS = 3n;
/** A payout whose sponsored cost exceeds this fraction is refused unless the host allows it (§3.1). */
export const UNECONOMIC_FRACTION_PERCENT = 25n;
/** A dropped operation is re-signed with both fee fields raised by this (ERC-4337 asks ≥ 10%). */
export const FEE_BUMP_NUMERATOR = 1125n;
export const FEE_BUMP_DENOMINATOR = 1000n;
/** Timing of the submission loop (§3.1); the client may override per instance. */
export const GASLESS_TIMING = Object.freeze({
    receiptPollMs: 2_000,
    logPollMs: 12_000,
    resendAfterMs: 5 * 60_000,
    stopBeforeValidUntilSeconds: 60,
    // 0: follow an operation until its proof expires (a finalization or
    // forward has no expiry and is followed until included).
    giveUpAfterMs: 0,
    // How long a finalization waits, before its prompt, for the chain's
    // latest block to reach the escape deadline the local clock already
    // passed (block time and RPC lag); `escape_not_due` beyond it.
    notDueWaitMs: 3 * 60_000
});
// The preVerificationGas rule both clients apply (zkapi-clientd's
// requiredPreVerificationGas computes the same numbers):
// PVG = clamp(max(A, ceil(1.1 × B), C), pvg_floor, pvg_cap).
/** C: the chain's intrinsic transaction gas, 16 per byte of handleOps calldata and an overhead. */
const PVG_BASE_GAS = 21_000n;
const PVG_CALLDATA_GAS = 16n;
const PVG_OVERHEAD_GAS = 10_000n;
// A: ERC-7562 LIM-070 (a bundler enforcing it refuses an op whose
// preVerificationGas is below the calldata cost of the op plus
// PRE_VERIFICATION_OVERHEAD_GAS), plus a margin for what bundlers add beyond
// it and for the zero bytes of a proof generated again.
const PVG_LIM070_OVERHEAD_GAS = 50_000n;
const PVG_LIM070_MARGIN_GAS = 2_000n;
const UINT128_MAX = (1n << 128n) - 1n;
// B: the per-operation minimum a standard bundler enforces (eth-infinitism
// bundler calcPreVerificationGas, DefaultGasOverheads of v0.7: fixed 21,000,
// perUserOp 18,300, perUserOpWord 4, zeroByte 4, nonZeroByte 16, over the
// abi-encoded packed op with a 65-byte signature), plus the client's margin.
const PVG_REFERENCE_FIXED_GAS = 21_000n;
const PVG_REFERENCE_PER_OP_GAS = 18_300n;
const PVG_REFERENCE_PER_WORD_GAS = 4n;
const PVG_REFERENCE_ZERO_BYTE_GAS = 4n;
const PVG_REFERENCE_NONZERO_BYTE_GAS = 16n;
const PVG_REFERENCE_MARGIN_PERCENT = 10n;
const SIGNATURE_BYTES = 65;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const WORD = /^0x[0-9a-fA-F]{64}$/;
const HEX = /^0x([0-9a-fA-F]{2})*$/;

/** The messages of every refusal of the gasless path, by code. */
export const GASLESS_MESSAGES = Object.freeze({
    gasless_unavailable: 'Paying the network fee from the payout is not available on this deployment. Pay it from a wallet instead.',
    gasless_profile_invalid: 'This app’s deployment profile pins an unusable gasless configuration, so the fee can only be paid from a wallet.',
    gasless_deployment_mismatch: 'The gasless contracts on this chain do not match the deployment this app pins, so the fee can only be paid from a wallet.',
    gasless_policy_mismatch: 'The paymaster’s gas policy does not match the deployment this app pins, so the fee can only be paid from a wallet.',
    bundler_unavailable: 'The bundler could not be reached. Try again, set your own bundler URL, or pay the fee from a wallet (a funded wallet can also submit this operation itself).',
    bundler_wrong_chain: 'The bundler is on another chain than the vault. Correct its URL, or pay the fee from a wallet.',
    bundler_unsupported_entry_point: 'The bundler does not serve the EntryPoint this deployment uses. Use another bundler, or pay the fee from a wallet.',
    bundler_hash_mismatch: 'The bundler returned a different operation hash than the one signed. The operation is tracked on chain under the signed hash.',
    bundler_url_invalid: 'The bundler must be an HTTPS (or loopback) URL without credentials.',
    bundler_url_unsaved: 'This browser cannot save the bundler setting.',
    bundler_rejected: 'The bundler refused the operation.',
    sponsorship_paused: 'The operator paused sponsored withdrawals. Pay the network fee from a wallet instead.',
    escapes_disabled: 'The operator does not sponsor escape initiations. Start the escape from a wallet. Its finalization can be sponsored only when the escape pays this withdrawal’s transit account (it continues a sponsored withdrawal already proved for it); otherwise finalize it from the wallet as well.',
    paymaster_underfunded: 'The paymaster’s float cannot cover this operation right now. Try again later, or pay the fee from a wallet.',
    exits_paused: 'The vault is paused by its owner. Sponsored closes and escapes reopen at the latest when its pause limit ends.',
    gas_above_paymaster_ceiling: 'Network fees are above what the paymaster sponsors right now. Try again later, or pay the fee from a wallet.',
    payout_below_gas: 'This payout does not cover the sponsored network fee. Pay the fee from a wallet instead.',
    gasless_uneconomic: 'The sponsored network fee would take more than a quarter of this payout. Pay the fee from a wallet, or allow the expensive fee explicitly.',
    gasless_attempts_exhausted: 'This balance state used its sponsored attempts. Pay the network fee from a wallet.',
    gasless_fee_above_cap: 'The paymaster’s flat fee is above the fee cap you accepted. Accept the current fee or pay the fee from a wallet.',
    gasless_estimate_above_cap: 'The bundler estimates more gas than the paymaster’s policy allows, which this app does not sign. Use another bundler, or pay the fee from a wallet.',
    wrong_owner_account: 'Connect the account that owns this withdrawal’s transit account to sign its operation.',
    entry_point_hash_mismatch: 'The EntryPoint computes a different operation hash than this app. Nothing was signed; update this app.',
    signature_rejected: 'The EntryPoint rejected the signature: the connected account is not the owner of this withdrawal’s transit account.',
    gasless_plan_mismatch: 'This withdrawal was prepared to pay the fee from a wallet. Finish it that way, or cancel it first.',
    gasless_record_not_pinned: 'This app no longer sponsors the paymaster this withdrawal used. Recover it from a funded wallet: if the note has not left the vault yet, withdraw again with the fee paid from the wallet; otherwise sweep a payout waiting in its transit account, claim a credited payout, or finalize a pending escape with the fee paid from the wallet.',
    gasless_op_expired: 'The withdrawal proof is about to expire before the operation was included. It is prepared again.',
    escape_not_due: 'The chain has not reached the end of this escape’s safety window yet. Finalize it once the latest block is past the deadline.',
    gasless_op_reverted: 'The sponsored operation was included but its vault call reverted. The withdrawal can be retried.',
    transit_funds_waiting: 'The payout sits in this withdrawal’s transit account. Collect it with a sponsored forward, or sweep it from a funded wallet.',
    transit_sweep_needed: 'The payout sits in this withdrawal’s transit account. Sweep it to the payout address from a funded wallet (sweepTransit); the paymaster has no record of it to sponsor a forward.',
    transit_not_stranded: 'The paymaster has no record of a payout waiting in this transit account. Sweep it from a funded wallet instead.',
    transit_balance_empty: 'The transit account holds nothing to collect.',
    user_op_pending: 'An earlier sponsored operation of this withdrawal may still be in a mempool. Wait until it is included or its proof expires.',
    gasless_fee_bump_exhausted: 'The operation is still not included at the paymaster’s fee ceiling. Wait, or pay the fee from a wallet.',
    gasless_op_pending: 'The sponsored operation is not included yet. It stays journaled and is checked in the background.',
    max_cost_above_policy: 'The sponsored operation would cost more than the paymaster’s policy allows at the current fees. Try again at a lower fee, or pay the fee from a wallet.',
    escape_already_sponsored: 'An escape of this balance was already sponsored once, or this transit account still has an open sponsored escape.',
    payout_credited: 'The payout address did not accept the payment. The paymaster holds it; anyone can deliver it with claimGaslessCredit once the address accepts ETH.'
});

/** An error of the gasless path: `code`, a display `shortMessage`, optional `data`. */
export function gaslessError(code, data = null, message = null) {
    const text = message || GASLESS_MESSAGES[code] || code;
    const error = new Error(text);
    error.name = 'ZkapiGaslessError';
    error.code = code;
    error.shortMessage = text;
    if (data) error.data = data;
    return error;
}

// ---------------------------------------------------------------- numbers and words

/** A non-negative bigint from a bigint, a safe integer or a decimal/0x string. */
export function toBigInt(value, label = 'value') {
    if (typeof value === 'bigint') {
        if (value < 0n) throw new TypeError(`${label} is negative.`);
        return value;
    }
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
    if (typeof value === 'string' && /^(0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value.trim())) return BigInt(value.trim());
    throw new TypeError(`${label} is not an unsigned integer.`);
}

const quantity = value => `0x${toBigInt(value).toString(16)}`;
const lower = value => String(value ?? '').toLowerCase();
const strip = value => String(value ?? '').replace(/^0x/i, '');
const word = value => toBigInt(value).toString(16).padStart(64, '0');
const words = hex => (strip(hex).match(/.{64}/g) || []).map(entry => BigInt(`0x${entry}`));
const addressOf = value => `0x${value.toString(16).padStart(40, '0')}`;
const topicAddress = topic => (WORD.test(topic || '') ? `0x${topic.slice(-40)}`.toLowerCase() : null);

function assertAddress(value, label) {
    if (!ADDRESS.test(value || '')) throw gaslessError('gasless_profile_invalid', { field: label }, `${label} is not an address.`);
    return value;
}

function assertHex(value, label) {
    if (!HEX.test(value || '')) throw gaslessError('gasless_profile_invalid', { field: label }, `${label} is not hex bytes.`);
    return value.toLowerCase();
}

/** abi.encode(string, uint256) or abi.encode(string, address): the paymaster's attempt keys. */
function encodeStringAndWord(text, value) {
    const bytes = new TextEncoder().encode(text);
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `${word(0x40)}${word(value)}${word(bytes.length)}${hex.padEnd(Math.ceil(bytes.length / 32) * 64, '0')}`;
}

// ---------------------------------------------------------------- profile pins

const GAS_POLICY_FIELDS = Object.freeze([
    // [camelCase, [accepted profile keys]]
    ['postOpFloor', ['post_op_floor', 'postop_floor']],
    ['postOpCap', ['post_op_cap', 'postop_cap']],
    ['verificationFloor', ['verification_floor']],
    ['verificationFloorInit', ['verification_floor_init']],
    ['verificationCap', ['verification_cap']],
    ['pvgFloor', ['pvg_floor']],
    ['pvgCap', ['pvg_cap']],
    ['pmVerificationFloor', ['pm_verification_floor']],
    ['pmVerificationCap', ['pm_verification_cap']],
    ['postOpBaseGas', ['post_op_base_gas', 'postop_base_gas']],
    ['postOpEscapeGas', ['post_op_escape_gas', 'postop_escape_gas']],
    ['postOpFinalizeExtraGas', ['post_op_finalize_extra_gas', 'postop_finalize_extra_gas']],
    ['postOpEscapeForwardGas', ['post_op_escape_forward_gas', 'postop_escape_forward_gas']],
    ['eoaPushGas', ['eoa_push_gas']],
    ['newAccountGas', ['new_account_gas']],
    ['payoutPushGas', ['payout_push_gas']],
    ['creditGas', ['credit_gas']],
    ['accountCallOverheadGas', ['account_call_overhead_gas']],
    ['accountCallOverheadEscapeGas', ['account_call_overhead_escape_gas']],
    ['marginGas', ['margin_gas']],
    ['finalizeReserveGas', ['finalize_reserve_gas']],
    ['maxAttempts', ['max_attempts']]
]);
/** The gasPolicy() tuple of the paymaster, in return order (two uint256[4] then 22 scalars). */
export const GAS_POLICY_SCALARS = Object.freeze(GAS_POLICY_FIELDS.map(([name]) => name));

function pick(source, keys) {
    for (const key of keys) if (source?.[key] != null) return source[key];
    return undefined;
}

/**
 * The profile's gas_policy as bigints, with the optional client defaults
 * (`call_default[4]`, `post_op_default`, `verification_default`,
 * `verification_default_init`, `pm_verification_default`). The committed
 * paymaster's floors and caps are the names of transit-vectors.json (the
 * snake_case of its GasPolicy struct); the design's `postop_*`/`call_cap`
 * spellings are accepted too.
 */
export function normalizeGasPolicy(raw) {
    if (!raw || typeof raw !== 'object') throw gaslessError('gasless_profile_invalid', { field: 'gas_policy' }, 'The profile has no gasless gas_policy.');
    const array = (keys, label) => {
        const value = pick(raw, keys);
        if (!Array.isArray(value) || value.length !== 4) {
            throw gaslessError('gasless_profile_invalid', { field: label }, `The profile's gas_policy.${label} is not four values.`);
        }
        return value.map((entry, index) => toBigInt(entry, `${label}[${index}]`));
    };
    const policy = { callFloor: array(['call_floor'], 'call_floor'), callHardCap: array(['call_hard_cap', 'call_cap'], 'call_hard_cap') };
    for (const [name, keys] of GAS_POLICY_FIELDS) {
        const value = pick(raw, keys);
        if (value == null) throw gaslessError('gasless_profile_invalid', { field: keys[0] }, `The profile's gas_policy lacks ${keys[0]}.`);
        policy[name] = toBigInt(value, keys[0]);
    }
    const defaults = {};
    const callDefault = pick(raw, ['call_default']);
    if (callDefault != null) {
        if (!Array.isArray(callDefault) || callDefault.length !== 4) {
            throw gaslessError('gasless_profile_invalid', { field: 'call_default' }, 'The profile’s gas_policy.call_default is not four values.');
        }
        defaults.callDefault = callDefault.map((entry, index) => toBigInt(entry, `call_default[${index}]`));
    }
    for (const [name, keys] of [['postOpDefault', ['post_op_default', 'postop_default']], ['verificationDefault', ['verification_default']],
        ['verificationDefaultInit', ['verification_default_init']], ['pmVerificationDefault', ['pm_verification_default']]]) {
        const value = pick(raw, keys);
        if (value != null) defaults[name] = toBigInt(value, keys[0]);
    }
    for (let kind = 0; kind < 4; kind += 1) {
        if (policy.callFloor[kind] > policy.callHardCap[kind]) {
            throw gaslessError('gasless_profile_invalid', { field: 'call_floor' }, 'A gas floor is above its cap in the profile.');
        }
    }
    for (const [floor, cap] of [['postOpFloor', 'postOpCap'], ['verificationFloor', 'verificationCap'], ['verificationFloorInit', 'verificationCap'],
        ['pvgFloor', 'pvgCap'], ['pmVerificationFloor', 'pmVerificationCap']]) {
        if (policy[floor] > policy[cap]) throw gaslessError('gasless_profile_invalid', { field: floor }, 'A gas floor is above its cap in the profile.');
    }
    policy.defaults = defaults;
    return policy;
}

/** Whether two normalized gas policies pin the same contract constants (defaults excluded). */
export function sameGasPolicy(left, right) {
    if (!left || !right) return false;
    for (let kind = 0; kind < 4; kind += 1) {
        if (left.callFloor[kind] !== right.callFloor[kind] || left.callHardCap[kind] !== right.callHardCap[kind]) return false;
    }
    return GAS_POLICY_SCALARS.every(name => left[name] === right[name]);
}

/**
 * The pinned `gasless` object of a trusted deployment profile (design §4.3),
 * validated and normalized, or null when the profile carries none (absent,
 * null, or a placeholder deployment): the gasless option is then hidden and
 * the wallet-paid path is unchanged. A malformed object throws
 * `gasless_profile_invalid`, which the client reports as unavailable.
 */
export function gaslessPins(trusted) {
    const gasless = trusted?.gasless;
    if (gasless == null || typeof gasless !== 'object') return null;
    if (trusted?.deployment_status === 'not_deployed'
        || (gasless.deployment_status != null && gasless.deployment_status !== 'deployed')) return null;
    const pins = {
        entryPoint: assertAddress(gasless.entry_point_address, 'entry_point_address'),
        entryPointCodehash: lower(gasless.entry_point_runtime_codehash),
        senderCreator: assertAddress(gasless.sender_creator_address, 'sender_creator_address'),
        senderCreatorCodehash: lower(gasless.sender_creator_runtime_codehash),
        paymaster: assertAddress(gasless.withdrawal_paymaster_address, 'withdrawal_paymaster_address'),
        paymasterCodehash: lower(gasless.withdrawal_paymaster_runtime_codehash),
        factory: assertAddress(gasless.withdrawal_account_factory_address, 'withdrawal_account_factory_address'),
        factoryCodehash: lower(gasless.withdrawal_account_factory_runtime_codehash),
        // Optional: the one account logic every transit proxy delegates to.
        implementation: gasless.withdrawal_account_implementation_address == null ? null
            : assertAddress(gasless.withdrawal_account_implementation_address, 'withdrawal_account_implementation_address'),
        implementationCodehash: gasless.withdrawal_account_implementation_runtime_codehash == null ? null
            : lower(gasless.withdrawal_account_implementation_runtime_codehash),
        accountCreationCode: assertHex(gasless.account_creation_code, 'account_creation_code'),
        accountCreationCodeKeccak256: lower(gasless.account_creation_code_keccak256),
        bundlerUrl: gasless.bundler_url == null ? null : String(gasless.bundler_url),
        gasPolicy: normalizeGasPolicy(gasless.gas_policy),
        policy: {
            maxSponsoredCostWei: toBigInt(gasless.policy?.max_sponsored_cost_wei ?? 0, 'policy.max_sponsored_cost_wei'),
            flatFeeWei: toBigInt(gasless.policy?.flat_fee_wei ?? 0, 'policy.flat_fee_wei'),
            minEscapeNetWei: toBigInt(gasless.policy?.min_escape_net_wei ?? 0, 'policy.min_escape_net_wei'),
            escapesEnabled: gasless.policy?.escapes_enabled === true
        },
        feeCeilings: {
            maxFeeWei: toBigInt(gasless.fee_ceilings?.max_fee_wei ?? 0, 'fee_ceilings.max_fee_wei'),
            priorityFeeWei: toBigInt(gasless.fee_ceilings?.priority_fee_wei ?? 0, 'fee_ceilings.priority_fee_wei')
        },
        uneconomicFractionPercent: gasless.uneconomic_fraction_percent == null
            ? UNECONOMIC_FRACTION_PERCENT : toBigInt(gasless.uneconomic_fraction_percent, 'uneconomic_fraction_percent')
    };
    for (const field of ['entryPointCodehash', 'senderCreatorCodehash', 'paymasterCodehash', 'factoryCodehash', 'accountCreationCodeKeccak256']) {
        if (!WORD.test(pins[field])) throw gaslessError('gasless_profile_invalid', { field }, `The profile's gasless ${field} is not a 32-byte hash.`);
    }
    if (codehash(pins.accountCreationCode) !== pins.accountCreationCodeKeccak256) {
        throw gaslessError('gasless_profile_invalid', { field: 'account_creation_code_keccak256' },
            'The profile’s account creation code does not hash to its pinned keccak256.');
    }
    if (pins.uneconomicFractionPercent > 100n) {
        throw gaslessError('gasless_profile_invalid', { field: 'uneconomic_fraction_percent' }, 'uneconomic_fraction_percent is above 100.');
    }
    return pins;
}

// ---------------------------------------------------------------- transit account

/**
 * S = CREATE2(factory, salt 0, keccak(creationCode ‖ abi.encode(entryPoint,
 * vault, paymaster, owner, payee))), computed locally from the pinned
 * creation code. The client cross-checks it with factory.getAddress.
 */
export function transitAccountAddress({ factory, creationCodeHex, entryPoint, vault, paymaster, owner, payee }) {
    for (const [label, value] of [['factory', factory], ['entryPoint', entryPoint], ['vault', vault], ['paymaster', paymaster],
        ['owner', owner], ['payee', payee]]) {
        if (!ADDRESS.test(value || '')) throw new TypeError(`The transit account's ${label} is not an address.`);
    }
    if (!HEX.test(creationCodeHex || '') || strip(creationCodeHex).length < 2) throw new TypeError('The account creation code is not hex bytes.');
    const initCode = `${strip(creationCodeHex)}${[entryPoint, vault, paymaster, owner, payee].map(word).join('')}`;
    const initCodeHash = keccak256(hexBytes(initCode));
    const digest = keccak256(hexBytes(`ff${strip(factory)}${'0'.repeat(64)}${strip(initCodeHash)}`));
    return `0x${digest.slice(-40)}`;
}

/** The op's initCode on first use: factory ‖ createAccount(owner, payee). */
export function transitInitCode({ factory, owner, payee }) {
    for (const [label, value] of [['factory', factory], ['owner', owner], ['payee', payee]]) {
        if (!ADDRESS.test(value || '')) throw new TypeError(`The transit account's ${label} is not an address.`);
    }
    return `0x${strip(factory).toLowerCase()}${GASLESS_ABI.createAccount}${word(owner)}${word(payee)}`;
}

/** The paymaster's attempt key of a sponsorship: keccak256(abi.encode("close", n)) etc. */
export function attemptsKey(kind, { nullifier = null, noteId = null, sender = null } = {}) {
    if (kind === KIND.close) return keccak256(hexBytes(encodeStringAndWord('close', toBigInt(nullifier, 'nullifier'))));
    if (kind === KIND.escape) return keccak256(hexBytes(encodeStringAndWord('escape', toBigInt(noteId, 'noteId'))));
    if (kind === KIND.finalize) return keccak256(hexBytes(encodeStringAndWord('finalize', toBigInt(noteId, 'noteId'))));
    if (kind === KIND.forward) {
        if (!ADDRESS.test(sender || '')) throw new TypeError('A forward key needs the transit account.');
        return keccak256(hexBytes(encodeStringAndWord('forward', BigInt(sender))));
    }
    throw new TypeError('Unknown sponsored operation kind.');
}

/** The nonce key (uint192) a kind's operation must use. */
export function nonceKeyFor(kind, { nullifier = null } = {}) {
    if (kind === KIND.forward) return FORWARD_NONCE_KEY;
    const value = toBigInt(nullifier, 'nullifier');
    return value & ((1n << 192n) - 1n);
}

export function packNonce(key, sequence) {
    return (toBigInt(key, 'nonce key') << 64n) | (toBigInt(sequence, 'nonce sequence') & ((1n << 64n) - 1n));
}

export function unpackNonce(nonce) {
    const value = toBigInt(nonce, 'nonce');
    return { key: value >> 64n, sequence: value & ((1n << 64n) - 1n) };
}

// ---------------------------------------------------------------- gas, fees, amounts

function clamp(value, floor, cap) {
    return value < floor ? floor : value > cap ? cap : value;
}

/** The EVM's calldata gas of hex bytes: 4 per zero byte, 16 per other. */
function calldataCost(hex) {
    const data = strip(hex);
    let gas = 0n;
    for (let index = 0; index < data.length; index += 2) {
        gas += data.slice(index, index + 2) === '00' ? PVG_REFERENCE_ZERO_BYTE_GAS : PVG_REFERENCE_NONZERO_BYTE_GAS;
    }
    return gas;
}

/**
 * The reference bundler's minimum preVerificationGas for `op` (eth-infinitism
 * calcPreVerificationGas, v0.7): 21,000 + 18,300 + 4 per word + 4 / 16 per
 * zero / non-zero byte of abi.encode(sender, nonce, initCode, callData,
 * accountGasLimits, preVerificationGas, gasFees, paymasterAndData, signature),
 * an unsigned op counted with a 65-byte non-zero signature (0x01 bytes) as the
 * bundler does. Term B of the rule (preVerificationGasFor), taken with the
 * op's preVerificationGas at pvg_cap.
 */
export function referencePreVerificationGas(op) {
    const signature = op.signature && strip(op.signature).length === SIGNATURE_BYTES * 2 ? op.signature : `0x${'01'.repeat(SIGNATURE_BYTES)}`;
    const encoded = encodePackedUserOperation({ ...op, signature });
    const words = BigInt(Math.ceil(encoded.length / 64));
    return PVG_REFERENCE_FIXED_GAS + PVG_REFERENCE_PER_OP_GAS + PVG_REFERENCE_PER_WORD_GAS * words + calldataCost(encoded);
}

/**
 * Term A of the rule (preVerificationGasFor): ERC-7562 LIM-070's minimum for
 * `op` at its worst plus a margin, the calldata cost of handleOps([probe],
 * 0xff…ff) + 50,000 + 2,000, where the probe is `op` with a 65-byte 0xff
 * signature, both fee fields 2^128 − 1 (so a re-sign with higher fees never
 * needs more) and preVerificationGas at pvg_cap; its nonce and feeCapWei as
 * given, 0 when absent.
 */
export function lim070PreVerificationGas(gasPolicy, op) {
    const probe = {
        ...op,
        nonce: op.nonce ?? 0n,
        feeCapWei: op.feeCapWei ?? 0n,
        signature: `0x${'ff'.repeat(SIGNATURE_BYTES)}`,
        maxFeePerGas: UINT128_MAX,
        maxPriorityFeePerGas: UINT128_MAX,
        preVerificationGas: gasPolicy.pvgCap
    };
    return calldataCost(encodeHandleOps([probe], `0x${'ff'.repeat(20)}`)) + PVG_LIM070_OVERHEAD_GAS + PVG_LIM070_MARGIN_GAS;
}

/**
 * The preVerificationGas the client signs, the rule both clients share
 * (zkapi-clientd's requiredPreVerificationGas computes the same numbers):
 *
 *     PVG = clamp(max(A, ceil(1.1 × B), C), pvg_floor, pvg_cap)
 *
 * with C = 21,000 + 16 × calldataBytes + 10,000 (`calldataBytes` the byte
 * length of handleOps([op], beneficiary) with a 65-byte signature,
 * handleOpsCalldataBytes), A = lim070PreVerificationGas(op) and B =
 * referencePreVerificationGas(op with its preVerificationGas at pvg_cap),
 * computed on the op being built (its nonce, initCode, callData, limits,
 * fees and fee cap). Without an op only C applies (a sizing draft). A
 * bundler estimate asking for more within pvg_cap is adopted by the caller
 * (crossCheckGaslessEstimate) before anything is shown or signed.
 */
export function preVerificationGasFor(gasPolicy, calldataBytes, op = null) {
    let raw = PVG_BASE_GAS + PVG_CALLDATA_GAS * toBigInt(calldataBytes, 'calldata size') + PVG_OVERHEAD_GAS;
    if (op) {
        const lim070 = lim070PreVerificationGas(gasPolicy, op);
        if (lim070 > raw) raw = lim070;
        const reference = referencePreVerificationGas({ ...op, preVerificationGas: gasPolicy.pvgCap });
        const reserved = reference + (reference * PVG_REFERENCE_MARGIN_PERCENT + 99n) / 100n;
        if (reserved > raw) raw = reserved;
    }
    return clamp(raw, gasPolicy.pvgFloor, gasPolicy.pvgCap);
}

/**
 * The five gas fields of an operation of `kind`, from the pinned policy and
 * its defaults (never from a raw estimate): a profile default when pinned,
 * else a quarter of the way from the floor to the cap (the figures the
 * contract tests sponsor), the live callCap bounding callGasLimit. Each is
 * checked against its floor and cap (`gas_limit_out_of_range`).
 */
export function gasFields({ gasPolicy, kind, withInitCode = false, calldataBytes = 0, callCap = null, overrides = {}, op = null }) {
    const index = kind - 1;
    if (!(index >= 0 && index < 4)) throw new TypeError('Unknown sponsored operation kind.');
    const quarter = (floor, cap) => floor + (cap - floor) / 4n;
    const defaults = gasPolicy.defaults || {};
    const hardCap = gasPolicy.callHardCap[index];
    const liveCap = callCap == null ? hardCap : clamp(toBigInt(callCap, 'callCap'), gasPolicy.callFloor[index], hardCap);
    const verificationFloor = withInitCode ? gasPolicy.verificationFloorInit : gasPolicy.verificationFloor;
    const fields = {
        callGasLimit: overrides.callGasLimit != null ? toBigInt(overrides.callGasLimit, 'callGasLimit')
            : clamp(defaults.callDefault?.[index] ?? quarter(gasPolicy.callFloor[index], hardCap), gasPolicy.callFloor[index], liveCap),
        verificationGasLimit: overrides.verificationGasLimit != null ? toBigInt(overrides.verificationGasLimit, 'verificationGasLimit')
            : clamp((withInitCode ? defaults.verificationDefaultInit : defaults.verificationDefault)
                ?? (withInitCode ? 300_000n : 80_000n), verificationFloor, gasPolicy.verificationCap),
        preVerificationGas: overrides.preVerificationGas != null ? toBigInt(overrides.preVerificationGas, 'preVerificationGas')
            : preVerificationGasFor(gasPolicy, calldataBytes, op),
        paymasterVerificationGasLimit: overrides.paymasterVerificationGasLimit != null
            ? toBigInt(overrides.paymasterVerificationGasLimit, 'paymasterVerificationGasLimit')
            : clamp(defaults.pmVerificationDefault ?? gasPolicy.pmVerificationFloor + 30_000n, gasPolicy.pmVerificationFloor, gasPolicy.pmVerificationCap),
        paymasterPostOpGasLimit: overrides.paymasterPostOpGasLimit != null ? toBigInt(overrides.paymasterPostOpGasLimit, 'paymasterPostOpGasLimit')
            : clamp(defaults.postOpDefault ?? quarter(gasPolicy.postOpFloor, gasPolicy.postOpCap), gasPolicy.postOpFloor, gasPolicy.postOpCap)
    };
    const ranges = [
        ['preVerificationGas', 0, gasPolicy.pvgFloor, gasPolicy.pvgCap],
        ['verificationGasLimit', 1, verificationFloor, gasPolicy.verificationCap],
        ['callGasLimit', 2, gasPolicy.callFloor[index], liveCap],
        ['paymasterVerificationGasLimit', 3, gasPolicy.pmVerificationFloor, gasPolicy.pmVerificationCap],
        ['paymasterPostOpGasLimit', 4, gasPolicy.postOpFloor, gasPolicy.postOpCap]
    ];
    for (const [name, field, floor, cap] of ranges) {
        const value = fields[name];
        if (value < floor || value > cap) {
            throw gaslessError('gas_limit_out_of_range', { field, name, value, floor, cap },
                `The ${name} ${value} is outside the paymaster's policy [${floor}, ${cap}].`);
        }
    }
    return fields;
}

/** Σ limits × maxFeePerGas: the prefund the EntryPoint debits from the paymaster (never more is charged). */
export function maxCostWei(gas, maxFeePerGas) {
    return (toBigInt(gas.preVerificationGas, 'preVerificationGas') + toBigInt(gas.verificationGasLimit, 'verificationGasLimit')
        + toBigInt(gas.callGasLimit, 'callGasLimit') + toBigInt(gas.paymasterVerificationGasLimit, 'paymasterVerificationGasLimit')
        + toBigInt(gas.paymasterPostOpGasLimit, 'paymasterPostOpGasLimit')) * toBigInt(maxFeePerGas, 'maxFeePerGas');
}

/**
 * The fee fields, by the rule clientd shares (its selectGaslessFees; both
 * assert zkapi-clientd/internal/zkapi/testdata/gasless-fee-parity.json):
 * maxPriorityFeePerGas = min(suggested tip, the paymaster's priority
 * ceiling); maxFeePerGas = min(2 × baseFee + priority, the max-fee ceiling),
 * refused (`gas_above_paymaster_ceiling`) only when baseFee + priority is
 * above the max-fee ceiling: the op could not land at any fee the paymaster
 * sponsors during that spike. An op at maxFeePerGas = ceiling still lands
 * while baseFee + priority fits under it; a base fee that rises past it is
 * handled by the fee bump (within the ceilings) and the stop before
 * validUntil.
 */
export function selectFees({ baseFeePerGas, priorityFeePerGas = null, maxFeeCeiling, priorityFeeCeiling }) {
    const base = toBigInt(baseFeePerGas, 'baseFeePerGas');
    const maxCeiling = toBigInt(maxFeeCeiling, 'maxFeeCeiling');
    const priorityCeiling = toBigInt(priorityFeeCeiling, 'priorityFeeCeiling');
    const suggested = priorityFeePerGas == null ? 1_000_000_000n : toBigInt(priorityFeePerGas, 'priorityFeePerGas');
    const maxPriorityFeePerGas = suggested < priorityCeiling ? suggested : priorityCeiling;
    const wanted = 2n * base + maxPriorityFeePerGas;
    if (base + maxPriorityFeePerGas > maxCeiling) {
        // neededMaxFeePerGas (base + tip) is what the refusal compares;
        // wantedMaxFeePerGas (2 × base + tip) keeps its earlier meaning for
        // hosts that display it.
        throw gaslessError('gas_above_paymaster_ceiling', {
            baseFeePerGas: base, maxPriorityFeePerGas, neededMaxFeePerGas: base + maxPriorityFeePerGas, wantedMaxFeePerGas: wanted,
            maxFeeCeiling: maxCeiling
        });
    }
    return { maxFeePerGas: wanted < maxCeiling ? wanted : maxCeiling, maxPriorityFeePerGas };
}

/** The smallest raise a bundler's replacement rule accepts: both fee fields at least 10% higher. */
export const FEE_REPLACEMENT_MIN_PERCENT = 10n;

/**
 * Both fee fields raised by 12.5% (rounded up) within the ceilings, for a
 * dropped operation's replacement; null when either field cannot rise by the
 * 10% a bundler's replacement rule needs within its ceiling (then no re-send
 * can be accepted and the bump is exhausted).
 */
export function bumpFees({ maxFeePerGas, maxPriorityFeePerGas }, { maxFeeCeiling, priorityFeeCeiling }) {
    const bump = value => (toBigInt(value) * FEE_BUMP_NUMERATOR + FEE_BUMP_DENOMINATOR - 1n) / FEE_BUMP_DENOMINATOR;
    const least = value => toBigInt(value) + (toBigInt(value) * FEE_REPLACEMENT_MIN_PERCENT + 99n) / 100n;
    const next = {
        maxFeePerGas: clamp(bump(maxFeePerGas), 0n, toBigInt(maxFeeCeiling)),
        maxPriorityFeePerGas: clamp(bump(maxPriorityFeePerGas), 0n, toBigInt(priorityFeeCeiling))
    };
    if (next.maxPriorityFeePerGas > next.maxFeePerGas) next.maxPriorityFeePerGas = next.maxFeePerGas;
    if (next.maxFeePerGas < least(maxFeePerGas) || next.maxPriorityFeePerGas < least(maxPriorityFeePerGas)) return null;
    return next;
}

/**
 * The amounts of a sponsored operation (wei; §3.1), from the payout the vault
 * will pay the transit account (`finalBalance × WEI_PER_UNIT`, or the
 * account's balance for a forward), the op's maxCost, the paymaster's flat
 * fee and what the account owes. A close, finalization or forward must leave
 * `minimumReceived > 0` (`payout_below_gas`); an escape initiation pays
 * nothing now but must cover its own cost, a gasless finalization at the
 * same fee, the minimum net and both flat fees. A sponsored cost above the
 * uneconomic fraction of the payout is refused (`gasless_uneconomic`) unless
 * `allowExpensiveGas`.
 */
export function gaslessAmounts({ kind, payoutWei, maxCost, flatFee = 0n, owed = 0n, finalizeReserveWei = 0n, minEscapeNetWei = 0n,
    uneconomicFractionPercent = UNECONOMIC_FRACTION_PERCENT, allowExpensiveGas = false }) {
    const payout = toBigInt(payoutWei, 'payout');
    const cost = toBigInt(maxCost, 'maxCost');
    const fee = toBigInt(flatFee, 'flatFee');
    const debt = toBigInt(owed, 'owed');
    const reserve = toBigInt(finalizeReserveWei, 'finalizeReserveWei');
    const minimumNet = toBigInt(minEscapeNetWei, 'minEscapeNetWei');
    const fraction = toBigInt(uneconomicFractionPercent, 'uneconomicFractionPercent');
    const escape = kind === KIND.escape;
    const requiredWei = escape ? cost + fee + debt + reserve + minimumNet + fee : cost + fee + debt;
    // An escape's net is not a floor: its finalization is charged at its own
    // feePerGas when it is sent (possibly days later), bounded only by that
    // operation's maxCost. It is an estimate at today's fees
    // (`estimatedReceived`); the guaranteed `minimumReceived` of the payout
    // is the finalization's, computed and shown when it is signed.
    const net = escape ? payout - cost - fee - debt - reserve - fee : payout - requiredWei;
    const result = {
        kind,
        payoutWei: payout,
        maxCost: cost,
        flatFee: fee,
        owed: debt,
        requiredWei,
        minimumReceived: escape ? null : net,
        estimatedReceived: escape ? net : null,
        finalizeReserveWei: escape ? reserve : 0n,
        minEscapeNetWei: escape ? minimumNet : 0n,
        initiationDebtMax: escape ? cost + fee : 0n,
        sponsoredCostWei: cost + fee,
        uneconomicFractionPercent: fraction,
        uneconomic: (cost + fee) * 100n > payout * fraction
    };
    if (payout < requiredWei || net <= 0n) {
        throw gaslessError('payout_below_gas', { ...result, requiredWei, available: payout });
    }
    if (result.uneconomic && !allowExpensiveGas) throw gaslessError('gasless_uneconomic', { ...result });
    return result;
}

/**
 * The paymaster's postOp charge before its flat fee, cap and credit surcharge
 * (ZkApiWithdrawalPaymaster.chargeFor): the EntryPoint's gas so far, the
 * pinned postOp and push gas of the kind and payee, the 10% penalty on the
 * unused call and postOp limits, and the margin, at feePerGas.
 */
export function chargeFor({ gasPolicy, kind, actualGas, executionGasUsed, callGasLimit, postOpGasLimit, payeeHasCode = false,
    payeeIsEmpty = false, feePerGas }) {
    let postOpGas;
    let overhead;
    if (kind === KIND.escape) {
        postOpGas = gasPolicy.postOpEscapeGas;
        overhead = gasPolicy.accountCallOverheadEscapeGas;
    } else {
        postOpGas = gasPolicy.postOpBaseGas + gasPolicy.eoaPushGas;
        if (payeeHasCode) postOpGas += gasPolicy.payoutPushGas;
        else if (payeeIsEmpty) postOpGas += gasPolicy.newAccountGas;
        if (kind === KIND.finalize) postOpGas += gasPolicy.postOpFinalizeExtraGas;
        overhead = gasPolicy.accountCallOverheadGas;
    }
    let used = toBigInt(executionGasUsed, 'executionGasUsed');
    const call = toBigInt(callGasLimit, 'callGasLimit');
    if (used > call) used = call;
    const usedOfLimit = used + overhead + postOpGas;
    const limit = call + toBigInt(postOpGasLimit, 'postOpGasLimit');
    const penalty = limit > usedOfLimit ? (limit - usedOfLimit) / 10n : 0n;
    return (toBigInt(actualGas, 'actualGas') + postOpGas + penalty + gasPolicy.marginGas) * toBigInt(feePerGas, 'feePerGas');
}

// ---------------------------------------------------------------- the user operation

/**
 * An unpacked v0.7 operation (bigint quantities). `paymasterData` is the
 * 12-byte feeCapWei the user accepted; `signature` is empty until signed.
 */
export function buildUserOperation({ sender, nonce, initCode = '0x', callData: data, gas, fees, paymaster, feeCapWei, signature = '0x' }) {
    if (!ADDRESS.test(sender || '')) throw new TypeError('The operation sender is not an address.');
    if (!ADDRESS.test(paymaster || '')) throw new TypeError('The paymaster is not an address.');
    if (!HEX.test(initCode || '') || !HEX.test(data || '') || !HEX.test(signature || '')) throw new TypeError('Operation bytes must be hex.');
    const cap = toBigInt(feeCapWei, 'feeCapWei');
    if (cap >= (1n << 96n)) throw new TypeError('feeCapWei does not fit in 12 bytes.');
    return {
        sender: lower(sender),
        nonce: toBigInt(nonce, 'nonce'),
        initCode: lower(initCode),
        callData: lower(data),
        callGasLimit: toBigInt(gas.callGasLimit, 'callGasLimit'),
        verificationGasLimit: toBigInt(gas.verificationGasLimit, 'verificationGasLimit'),
        preVerificationGas: toBigInt(gas.preVerificationGas, 'preVerificationGas'),
        maxFeePerGas: toBigInt(fees.maxFeePerGas, 'maxFeePerGas'),
        maxPriorityFeePerGas: toBigInt(fees.maxPriorityFeePerGas, 'maxPriorityFeePerGas'),
        paymaster: lower(paymaster),
        paymasterVerificationGasLimit: toBigInt(gas.paymasterVerificationGasLimit, 'paymasterVerificationGasLimit'),
        paymasterPostOpGasLimit: toBigInt(gas.paymasterPostOpGasLimit, 'paymasterPostOpGasLimit'),
        paymasterData: `0x${cap.toString(16).padStart(24, '0')}`,
        feeCapWei: cap,
        signature: lower(signature)
    };
}

const uint128 = (value, label) => {
    const number = toBigInt(value, label);
    if (number >= (1n << 128n)) throw new TypeError(`${label} does not fit in 128 bits.`);
    return number.toString(16).padStart(32, '0');
};

/** The packed form: accountGasLimits, gasFees and paymasterAndData = P ‖ pmVerification(16) ‖ postOp(16) ‖ feeCapWei(12). */
export function packUserOperation(op) {
    return {
        sender: lower(op.sender),
        nonce: `0x${word(op.nonce)}`,
        initCode: lower(op.initCode || '0x'),
        callData: lower(op.callData),
        accountGasLimits: `0x${uint128(op.verificationGasLimit, 'verificationGasLimit')}${uint128(op.callGasLimit, 'callGasLimit')}`,
        preVerificationGas: `0x${word(op.preVerificationGas)}`,
        gasFees: `0x${uint128(op.maxPriorityFeePerGas, 'maxPriorityFeePerGas')}${uint128(op.maxFeePerGas, 'maxFeePerGas')}`,
        paymasterAndData: `0x${strip(op.paymaster).toLowerCase()}${uint128(op.paymasterVerificationGasLimit, 'paymasterVerificationGasLimit')}`
            + `${uint128(op.paymasterPostOpGasLimit, 'paymasterPostOpGasLimit')}${strip(op.paymasterData || `0x${word(op.feeCapWei).slice(-24)}`).toLowerCase()}`,
        signature: lower(op.signature || '0x')
    };
}

/**
 * keccak256(abi.encode(keccak256(abi.encode(sender, nonce, keccak(initCode),
 * keccak(callData), accountGasLimits, preVerificationGas, gasFees,
 * keccak(paymasterAndData))), entryPoint, chainId)): UserOperationLib.hash of v0.7.0.
 */
export function userOpHash(op, entryPoint, chainId) {
    if (!ADDRESS.test(entryPoint || '')) throw new TypeError('The EntryPoint is not an address.');
    const packed = packUserOperation(op);
    const inner = keccak256(hexBytes(`${word(packed.sender)}${strip(packed.nonce)}${strip(keccak256(hexBytes(packed.initCode)))}`
        + `${strip(keccak256(hexBytes(packed.callData)))}${strip(packed.accountGasLimits)}${strip(packed.preVerificationGas)}`
        + `${strip(packed.gasFees)}${strip(keccak256(hexBytes(packed.paymasterAndData)))}`));
    return keccak256(hexBytes(`${strip(inner)}${word(entryPoint)}${word(toBigInt(chainId, 'chainId'))}`));
}

/** keccak256("\x19Ethereum Signed Message:\n32" ‖ hash): what personal_sign of the 32 raw bytes signs. */
export function eip191Digest(hash) {
    if (!WORD.test(hash || '')) throw new TypeError('The user operation hash is not 32 bytes.');
    const prefix = new TextEncoder().encode('\x19Ethereum Signed Message:\n32');
    return keccak256(Uint8Array.from([...prefix, ...hexBytes(hash)]));
}

/** The unpacked v0.7 JSON the bundler RPC takes; factory fields only with initCode (0x quantities). */
export function userOperationJson(op) {
    const initCode = strip(op.initCode || '');
    return {
        sender: lower(op.sender),
        nonce: quantity(op.nonce),
        ...(initCode.length >= 40 ? { factory: `0x${initCode.slice(0, 40)}`, factoryData: `0x${initCode.slice(40)}` } : {}),
        callData: lower(op.callData),
        callGasLimit: quantity(op.callGasLimit),
        verificationGasLimit: quantity(op.verificationGasLimit),
        preVerificationGas: quantity(op.preVerificationGas),
        maxFeePerGas: quantity(op.maxFeePerGas),
        maxPriorityFeePerGas: quantity(op.maxPriorityFeePerGas),
        paymaster: lower(op.paymaster),
        paymasterVerificationGasLimit: quantity(op.paymasterVerificationGasLimit),
        paymasterPostOpGasLimit: quantity(op.paymasterPostOpGasLimit),
        paymasterData: lower(op.paymasterData || `0x${word(op.feeCapWei).slice(-24)}`),
        signature: lower(op.signature || '0x')
    };
}

/** The operation an unpacked JSON (a journal entry or a bundler answer) describes. */
export function userOperationFromJson(json) {
    if (!json || typeof json !== 'object') throw new TypeError('The user operation JSON is missing.');
    const initCode = json.factory ? `0x${strip(json.factory)}${strip(json.factoryData || '')}`.toLowerCase() : '0x';
    const paymasterData = lower(json.paymasterData || '0x');
    return buildUserOperation({
        sender: json.sender,
        nonce: json.nonce,
        initCode,
        callData: json.callData,
        gas: {
            callGasLimit: json.callGasLimit, verificationGasLimit: json.verificationGasLimit, preVerificationGas: json.preVerificationGas,
            paymasterVerificationGasLimit: json.paymasterVerificationGasLimit, paymasterPostOpGasLimit: json.paymasterPostOpGasLimit
        },
        fees: { maxFeePerGas: json.maxFeePerGas, maxPriorityFeePerGas: json.maxPriorityFeePerGas },
        paymaster: json.paymaster,
        feeCapWei: strip(paymasterData).length === 24 ? BigInt(paymasterData) : 0n,
        signature: json.signature || '0x'
    });
}

// ---------------------------------------------------------------- ABI encoding of calls

function bytesTail(hex) {
    const data = strip(hex);
    return `${word(data.length / 2)}${data.padEnd(Math.ceil(data.length / 64) * 64, '0')}`;
}

/** The ABI encoding of one PackedUserOperation tuple (9 head words, 4 dynamic tails). */
export function encodePackedUserOperation(op) {
    const packed = packUserOperation(op);
    const dynamic = [packed.initCode, packed.callData, packed.paymasterAndData, packed.signature].map(bytesTail);
    let offset = 9n * 32n;
    const offsets = dynamic.map(tail => {
        const here = offset;
        offset += BigInt(tail.length / 2);
        return here;
    });
    return `${word(packed.sender)}${strip(packed.nonce)}${word(offsets[0])}${word(offsets[1])}${strip(packed.accountGasLimits)}`
        + `${strip(packed.preVerificationGas)}${strip(packed.gasFees)}${word(offsets[2])}${word(offsets[3])}${dynamic.join('')}`;
}

/** EntryPoint.handleOps(ops, beneficiary) calldata. */
export function encodeHandleOps(ops, beneficiary) {
    if (!ADDRESS.test(beneficiary || '')) throw new TypeError('The beneficiary is not an address.');
    const tuples = ops.map(encodePackedUserOperation);
    let offset = BigInt(tuples.length) * 32n;
    const heads = tuples.map(tuple => {
        const here = offset;
        offset += BigInt(tuple.length / 2);
        return word(here);
    });
    return callData(GASLESS_ABI.handleOps, [word(0x40), word(beneficiary), word(tuples.length), ...heads, ...tuples]);
}

/** EntryPoint.getUserOpHash(op) calldata. */
export function encodeGetUserOpHash(op) {
    return callData(GASLESS_ABI.getUserOpHash, [word(0x20), encodePackedUserOperation(op)]);
}

/** EntryPoint.getNonce(sender, key) calldata. */
export function encodeGetNonce(sender, key) {
    if (!ADDRESS.test(sender || '')) throw new TypeError('The sender is not an address.');
    const value = toBigInt(key, 'nonce key');
    if (value >= (1n << 192n)) throw new TypeError('The nonce key does not fit in 192 bits.');
    return callData(GASLESS_ABI.getNonce, [word(sender), word(value)]);
}

/** handleOps calldata bytes of a bundle of one op with a 65-byte signature placeholder (for preVerificationGas). */
export function handleOpsCalldataBytes(op, beneficiary = CANONICAL_ENTRY_POINT) {
    const signed = { ...op, signature: op.signature && strip(op.signature).length === SIGNATURE_BYTES * 2 ? op.signature : `0x${'00'.repeat(SIGNATURE_BYTES)}` };
    return strip(encodeHandleOps([signed], beneficiary)).length / 2;
}

const addressArgument = (value, label) => {
    if (!ADDRESS.test(value || '')) throw new TypeError(`${label} is not an address.`);
    return word(value);
};

export const encodeOwed = account => callData(GASLESS_ABI.owed, [addressArgument(account, 'The transit account')]);
export const encodeStranded = account => callData(GASLESS_ABI.stranded, [addressArgument(account, 'The transit account')]);
export const encodeEscapeNotePlusOne = account => callData(GASLESS_ABI.escapeNotePlusOne, [addressArgument(account, 'The transit account')]);
export const encodeCredits = payee => callData(GASLESS_ABI.credits, [addressArgument(payee, 'The payee')]);
export const encodeBalanceOf = account => callData(GASLESS_ABI.balanceOf, [addressArgument(account, 'The account')]);
export const encodeGetDepositInfo = account => callData(GASLESS_ABI.getDepositInfo, [addressArgument(account, 'The account')]);
export const encodeCallCap = kind => callData(GASLESS_ABI.callCap, [word(toBigInt(kind, 'kind'))]);
export const encodeEscapeSponsored = noteId => callData(GASLESS_ABI.escapeSponsored, [word(toBigInt(noteId, 'noteId'))]);
export const encodeGetAddress = (owner, payee) => callData(GASLESS_ABI.getAddress,
    [addressArgument(owner, 'The owner'), addressArgument(payee, 'The payee')]);
export const encodeTransitAccount = (owner, payee) => callData(GASLESS_ABI.transitAccount,
    [addressArgument(owner, 'The owner'), addressArgument(payee, 'The payee')]);
export function encodeAttempts(key) {
    if (!WORD.test(key || '')) throw new TypeError('The attempts key is not 32 bytes.');
    return callData(GASLESS_ABI.attempts, [strip(key).toLowerCase()]);
}
export function encodeKeyFor(kind, { nullifier = 0n, noteId = 0n, sender = `0x${'0'.repeat(40)}` } = {}) {
    return callData(GASLESS_ABI.keyFor, [word(toBigInt(kind, 'kind')), word(toBigInt(nullifier, 'nullifier')), word(toBigInt(noteId, 'noteId')),
        addressArgument(sender, 'The sender')]);
}
export function encodeQuote({ kind, sender, noteId = 0n, nullifier = 0n, maxCost, maxFeePerGas }) {
    return callData(GASLESS_ABI.quote, [word(toBigInt(kind, 'kind')), addressArgument(sender, 'The sender'), word(toBigInt(noteId, 'noteId')),
        word(toBigInt(nullifier, 'nullifier')), word(toBigInt(maxCost, 'maxCost')), word(toBigInt(maxFeePerGas, 'maxFeePerGas'))]);
}
export function encodeChargeFor({ kind, actualGas, executionGasUsed, callGasLimit, postOpGasLimit, payeeHasCode, payeeIsEmpty, feePerGas }) {
    return callData(GASLESS_ABI.chargeFor, [word(toBigInt(kind, 'kind')), word(toBigInt(actualGas, 'actualGas')),
        word(toBigInt(executionGasUsed, 'executionGasUsed')), word(toBigInt(callGasLimit, 'callGasLimit')),
        word(toBigInt(postOpGasLimit, 'postOpGasLimit')), word(payeeHasCode ? 1n : 0n), word(payeeIsEmpty ? 1n : 0n), word(toBigInt(feePerGas, 'feePerGas'))]);
}

// ---------------------------------------------------------------- view decoding

function exactWords(hex, count, label) {
    const values = words(hex);
    if (values.length !== count || !/^0x([0-9a-fA-F]{64})*$/.test(String(hex || ''))) {
        throw new Error(`${label} must be exactly ${count} ABI words.`);
    }
    return values;
}

/** The paymaster's gasPolicy() (30 words) as a normalized policy. */
export function decodeGasPolicy(hex) {
    const values = exactWords(hex, 8 + GAS_POLICY_SCALARS.length, 'gasPolicy');
    const policy = { callFloor: values.slice(0, 4), callHardCap: values.slice(4, 8), defaults: {} };
    GAS_POLICY_SCALARS.forEach((name, index) => { policy[name] = values[8 + index]; });
    return policy;
}

/** The paymaster's policy() (5 words). */
export function decodePolicy(hex) {
    const [maxSponsoredCostWei, flatFeeWei, minEscapeNetWei, escapesEnabled, sponsorshipPaused] = exactWords(hex, 5, 'policy');
    if (escapesEnabled > 1n || sponsorshipPaused > 1n) throw new Error('policy flags are not booleans.');
    return { maxSponsoredCostWei, flatFeeWei, minEscapeNetWei, escapesEnabled: escapesEnabled === 1n, sponsorshipPaused: sponsorshipPaused === 1n };
}

/** The paymaster's quote(...) (6 words). */
export function decodeQuote(hex) {
    const [requiredWei, owedWei, flatFeeWei, finalizeReserveWei, attemptsLeft, escapeOpen] = exactWords(hex, 6, 'quote');
    if (attemptsLeft > 1n || escapeOpen > 1n) throw new Error('quote flags are not booleans.');
    return { requiredWei, owedWei, flatFeeWei, finalizeReserveWei, attemptsLeft: attemptsLeft === 1n, escapeOpen: escapeOpen === 1n };
}

/** The EntryPoint's getDepositInfo (5 words). */
export function decodeDepositInfo(hex) {
    const [deposit, staked, stake, unstakeDelaySec, withdrawTime] = exactWords(hex, 5, 'getDepositInfo');
    return { deposit, staked: staked === 1n, stake, unstakeDelaySec, withdrawTime };
}

/** One uint256 word (a getter, a mapping read, getNonce, balanceOf). */
export function decodeWord(hex, label = 'value') {
    return exactWords(hex, 1, label)[0];
}

export function decodeAddressWord(hex, label = 'address') {
    const value = decodeWord(hex, label);
    if (value >= (1n << 160n)) throw new Error(`${label} is not an address word.`);
    return addressOf(value);
}

export function decodeBool(hex, label = 'flag') {
    const value = decodeWord(hex, label);
    if (value > 1n) throw new Error(`${label} is not a boolean.`);
    return value === 1n;
}

// ---------------------------------------------------------------- receipts

function contractLog(log, address) {
    return log?.removed !== true && lower(log?.address) === lower(address) && Array.isArray(log?.topics);
}

/**
 * The EntryPoint's UserOperationEvent of `hash` (or of `sender`) in a
 * receipt: { userOpHash, sender, paymaster, nonce, success, actualGasCost,
 * actualGasUsed, logIndex }, or null.
 */
export function parseUserOperationEvent(receipt, { entryPoint, hash = null, sender = null, nonce = null } = {}) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, entryPoint) || log.topics.length !== 4 || lower(log.topics[0]) !== GASLESS_ABI.userOperationEvent) continue;
        if (hash && lower(log.topics[1]) !== lower(hash)) continue;
        if (sender && topicAddress(log.topics[2]) !== lower(sender)) continue;
        const data = words(log.data);
        if (data.length !== 4 || data[1] > 1n) continue;
        if (nonce != null && data[0] !== BigInt(nonce)) continue;
        return {
            userOpHash: lower(log.topics[1]),
            sender: topicAddress(log.topics[2]),
            paymaster: topicAddress(log.topics[3]),
            nonce: data[0],
            success: data[1] === 1n,
            actualGasCost: data[2],
            actualGasUsed: data[3],
            logIndex: log.logIndex == null ? null : Number(BigInt(log.logIndex))
        };
    }
    return null;
}

/** The UserOperationRevertReason bytes of `hash` (an op whose execution reverted), decoded when known. */
export function parseUserOperationRevertReason(receipt, { entryPoint, hash }) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, entryPoint) || log.topics.length !== 3 || lower(log.topics[0]) !== GASLESS_ABI.userOperationRevertReasonEvent
            || lower(log.topics[1]) !== lower(hash)) continue;
        const data = strip(log.data);
        const offset = Number(BigInt(`0x${data.slice(64, 128) || '0'}`));
        const length = Number(BigInt(`0x${data.slice(offset * 2, offset * 2 + 64) || '0'}`));
        const reason = `0x${data.slice(offset * 2 + 64, offset * 2 + 64 + length * 2)}`;
        // S bubbles the vault's error as VaultCallFailed(bytes): decode the inner bytes too.
        const decoded = decodeContractRevert(reason);
        const inner = decoded?.code === 'vault_call_failed' && decoded.args?.reason ? decodeContractRevert(decoded.args.reason) : null;
        return { revertReason: reason, decoded: inner || decoded };
    }
    return null;
}

/** The paymaster's Settled event for `sender` (and `key` when given). */
export function parseSettled(receipt, paymaster, sender, { key = null } = {}) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 4 || lower(log.topics[0]) !== GASLESS_ABI.settledEvent) continue;
        if (topicAddress(log.topics[2]) !== lower(sender)) continue;
        if (key && lower(log.topics[1]) !== lower(key)) continue;
        const data = words(log.data);
        if (data.length !== 6) continue;
        return {
            key: lower(log.topics[1]), sender: topicAddress(log.topics[2]), payee: topicAddress(log.topics[3]),
            kind: Number(data[0]), noteId: data[1], received: data[2], charged: data[3], owedPaid: data[4], paidOut: data[5]
        };
    }
    return null;
}

/** The paymaster's PayoutCredited event for `payee`: the push failed and the payout is held. */
export function parsePayoutCredited(receipt, paymaster, payee) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 2 || lower(log.topics[0]) !== GASLESS_ABI.payoutCreditedEvent
            || topicAddress(log.topics[1]) !== lower(payee)) continue;
        const data = words(log.data);
        if (data.length !== 1) continue;
        return { payee: lower(payee), amount: data[0] };
    }
    return null;
}

/** The paymaster's SponsorshipFailed event for `sender`: the vault call reverted and the float paid. */
export function parseSponsorshipFailed(receipt, paymaster, sender) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 3 || lower(log.topics[0]) !== GASLESS_ABI.sponsorshipFailedEvent
            || topicAddress(log.topics[2]) !== lower(sender)) continue;
        const data = words(log.data);
        if (data.length !== 3) continue;
        return { key: lower(log.topics[1]), sender: lower(sender), kind: Number(data[0]), noteId: data[1], actualGasCost: data[2] };
    }
    return null;
}

/** Whether the paymaster recorded `sender` as stranded in this receipt. */
export function parseStranded(receipt, paymaster, sender) {
    return (receipt?.logs || []).some(log => contractLog(log, paymaster) && log.topics.length === 2
        && lower(log.topics[0]) === GASLESS_ABI.strandedEvent && topicAddress(log.topics[1]) === lower(sender));
}

/** The paymaster's Collected event of a sweep from `sender`. */
export function parseCollected(receipt, paymaster, sender) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 3 || lower(log.topics[0]) !== GASLESS_ABI.collectedEvent
            || topicAddress(log.topics[1]) !== lower(sender)) continue;
        const data = words(log.data);
        if (data.length !== 3) continue;
        return { sender: lower(sender), payee: topicAddress(log.topics[2]), received: data[0], owedPaid: data[1], paidOut: data[2] };
    }
    return null;
}

/** The paymaster's CreditClaimed event for `payee`. */
export function parseCreditClaimed(receipt, paymaster, payee) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 2 || lower(log.topics[0]) !== GASLESS_ABI.creditClaimedEvent
            || topicAddress(log.topics[1]) !== lower(payee)) continue;
        const data = words(log.data);
        if (data.length !== 1) continue;
        return { payee: lower(payee), amount: data[0] };
    }
    return null;
}

/** The paymaster's EscapeInitiationOwed event for `sender`: the debt a sponsored initiation recorded. */
export function parseEscapeInitiationOwed(receipt, paymaster, sender) {
    for (const log of receipt?.logs || []) {
        if (!contractLog(log, paymaster) || log.topics.length !== 3 || lower(log.topics[0]) !== GASLESS_ABI.escapeInitiationOwedEvent
            || topicAddress(log.topics[1]) !== lower(sender)) continue;
        const data = words(log.data);
        if (data.length !== 1) continue;
        return { sender: lower(sender), noteId: BigInt(log.topics[2]), owedWei: data[0] };
    }
    return null;
}

/** The factory's AccountCreated event for `account`. */
export function parseAccountCreated(receipt, factory, account) {
    return (receipt?.logs || []).some(log => contractLog(log, factory) && log.topics.length === 4
        && lower(log.topics[0]) === GASLESS_ABI.accountCreatedEvent && topicAddress(log.topics[1]) === lower(account));
}

/** The settlement of a sponsored op in a bundle receipt, as the client journals and shows it. */
export function settlementOf(receipt, { entryPoint, paymaster, hash = null, sender, payee }) {
    // S's operation (by its hash when known: a bundle may carry other senders' ops).
    const event = parseUserOperationEvent(receipt, { entryPoint, hash, sender });
    if (!event) return null;
    const settled = parseSettled(receipt, paymaster, sender);
    const credited = parsePayoutCredited(receipt, paymaster, payee);
    const failed = parseSponsorshipFailed(receipt, paymaster, sender);
    const revert = event.success ? null : parseUserOperationRevertReason(receipt, { entryPoint, hash: event.userOpHash });
    return {
        event,
        success: event.success,
        settled,
        credited,
        failed,
        stranded: parseStranded(receipt, paymaster, sender),
        owed: parseEscapeInitiationOwed(receipt, paymaster, sender),
        revert,
        transactionHash: lower(receipt?.transactionHash) || null,
        blockNumber: receipt?.blockNumber == null ? null : Number(BigInt(receipt.blockNumber))
    };
}

/**
 * The hash the EntryPoint emitted S's operation under in `receipt`: the first
 * of `candidates` (the hash an inclusion was found under, then the locally
 * computed ones) that has a UserOperationEvent of `sender`, else the event of
 * `sender` at `nonce` (any signed variant of this operation). A bundler's own
 * hash (eth_sendUserOperation answering another one) never names an event:
 * the EntryPoint always emits the canonical hash. null when neither matches.
 */
export function emittedUserOpHash(receipt, { entryPoint, sender, candidates = [], nonce = null }) {
    for (const hash of candidates) {
        if (!hash) continue;
        const event = parseUserOperationEvent(receipt, { entryPoint, hash, sender });
        if (event) return event.userOpHash;
    }
    if (nonce == null) return null;
    return parseUserOperationEvent(receipt, { entryPoint, sender, nonce })?.userOpHash ?? null;
}

/** The bundle transaction hash a bundler's eth_getUserOperationReceipt names, or null. */
export function userOperationReceiptTransactionHash(receipt) {
    const hash = receipt?.receipt?.transactionHash || receipt?.transactionHash || null;
    return /^0x[0-9a-fA-F]{64}$/.test(hash || '') ? lower(hash) : null;
}

// ---------------------------------------------------------------- the dry run

/**
 * The refusal of a dry run (eth_call handleOps([op], beneficiary)) or of a
 * bundler: FailedOp / FailedOpWithRevert decoded to a coded error (AA codes,
 * the paymaster's errors for AA33), or null when the value is no EntryPoint
 * revert. `error.silent` marks AA10 and AA25, which the client handles alone.
 */
export function dryRunError(error) {
    return entryPointError(error);
}

export { decodeEntryPointRevert };

// ---------------------------------------------------------------- the bundler

/** ERC-7769's JSON-RPC refusal codes that name a cause other than the fee (used when the bundler names no AA code). */
export const BUNDLER_RPC_ERRORS = Object.freeze({
    [-32507]: Object.freeze({ code: 'signature_rejected', message: GASLESS_MESSAGES.signature_rejected }),
    [-32508]: Object.freeze({ code: 'paymaster_underfunded', message: GASLESS_MESSAGES.paymaster_underfunded })
});

function bundlerError(code, message, data = null, cause = null) {
    const error = gaslessError(code, data, message);
    error.cause = cause;
    return error;
}

/**
 * A client of an ERC-4337 bundler: a URL (JSON-RPC over fetch, credentials
 * omitted), an EIP-1193-style `{ request }` object, or a host's duck-typed
 * transport with `sendUserOperation`, `getUserOperationReceipt`,
 * `getUserOperationByHash`, `estimateUserOperationGas` (and optionally
 * `chainId`, `supportedEntryPoints`). A transport failure is
 * `bundler_unavailable`; a JSON-RPC error is `bundler_rejected` (refined to
 * the AA code when the bundler names one), with `rpcCode` and `rpcMessage`.
 */
export function bundlerClient(target, { fetchImpl = null, timeoutMs = 20_000 } = {}) {
    if (!target) throw bundlerError('bundler_unavailable', 'No bundler is configured: set one with setBundlerUrl, or pay the fee from a wallet.');
    const refine = (error, method) => {
        const decoded = entryPointError(error);
        if (decoded) {
            decoded.rpcCode = error?.rpcCode ?? error?.code ?? null;
            decoded.rpcMessage = error?.message || null;
            decoded.method = method;
            return decoded;
        }
        const message = error?.message || 'The bundler refused the request.';
        const aa = /\b(AA\d\d)\b/.exec(message);
        // Without an AA code, ERC-7769's own refusal codes still name the
        // cause: -32507 a failed signature check, -32508 a paymaster balance
        // that cannot cover every pending operation (EREP-010). Neither is a
        // fee refusal, and neither is cured by signing again.
        const detail = aa ? ENTRY_POINT_ERRORS[aa[1]] : BUNDLER_RPC_ERRORS[Number(error?.rpcCode ?? error?.code)] || null;
        const wrapped = bundlerError(detail?.code || 'bundler_rejected', detail?.message || `The bundler refused ${method}: ${message}`,
            { method, rpcCode: error?.rpcCode ?? error?.code ?? null, rpcMessage: message, rpcData: error?.data ?? null }, error);
        wrapped.silent = Boolean(detail?.silent);
        wrapped.aa = aa ? aa[1] : null;
        wrapped.rpcCode = error?.rpcCode ?? error?.code ?? null;
        wrapped.rpcMessage = message;
        return wrapped;
    };
    let call;
    let kind;
    if (typeof target === 'string') {
        kind = 'url';
        const url = bundlerUrl(target);
        call = async (method, params) => {
            let response;
            try {
                response = await (fetchImpl || globalThis.fetch)(url, {
                    method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit', cache: 'no-store',
                    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(timeoutMs)
                });
            } catch (error) {
                throw bundlerError('bundler_unavailable', GASLESS_MESSAGES.bundler_unavailable, { method, url }, error);
            }
            if (!response.ok) throw bundlerError('bundler_unavailable', `The bundler answered HTTP ${response.status}.`, { method, url, status: response.status });
            let body;
            try {
                body = await response.json();
            } catch (error) {
                throw bundlerError('bundler_unavailable', 'The bundler answered with malformed JSON.', { method, url }, error);
            }
            if (body?.error) {
                throw refine(Object.assign(new Error(body.error.message || 'The bundler returned an error.'),
                    { rpcCode: body.error.code ?? null, data: body.error.data ?? null }), method);
            }
            return body?.result;
        };
    } else if (typeof target.request === 'function') {
        kind = 'request';
        call = async (method, params) => {
            try {
                return await target.request({ method, params });
            } catch (error) {
                if (error?.code === 'bundler_unavailable' || error?.name === 'TimeoutError' || error?.name === 'AbortError') {
                    throw bundlerError('bundler_unavailable', GASLESS_MESSAGES.bundler_unavailable, { method }, error);
                }
                throw refine(error, method);
            }
        };
    } else if (typeof target.sendUserOperation === 'function') {
        kind = 'host';
        const methods = {
            eth_chainId: () => (typeof target.chainId === 'function' ? target.chainId() : null),
            eth_supportedEntryPoints: () => (typeof target.supportedEntryPoints === 'function' ? target.supportedEntryPoints() : null),
            eth_estimateUserOperationGas: ([op, entryPoint]) => (typeof target.estimateUserOperationGas === 'function'
                ? target.estimateUserOperationGas(op, entryPoint) : null),
            eth_sendUserOperation: ([op, entryPoint]) => target.sendUserOperation(op, entryPoint),
            eth_getUserOperationByHash: ([hash]) => (typeof target.getUserOperationByHash === 'function' ? target.getUserOperationByHash(hash) : null),
            eth_getUserOperationReceipt: ([hash]) => (typeof target.getUserOperationReceipt === 'function' ? target.getUserOperationReceipt(hash) : null)
        };
        call = async (method, params) => {
            try {
                return await methods[method](params);
            } catch (error) {
                throw refine(error, method);
            }
        };
    } else {
        throw new TypeError('The bundler must be a URL, a request function object or a host transport.');
    }
    const requireHash = value => {
        if (!/^0x[0-9a-fA-F]{64}$/.test(value || '')) throw bundlerError('bundler_rejected', 'The bundler did not return a user operation hash.', { value });
        return lower(value);
    };
    // The bundler's own tip (§3.1 fees): Rundler's rundler_maxPriorityFeePerGas
    // or Pimlico's pimlico_getUserOperationGasPrice (its standard tier); a
    // host transport may offer maxPriorityFeePerGas(). null when the bundler
    // offers neither (remembered for this client), so the chain's tip is used.
    let tipUnsupported = false;
    const suggestedPriorityFee = async () => {
        if (tipUnsupported) return null;
        const tipOf = value => {
            try {
                const tip = value == null ? null : toBigInt(value, 'priorityFee');
                return tip != null && tip >= 0n ? tip : null;
            } catch {
                return null;
            }
        };
        if (kind === 'host') {
            if (typeof target.maxPriorityFeePerGas !== 'function') return null;
            try {
                return tipOf(await target.maxPriorityFeePerGas());
            } catch {
                return null;
            }
        }
        const sources = [
            ['rundler_maxPriorityFeePerGas', value => value],
            ['pimlico_getUserOperationGasPrice', value => value?.standard?.maxPriorityFeePerGas ?? value?.fast?.maxPriorityFeePerGas ?? null]
        ];
        for (const [method, pick] of sources) {
            try {
                const tip = tipOf(pick(await call(method, [])));
                if (tip != null) return tip;
            } catch (error) {
                if (error?.code === 'bundler_unavailable') return null;
            }
        }
        tipUnsupported = true;
        return null;
    };
    return {
        kind,
        request: call,
        suggestedPriorityFee,
        chainId: async () => {
            const value = await call('eth_chainId', []);
            return value == null ? null : toBigInt(value, 'chainId');
        },
        supportedEntryPoints: async () => {
            const value = await call('eth_supportedEntryPoints', []);
            return value == null ? null : (Array.isArray(value) ? value.map(lower) : []);
        },
        estimateUserOperationGas: (opJson, entryPoint) => call('eth_estimateUserOperationGas', [opJson, entryPoint]),
        sendUserOperation: async (opJson, entryPoint) => requireHash(await call('eth_sendUserOperation', [opJson, entryPoint])),
        getUserOperationByHash: hash => call('eth_getUserOperationByHash', [hash]),
        getUserOperationReceipt: hash => call('eth_getUserOperationReceipt', [hash])
    };
}

/** A validated bundler URL: HTTPS, or HTTP on loopback, without credentials (the exit RPC's rule). */
export function bundlerUrl(value) {
    let url;
    try {
        url = new URL(String(value));
    } catch {
        throw gaslessError('bundler_url_invalid');
    }
    if (url.username || url.password || (url.protocol !== 'https:'
        && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
        throw gaslessError('bundler_url_invalid');
    }
    return url.href;
}

/**
 * A bundler's estimate (eth_estimateUserOperationGas) is a cross-check only:
 * an estimate above a cap is refused (`gasless_estimate_above_cap`, the
 * bundler is suspect); one below the pinned default is ignored. Returns the
 * fields the client signs (unchanged) or throws.
 */
export function checkEstimate(estimate, { gasPolicy, kind, withInitCode = false, callCap = null }) {
    if (!estimate || typeof estimate !== 'object') return null;
    const index = kind - 1;
    const caps = {
        preVerificationGas: gasPolicy.pvgCap,
        verificationGasLimit: gasPolicy.verificationCap,
        callGasLimit: callCap == null ? gasPolicy.callHardCap[index] : toBigInt(callCap),
        paymasterVerificationGasLimit: gasPolicy.pmVerificationCap,
        paymasterPostOpGasLimit: gasPolicy.postOpCap
    };
    const above = [];
    for (const [name, cap] of Object.entries(caps)) {
        if (estimate[name] == null) continue;
        let value;
        try {
            value = toBigInt(estimate[name], name);
        } catch {
            continue;
        }
        if (value > cap) above.push({ name, value, cap });
    }
    if (above.length) throw gaslessError('gasless_estimate_above_cap', { above, withInitCode });
    return above;
}

// ---------------------------------------------------------------- availability

/**
 * The first reason the sponsored path is unavailable, in the order of the
 * pre-flight of §3.1 (the deployment check runs before): the bundler, the
 * paymaster's policy and float, the vault's pause, the key's attempts.
 * Returns { available, reason, message, data }.
 */
export function availabilityVerdict({ bundler = null, policy = null, policyMatches = true, depositWei = null, maxCost = 0n,
    vaultPaused = false, reopenAt = null, attempts = null, kind = KIND.close, maxAttempts = MAX_ATTEMPTS } = {}) {
    const refusal = (reason, data = null) => ({ available: false, reason, message: GASLESS_MESSAGES[reason] || reason, data });
    if (bundler?.reachable === false) return refusal('bundler_unavailable', { fallbacks: ['self_bundle', 'direct_call'] });
    if (bundler?.wrongChain) return refusal('bundler_wrong_chain', { chainId: bundler.chainId ?? null });
    if (bundler?.supportsEntryPoint === false) return refusal('bundler_unsupported_entry_point', { entryPoints: bundler.entryPoints || [] });
    if (policy?.sponsorshipPaused) return refusal('sponsorship_paused');
    if (kind === KIND.escape && policy && !policy.escapesEnabled) return refusal('escapes_disabled');
    if (!policyMatches) return refusal('gasless_policy_mismatch');
    if (depositWei != null && toBigInt(depositWei) < toBigInt(maxCost)) {
        return refusal('paymaster_underfunded', { depositWei: toBigInt(depositWei), maxCost: toBigInt(maxCost) });
    }
    if (vaultPaused && kind !== KIND.finalize && kind !== KIND.forward) return refusal('exits_paused', { reopenAt });
    if (attempts != null && toBigInt(attempts) >= toBigInt(maxAttempts)) {
        return refusal('gasless_attempts_exhausted', { attempts: toBigInt(attempts), maxAttempts: toBigInt(maxAttempts) });
    }
    return { available: true, reason: null, message: null, data: null };
}

/** A journal-safe copy: bigints as decimal strings, nested, arrays included. */
export function journalValue(value) {
    if (typeof value === 'bigint') return value.toString();
    if (Array.isArray(value)) return value.map(journalValue);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, journalValue(entry)]));
    return value;
}

/** The decimal string of a wei amount for status payloads, or null. */
export function weiString(value) {
    return value == null ? null : toBigInt(value).toString();
}
