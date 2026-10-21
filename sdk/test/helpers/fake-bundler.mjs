// A scripted ERC-4337 bundler, a scripted read RPC of a chain that holds the
// vault, the EntryPoint, the withdrawal paymaster and its factory, and an
// EIP-1193 wallet that signs with personal_sign and refuses to send
// transactions: the observed fakes of the gasless withdrawal tests (design
// §5.2). The user operation hash, the CREATE2 of a transit account and the
// paymaster's quote are recomputed here from the packed bytes and the
// contract formulas, independently of sdk/services/zkapiGasless.mjs; the
// profile and every constant come from protocol/contracts/test/fixtures/
// transit-vectors.json.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { codehash, hexBytes, keccak256 } from '../../services/zkapiKeccak.mjs';
import { ABI as GASLESS_ABI_VAULT, GASLESS_ABI } from '../../wallet.js';
import { sign } from './secp256k1.mjs';

export const VECTORS = JSON.parse(readFileSync(new URL('../../../protocol/contracts/test/fixtures/transit-vectors.json', import.meta.url), 'utf8'));
/** The canonical v0.7.0 runtimes (vendored fixtures), whose keccaks are the pinned codehashes. */
export const ENTRY_POINT_RUNTIME = readFileSync(new URL('../../../protocol/contracts/test/fixtures/entrypoint-v0.7.0.runtime.hex', import.meta.url), 'utf8').trim();
export const SENDER_CREATOR_RUNTIME = readFileSync(new URL('../../../protocol/contracts/test/fixtures/sender-creator-v0.7.0.runtime.hex', import.meta.url), 'utf8').trim();
export const BUNDLER_URL = 'https://bundler.example/rpc';
export const EXIT_RPC_URL = 'https://exit-rpc.example/rpc';
/** Fake runtime codes of the contracts the pins name; their keccaks are the profile's codehashes. */
export const FAKE_CODE = Object.freeze({
    paymaster: '0x60806040526004361061aa',
    factory: '0x60806040526004361061bb',
    implementation: '0x60806040526004361061cc'
});

const strip = value => String(value ?? '').replace(/^0x/i, '').toLowerCase();
const lower = value => String(value ?? '').toLowerCase();
export const word = value => BigInt(value).toString(16).padStart(64, '0');
const u128 = value => BigInt(value).toString(16).padStart(32, '0');
export const topicOf = address => `0x${word(BigInt(address))}`;
const hex = value => `0x${BigInt(value).toString(16)}`;
const selector = name => GASLESS_ABI[name];

/**
 * The `gasless` object of a deployment profile (design §4.3) from the vectors.
 * `spelling: 'vectors'` uses transit-vectors.json's keys (post_op_*,
 * call_hard_cap); 'profile' the design's (postop_*, call_cap, with defaults),
 * as scripts/deployment-profile.mjs writes them.
 */
export function gaslessProfileFromVectors({ bundlerUrl = BUNDLER_URL, spelling = 'vectors', escapesEnabled = true, codes = FAKE_CODE } = {}) {
    const gp = VECTORS.gas_policy;
    const number = value => Number(value);
    const base = {
        entry_point_address: VECTORS.entry_point,
        entry_point_runtime_codehash: VECTORS.entry_point_codehash,
        sender_creator_address: VECTORS.sender_creator,
        sender_creator_runtime_codehash: VECTORS.sender_creator_codehash,
        withdrawal_paymaster_address: VECTORS.paymaster,
        withdrawal_paymaster_runtime_codehash: codehash(codes.paymaster),
        withdrawal_account_factory_address: VECTORS.factory,
        withdrawal_account_factory_runtime_codehash: codehash(codes.factory),
        withdrawal_account_implementation_address: VECTORS.implementation,
        withdrawal_account_implementation_runtime_codehash: codehash(codes.implementation),
        account_creation_code: VECTORS.account_creation_code,
        account_creation_code_keccak256: VECTORS.account_creation_code_keccak256,
        bundler_url: bundlerUrl,
        policy: {
            max_sponsored_cost_wei: VECTORS.policy.max_sponsored_cost,
            flat_fee_wei: VECTORS.policy.flat_fee_wei,
            min_escape_net_wei: VECTORS.policy.min_escape_net_wei,
            escapes_enabled: escapesEnabled
        },
        fee_ceilings: { max_fee_wei: VECTORS.policy.max_fee_ceiling, priority_fee_wei: VECTORS.policy.priority_fee_ceiling },
        uneconomic_fraction_percent: 25
    };
    if (spelling === 'vectors') return { ...base, gas_policy: structuredClone(gp) };
    const floors = gp.call_floor.map(number);
    const caps = gp.call_hard_cap.map(number);
    return {
        ...base,
        gas_policy: {
            call_floor: floors,
            call_cap: caps,
            call_default: floors.map((floor, index) => floor + Math.floor((caps[index] - floor) / 4)),
            postop_floor: number(gp.post_op_floor),
            postop_cap: number(gp.post_op_cap),
            postop_default: number(gp.post_op_floor) + 20_000,
            verification_floor: number(gp.verification_floor),
            verification_floor_init: number(gp.verification_floor_init),
            verification_cap: number(gp.verification_cap),
            verification_default: number(gp.verification_floor) + 20_000,
            verification_default_init: number(gp.verification_floor_init) + 40_000,
            pvg_floor: number(gp.pvg_floor),
            pvg_cap: number(gp.pvg_cap),
            pm_verification_floor: number(gp.pm_verification_floor),
            pm_verification_cap: number(gp.pm_verification_cap),
            pm_verification_default: number(gp.pm_verification_floor) + 30_000,
            postop_base_gas: number(gp.post_op_base_gas),
            postop_escape_gas: number(gp.post_op_escape_gas),
            postop_finalize_extra_gas: number(gp.post_op_finalize_extra_gas),
            postop_escape_forward_gas: number(gp.post_op_escape_forward_gas),
            eoa_push_gas: number(gp.eoa_push_gas),
            new_account_gas: number(gp.new_account_gas),
            payout_push_gas: number(gp.payout_push_gas),
            credit_gas: number(gp.credit_gas),
            account_call_overhead_gas: number(gp.account_call_overhead_gas),
            account_call_overhead_escape_gas: number(gp.account_call_overhead_escape_gas),
            margin_gas: number(gp.margin_gas),
            finalize_reserve_gas: number(gp.finalize_reserve_gas),
            max_attempts: number(gp.max_attempts)
        }
    };
}

// ---- independent re-implementations of the byte formats ----

/** S = CREATE2(factory, 0, keccak(creationCode ‖ abi.encode(entryPoint, vault, paymaster, owner, payee))). */
export function create2TransitAccount({ factory, creationCode, entryPoint, vault, paymaster, owner, payee }) {
    const initCode = strip(creationCode) + [entryPoint, vault, paymaster, owner, payee].map(address => word(BigInt(address))).join('');
    const initCodeHash = keccak256(hexBytes(initCode));
    return `0x${keccak256(hexBytes(`ff${strip(factory)}${'0'.repeat(64)}${strip(initCodeHash)}`)).slice(-40)}`;
}

/** The packed fields of an unpacked v0.7 JSON operation. */
export function packedFromJson(op) {
    return {
        sender: lower(op.sender),
        nonce: word(op.nonce),
        initCode: op.factory ? strip(op.factory) + strip(op.factoryData || '') : '',
        callData: strip(op.callData),
        accountGasLimits: u128(op.verificationGasLimit) + u128(op.callGasLimit),
        preVerificationGas: word(op.preVerificationGas),
        gasFees: u128(op.maxPriorityFeePerGas) + u128(op.maxFeePerGas),
        paymasterAndData: strip(op.paymaster) + u128(op.paymasterVerificationGasLimit) + u128(op.paymasterPostOpGasLimit) + strip(op.paymasterData || ''),
        signature: strip(op.signature || '')
    };
}

/** UserOperationLib.hash of v0.7.0 over packed fields. */
export function hashPacked(packed, entryPoint, chainId) {
    const field = name => strip(packed[name]);
    const inner = keccak256(hexBytes(`${word(BigInt(packed.sender))}${field('nonce')}${strip(keccak256(hexBytes(field('initCode'))))}`
        + `${strip(keccak256(hexBytes(field('callData'))))}${field('accountGasLimits')}${field('preVerificationGas')}${field('gasFees')}`
        + `${strip(keccak256(hexBytes(field('paymasterAndData'))))}`));
    return keccak256(hexBytes(`${strip(inner)}${word(BigInt(entryPoint))}${word(chainId)}`));
}

export const userOperationHashFromJson = (op, entryPoint, chainId) => hashPacked(packedFromJson(op), entryPoint, chainId);

/** One PackedUserOperation tuple at `offset` (hex chars) of `body`. */
function decodeTuple(body, offset) {
    const w = index => body.slice(offset + index * 64, offset + (index + 1) * 64);
    const bytesAt = index => {
        const start = offset + Number(BigInt(`0x${w(index)}`)) * 2;
        const length = Number(BigInt(`0x${body.slice(start, start + 64)}`));
        return body.slice(start + 64, start + 64 + length * 2);
    };
    return {
        sender: `0x${w(0).slice(-40)}`,
        nonce: w(1),
        initCode: bytesAt(2),
        callData: bytesAt(3),
        accountGasLimits: w(4),
        preVerificationGas: w(5),
        gasFees: w(6),
        paymasterAndData: bytesAt(7),
        signature: bytesAt(8)
    };
}

/** EntryPoint.handleOps(ops, beneficiary) calldata → { beneficiary, ops: [packed] }. */
export function decodeHandleOps(data) {
    const body = strip(data).slice(8);
    assert.equal(strip(data).slice(0, 8), selector('handleOps'), 'handleOps selector');
    const opsOffset = Number(BigInt(`0x${body.slice(0, 64)}`)) * 2;
    const beneficiary = `0x${body.slice(64 + 24, 128)}`;
    const length = Number(BigInt(`0x${body.slice(opsOffset, opsOffset + 64)}`));
    const ops = [];
    for (let index = 0; index < length; index += 1) {
        const relative = Number(BigInt(`0x${body.slice(opsOffset + 64 + index * 64, opsOffset + 128 + index * 64)}`)) * 2;
        ops.push(decodeTuple(body, opsOffset + 64 + relative));
    }
    return { beneficiary, ops };
}

/** EntryPoint.getUserOpHash(op) calldata → packed op. */
export function decodeGetUserOpHash(data) {
    const body = strip(data).slice(8);
    assert.equal(strip(data).slice(0, 8), selector('getUserOpHash'), 'getUserOpHash selector');
    const offset = Number(BigInt(`0x${body.slice(0, 64)}`)) * 2;
    return decodeTuple(body, offset);
}

/** abi.encode(string, uint256|address) keccak: the paymaster's attempt keys. */
export function attemptsKeyOf(kind, { nullifier = 0n, noteId = 0n, sender = null } = {}) {
    const text = ['close', 'escape', 'finalize', 'forward'][kind - 1];
    const value = kind === 1 ? BigInt(nullifier) : kind === 4 ? BigInt(sender) : BigInt(noteId);
    const bytes = new TextEncoder().encode(text);
    const encoded = `${word(0x40)}${word(value)}${word(bytes.length)}${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('').padEnd(64, '0')}`;
    return keccak256(hexBytes(encoded));
}

/** The ABI-encoded revert of FailedOp(index, reason) or FailedOpWithRevert(index, reason, inner). */
export function failedOpData(reason, inner = null) {
    const text = new TextEncoder().encode(reason);
    const textHex = Array.from(text, byte => byte.toString(16).padStart(2, '0')).join('').padEnd(Math.ceil(text.length / 32) * 64, '0');
    if (inner == null) return `0x${selector('failedOpError')}${word(0)}${word(0x40)}${word(text.length)}${textHex}`;
    const innerHex = strip(inner);
    const innerPadded = innerHex.padEnd(Math.ceil(innerHex.length / 64) * 64, '0');
    const reasonOffset = 0x60;
    const innerOffset = reasonOffset + 32 + textHex.length / 2;
    return `0x${selector('failedOpWithRevertError')}${word(0)}${word(reasonOffset)}${word(innerOffset)}${word(text.length)}${textHex}${word(innerHex.length / 2)}${innerPadded}`;
}

/** A node's revert error for an eth_call, as the SDK's RPC helpers surface it. */
export function revertError(data, message = 'execution reverted') {
    return Object.assign(new Error(message), { code: 'rpc_call_reverted', data });
}

// ---- logs ----

const log = (address, topics, words, extra = {}) => ({ address: lower(address), topics, data: `0x${words.map(word).join('')}`, removed: false, ...extra });
export const logs = Object.freeze({
    mutualClose: (vault, { noteId, nullifier = 0x99n, finalBalance, destination }) => log(vault,
        [GASLESS_ABI_VAULT.mutualCloseEvent, `0x${word(noteId)}`], [nullifier, finalBalance, BigInt(destination)]),
    escapeInitiated: (vault, { noteId, nullifier = 0x99n, finalBalance, destination, challengeDeadline, root = 0x77n }) => log(vault,
        [GASLESS_ABI_VAULT.escapeInitiatedEvent, `0x${word(noteId)}`], [nullifier, finalBalance, BigInt(destination), challengeDeadline, root]),
    escapeFinalized: (vault, { noteId, nullifier = 0x99n, finalBalance, destination }) => log(vault,
        [GASLESS_ABI_VAULT.escapeFinalizedEvent, `0x${word(noteId)}`], [nullifier, finalBalance, BigInt(destination)]),
    settled: (paymaster, { key, sender, payee, kind, noteId, received, charged, owedPaid, paidOut }) => log(paymaster,
        [GASLESS_ABI.settledEvent, key, topicOf(sender), topicOf(payee)], [kind, noteId, received, charged, owedPaid, paidOut]),
    payoutCredited: (paymaster, payee, amount) => log(paymaster, [GASLESS_ABI.payoutCreditedEvent, topicOf(payee)], [amount]),
    sponsorshipFailed: (paymaster, { key, sender, kind, noteId, actualGasCost }) => log(paymaster,
        [GASLESS_ABI.sponsorshipFailedEvent, key, topicOf(sender)], [kind, noteId, actualGasCost]),
    stranded: (paymaster, sender) => log(paymaster, [GASLESS_ABI.strandedEvent, topicOf(sender)], []),
    escapeInitiationOwed: (paymaster, { sender, noteId, owedWei }) => log(paymaster,
        [GASLESS_ABI.escapeInitiationOwedEvent, topicOf(sender), `0x${word(noteId)}`], [owedWei]),
    collected: (paymaster, { sender, payee, received, owedPaid, paidOut }) => log(paymaster,
        [GASLESS_ABI.collectedEvent, topicOf(sender), topicOf(payee)], [received, owedPaid, paidOut]),
    creditClaimed: (paymaster, payee, amount) => log(paymaster, [GASLESS_ABI.creditClaimedEvent, topicOf(payee)], [amount]),
    accountCreated: (factory, { account, owner, payee }) => log(factory,
        [GASLESS_ABI.accountCreatedEvent, topicOf(account), topicOf(owner), topicOf(payee)], []),
    userOperationEvent: (entryPoint, { hash, sender, paymaster, nonce, success, actualGasCost = 0n, actualGasUsed = 0n }) => log(entryPoint,
        [GASLESS_ABI.userOperationEvent, lower(hash), topicOf(sender), topicOf(paymaster)], [nonce, success ? 1n : 0n, actualGasCost, actualGasUsed]),
    userOperationRevertReason: (entryPoint, { hash, sender, nonce, reason }) => {
        const inner = strip(reason);
        return log(entryPoint, [GASLESS_ABI.userOperationRevertReasonEvent, lower(hash), topicOf(sender)], [nonce, 0x40n, inner.length / 2],
            { data: `0x${word(nonce)}${word(0x40)}${word(inner.length / 2)}${inner.padEnd(Math.ceil(inner.length / 64) * 64, '0')}` });
    }
});

// ---- the chain ----

/**
 * A chain that holds the vault, the EntryPoint, the paymaster and its factory,
 * as an EIP-1193 request function with scripted state. `eth_call` answers the
 * reads the sponsored path makes; `handleOps` is the dry run; everything is
 * recorded in `calls`.
 */
export function fakeGaslessChain({ chainId, vault, gasless, noteId = 7, noteStatus = 1, finalBalance = 500_000_000, codes = FAKE_CODE } = {}) {
    const pins = gasless;
    const entryPoint = lower(pins.entry_point_address);
    const paymaster = lower(pins.withdrawal_paymaster_address);
    const factory = lower(pins.withdrawal_account_factory_address);
    const gp = pins.gas_policy;
    const scalar = (...names) => BigInt(names.map(name => gp[name]).find(value => value != null));
    const policyWords = [
        ...(gp.call_floor).map(BigInt), ...(gp.call_hard_cap ?? gp.call_cap).map(BigInt),
        scalar('post_op_floor', 'postop_floor'), scalar('post_op_cap', 'postop_cap'), scalar('verification_floor'), scalar('verification_floor_init'),
        scalar('verification_cap'), scalar('pvg_floor'), scalar('pvg_cap'), scalar('pm_verification_floor'), scalar('pm_verification_cap'),
        scalar('post_op_base_gas', 'postop_base_gas'), scalar('post_op_escape_gas', 'postop_escape_gas'),
        scalar('post_op_finalize_extra_gas', 'postop_finalize_extra_gas'), scalar('post_op_escape_forward_gas', 'postop_escape_forward_gas'),
        scalar('eoa_push_gas'), scalar('new_account_gas'), scalar('payout_push_gas'), scalar('credit_gas'), scalar('account_call_overhead_gas'),
        scalar('account_call_overhead_escape_gas'), scalar('margin_gas'), scalar('finalize_reserve_gas'), scalar('max_attempts')
    ];
    const chain = {
        chainId: BigInt(chainId),
        entryPoint, paymaster, factory, vault: lower(vault),
        head: 1_000,
        finalized: 900,
        baseFee: 10_000_000_000n,
        priorityFee: 2_000_000_000n,
        servesPriorityFee: true,
        code: new Map([
            [entryPoint, ENTRY_POINT_RUNTIME], [lower(pins.sender_creator_address), SENDER_CREATOR_RUNTIME],
            [paymaster, codes.paymaster], [factory, codes.factory], [lower(pins.withdrawal_account_implementation_address), codes.implementation]
        ]),
        codeHashOverride: new Map(),
        balances: new Map(),
        nonces: new Map(),
        paymasterState: {
            policy: {
                maxSponsoredCost: BigInt(pins.policy.max_sponsored_cost_wei), flatFee: BigInt(pins.policy.flat_fee_wei),
                minEscapeNet: BigInt(pins.policy.min_escape_net_wei), escapesEnabled: pins.policy.escapes_enabled === true, sponsorshipPaused: false
            },
            maxFeeCeiling: BigInt(pins.fee_ceilings.max_fee_wei),
            priorityFeeCeiling: BigInt(pins.fee_ceilings.priority_fee_wei),
            gasPolicyWords: policyWords,
            deposit: 1_000_000_000_000_000_000n,
            callCap: (gp.call_hard_cap ?? gp.call_cap).map(BigInt),
            attempts: new Map(),
            owed: new Map(),
            stranded: new Map(),
            escapeNotePlusOne: new Map(),
            escapeSponsored: new Map(),
            credits: new Map()
        },
        vaultState: {
            paused: false, pausedAt: 0n, currentRoot: 0x77n,
            notes: new Map([[Number(noteId), { status: noteStatus, deposit: BigInt(finalBalance) }]]),
            pending: new Map(),
            escapePayoutCredits: new Map()
        },
        receipts: new Map(),
        logs: [],
        calls: [],
        dryRun: null,
        failing: new Set(),
        timestamp: () => Math.floor(Date.now() / 1_000)
    };
    const codeOf = address => chain.code.get(lower(address)) ?? '0x';
    const balanceOf = address => chain.balances.get(lower(address)) ?? 0n;
    chain.nonceOf = (sender, key) => chain.nonces.get(`${lower(sender)}:${BigInt(key)}`) ?? 0n;
    chain.setNonce = (sender, key, sequence) => chain.nonces.set(`${lower(sender)}:${BigInt(key)}`, BigInt(sequence));
    chain.setBalance = (address, wei) => chain.balances.set(lower(address), BigInt(wei));
    chain.setCode = (address, code) => chain.code.set(lower(address), code);
    chain.noteStatus = (id, status) => {
        const note = chain.vaultState.notes.get(Number(id)) || { deposit: BigInt(finalBalance) };
        chain.vaultState.notes.set(Number(id), { ...note, status });
    };
    chain.setPending = (id, pending) => chain.vaultState.pending.set(Number(id), pending);
    chain.transitAccount = (owner, payee) => create2TransitAccount({
        factory, creationCode: pins.account_creation_code, entryPoint, vault: lower(vault), paymaster, owner, payee
    });
    const quote = ({ kind, sender, noteIdValue, nullifier, maxCost, maxFeePerGas }) => {
        const state = chain.paymasterState;
        const owed = state.owed.get(lower(sender)) ?? 0n;
        const flat = state.policy.flatFee;
        let required = maxCost + flat + owed;
        let reserve = 0n;
        if (kind === 2n) {
            reserve = scalar('finalize_reserve_gas') * maxFeePerGas;
            required += reserve + state.policy.minEscapeNet + flat;
        }
        const key = attemptsKeyOf(Number(kind), { nullifier, noteId: noteIdValue, sender });
        const attemptsLeft = (state.attempts.get(key) ?? 0n) < scalar('max_attempts');
        const recorded = state.escapeNotePlusOne.get(lower(sender)) ?? 0n;
        let open = false;
        if (recorded !== 0n) {
            const status = chain.vaultState.notes.get(Number(recorded - 1n))?.status ?? 1;
            open = status === 2 || (status === 3 && balanceOf(sender) !== 0n);
        }
        const escapeOpen = state.policy.escapesEnabled && !(state.escapeSponsored.get(Number(noteIdValue)) === true) && !open;
        return `0x${[required, owed, flat, reserve, attemptsLeft ? 1n : 0n, escapeOpen ? 1n : 0n].map(word).join('')}`;
    };
    const ethCall = ({ to, data }) => {
        const target = lower(to);
        const sel = strip(data).slice(0, 8);
        const arg = index => BigInt(`0x${strip(data).slice(8 + index * 64, 8 + (index + 1) * 64) || '0'}`);
        const address = index => `0x${word(arg(index)).slice(-40)}`;
        if (chain.failing.has(`${target}:${sel}`)) throw new Error(`scripted read failure ${sel}`);
        if (target === entryPoint) {
            if (sel === selector('getNonce')) return `0x${word((arg(1) << 64n) | chain.nonceOf(address(0), arg(1)))}`;
            if (sel === selector('getUserOpHash')) return hashPacked(decodeGetUserOpHash(data), entryPoint, chain.chainId);
            if (sel === selector('balanceOf')) return `0x${word(lower(address(0)) === paymaster ? chain.paymasterState.deposit : 0n)}`;
            if (sel === selector('handleOps')) {
                const { ops } = decodeHandleOps(data);
                const op = ops[0];
                const outcome = chain.dryRun?.(op, chain);
                if (outcome instanceof Error) throw outcome;
                if (outcome === 'ok') return '0x';
                if (!op.signature.length) throw revertError(failedOpData('AA24 signature error'));
                return '0x';
            }
            throw new Error(`unexpected EntryPoint read ${sel}`);
        }
        if (target === paymaster) {
            const state = chain.paymasterState;
            if (sel === selector('policy')) {
                return `0x${[state.policy.maxSponsoredCost, state.policy.flatFee, state.policy.minEscapeNet,
                    state.policy.escapesEnabled ? 1n : 0n, state.policy.sponsorshipPaused ? 1n : 0n].map(word).join('')}`;
            }
            if (sel === selector('maxFeeCeiling')) return `0x${word(state.maxFeeCeiling)}`;
            if (sel === selector('priorityFeeCeiling')) return `0x${word(state.priorityFeeCeiling)}`;
            if (sel === selector('gasPolicy')) return `0x${state.gasPolicyWords.map(word).join('')}`;
            if (sel === selector('callCap')) return `0x${word(state.callCap[Number(arg(0)) - 1])}`;
            if (sel === selector('attempts')) return `0x${word(state.attempts.get(`0x${word(arg(0))}`) ?? 0n)}`;
            if (sel === selector('owed')) return `0x${word(state.owed.get(lower(address(0))) ?? 0n)}`;
            if (sel === selector('stranded')) return `0x${word(state.stranded.get(lower(address(0))) ? 1n : 0n)}`;
            if (sel === selector('escapeNotePlusOne')) return `0x${word(state.escapeNotePlusOne.get(lower(address(0))) ?? 0n)}`;
            if (sel === selector('credits')) return `0x${word(state.credits.get(lower(address(0))) ?? 0n)}`;
            if (sel === selector('quote')) {
                return quote({ kind: arg(0), sender: address(1), noteIdValue: arg(2), nullifier: arg(3), maxCost: arg(4), maxFeePerGas: arg(5) });
            }
            if (sel === selector('vault')) return `0x${word(BigInt(vault))}`;
            if (sel === selector('factory')) return `0x${word(BigInt(factory))}`;
            if (sel === selector('entryPoint')) return `0x${word(BigInt(entryPoint))}`;
            if (sel === selector('WEI_PER_UNIT')) return `0x${word(1_000_000_000n)}`;
            if (sel === selector('transitAccount')) return `0x${word(BigInt(chain.transitAccount(address(0), address(1))))}`;
            throw new Error(`unexpected paymaster read ${sel}`);
        }
        if (target === factory) {
            if (sel === selector('getAddress')) return `0x${word(BigInt(chain.transitAccount(address(0), address(1))))}`;
            if (sel === selector('paymaster')) return `0x${word(BigInt(paymaster))}`;
            if (sel === selector('accountCreationCodeHash')) return lower(pins.account_creation_code_keccak256);
            if (sel === selector('implementation')) return `0x${word(BigInt(pins.withdrawal_account_implementation_address))}`;
            throw new Error(`unexpected factory read ${sel}`);
        }
        if (target === lower(vault)) {
            const state = chain.vaultState;
            if (sel === '9f18e4ed') {
                const note = state.notes.get(Number(arg(0)));
                return `0x${[0n, note?.deposit ?? 0n, 0n, BigInt(note?.status ?? 0)].map(word).join('')}`;
            }
            if (sel === 'a2f9f1ce') {
                const pending = state.pending.get(Number(arg(0)));
                if (!pending) return `0x${[0n, 0n, 0n, 0n, 0n, 0n].map(word).join('')}`;
                return `0x${[1n, pending.activeRoot ?? 0x11n, pending.nullifier, pending.finalBalance, BigInt(pending.destination), pending.challengeDeadline].map(word).join('')}`;
            }
            if (sel === 'f8ffe6e0') {
                const pending = state.pending.get(Number(arg(0)));
                return `0x${[pending?.nextNullifier ?? 0n, pending?.stateBalance ?? 0n, pending?.conceded ?? 0n].map(word).join('')}`;
            }
            if (sel === selector('paused')) return `0x${word(state.paused ? 1n : 0n)}`;
            if (sel === selector('pausedAt')) return `0x${word(state.pausedAt)}`;
            if (sel === 'fdab463d') return `0x${word(state.currentRoot)}`;
            if (sel === '7cb4a03c') return `0x${word(2_000_000_000n)}`;
            if (sel === '6cda756a') return `0x${word(0n)}`;
            if (sel === 'aad24061') return `0x${word(0n)}`;
            if (sel === '91f6e93a') return `0x${word(state.escapePayoutCredits.get(lower(address(0))) ?? 0n)}`;
            throw new Error(`unexpected vault read ${sel}`);
        }
        throw new Error(`unexpected eth_call to ${target}`);
    };
    const matches = (entry, filter) => {
        if (filter.address && lower(entry.address) !== lower(filter.address)) return false;
        const from = filter.fromBlock && filter.fromBlock !== 'earliest' ? Number(BigInt(filter.fromBlock)) : 0;
        if (Number(BigInt(entry.blockNumber)) < from) return false;
        for (const [index, wanted] of (filter.topics || []).entries()) {
            if (wanted == null) continue;
            const candidates = (Array.isArray(wanted) ? wanted : [wanted]).map(lower);
            if (!candidates.includes(lower(entry.topics[index]))) return false;
        }
        return true;
    };
    chain.request = async ({ method, params = [] }) => {
        chain.calls.push({ method, params: structuredClone(params) });
        if (chain.failing.has(method)) throw new Error(`scripted ${method} failure`);
        switch (method) {
            case 'eth_chainId': return hex(chain.chainId);
            case 'eth_blockNumber': return hex(chain.head);
            case 'eth_getBlockByNumber': {
                if (params[0] === 'finalized') return { number: hex(chain.finalized), timestamp: hex(chain.timestamp()) };
                return { number: hex(chain.head), baseFeePerGas: hex(chain.baseFee), timestamp: hex(chain.timestamp()) };
            }
            case 'eth_gasPrice': return hex(chain.baseFee + chain.priorityFee);
            case 'eth_maxPriorityFeePerGas':
                if (!chain.servesPriorityFee) throw new Error('method not found');
                return hex(chain.priorityFee);
            case 'eth_getCode': {
                const override = chain.codeHashOverride.get(lower(params[0]));
                return override ?? codeOf(params[0]);
            }
            case 'eth_getBalance': return hex(balanceOf(params[0]));
            case 'eth_call': return ethCall(params[0]);
            case 'eth_getLogs': return chain.logs.filter(entry => matches(entry, params[0]));
            case 'eth_getTransactionReceipt': return structuredClone(chain.receipts.get(lower(params[0])) ?? null);
            case 'eth_getTransactionByHash': return chain.receipts.has(lower(params[0])) ? { hash: lower(params[0]) } : null;
            default: throw new Error(`unexpected chain RPC ${method}`);
        }
    };
    let transactions = 0;
    /**
     * Include an operation: a bundle receipt with the EntryPoint's
     * UserOperationEvent (and UserOperationRevertReason when `success` is
     * false) and the vault/paymaster logs given; the nonce sequence advances,
     * S gets code when the op carried initCode, and `effects` adjusts the rest.
     */
    chain.mineUserOperation = ({ hash, op, success = true, revertReason = null, extraLogs = [], actualGasCost = 5_000_000_000_000_000n,
        actualGasUsed = 400_000n, effects = null, transactionHash: givenHash = null } = {}) => {
        const packed = op.factory !== undefined || op.callGasLimit !== undefined ? packedFromJson(op) : op;
        const nonce = BigInt(`0x${strip(packed.nonce)}`);
        chain.head += 1;
        transactions += 1;
        const transactionHash = givenHash || `0x${keccak256(`bundle-${transactions}-${hash}`).slice(2)}`;
        const entryPointLogs = [
            logs.userOperationEvent(entryPoint, { hash, sender: packed.sender, paymaster, nonce, success, actualGasCost, actualGasUsed }),
            ...(success ? [] : [logs.userOperationRevertReason(entryPoint, { hash, sender: packed.sender, nonce, reason: revertReason || '0x' })])
        ];
        const all = [...extraLogs, ...entryPointLogs].map((entry, index) => ({
            ...entry, blockNumber: hex(chain.head), transactionHash, logIndex: hex(index)
        }));
        const receipt = { transactionHash, blockNumber: hex(chain.head), status: '0x1', logs: all };
        chain.receipts.set(transactionHash, receipt);
        chain.logs.push(...all.filter(entry => lower(entry.address) === entryPoint));
        chain.setNonce(packed.sender, nonce >> 64n, (nonce & ((1n << 64n) - 1n)) + 1n);
        if (packed.initCode.length) chain.setCode(packed.sender, `0x${'36600060003760a0603d36396000600060a03601600073'}`);
        effects?.(chain, receipt);
        return { transactionHash, receipt, blockNumber: chain.head };
    };
    return chain;
}

// ---- the bundler ----

/**
 * An ERC-4337 bundler over fetch (JSON-RPC at `url`): asserts the exact v0.7
 * shape of every operation it takes, hashes it independently, and includes
 * it on the chain when `autoMine` is set; `hold`, `drop`, `forgetReceipts`,
 * `failSend` and `returnHash` script the failure scenarios.
 */
export function fakeBundler({ chain, url = BUNDLER_URL, entryPoint = chain.entryPoint, chainId = chain.chainId } = {}) {
    const bundler = {
        url,
        calls: [],
        sent: [],
        ops: new Map(),
        chainId,
        serveChainId: true,
        entryPoints: [lower(entryPoint)],
        estimate: null,
        hold: false,
        drop: false,
        forgetReceipts: false,
        failSend: null,
        returnHash: null,
        unreachable: false,
        unreachableMethods: new Set(),
        autoMine: null,
        // The bundler's own tip (wei), served as rundler_maxPriorityFeePerGas
        // or pimlico_getUserOperationGasPrice when set; unset, both are unknown methods.
        rundlerTip: null,
        pimlicoTip: null,
        onSend: null,
        onMethod: null,
        mined: new Map()
    };
    const rpcError = (code, message, data = null) => ({ error: { code, message, ...(data != null ? { data } : {}) } });
    bundler.handle = async ({ method, params = [] }) => {
        bundler.calls.push({ method, params: structuredClone(params) });
        await bundler.onMethod?.(method, params);
        switch (method) {
            case 'eth_chainId':
                if (!bundler.serveChainId) return rpcError(-32601, 'Method not found');
                return { result: hex(bundler.chainId) };
            case 'eth_supportedEntryPoints': return { result: bundler.entryPoints };
            case 'rundler_maxPriorityFeePerGas':
                if (bundler.rundlerTip == null) return rpcError(-32601, `Method not found: ${method}`);
                return { result: hex(bundler.rundlerTip) };
            case 'pimlico_getUserOperationGasPrice': {
                if (bundler.pimlicoTip == null) return rpcError(-32601, `Method not found: ${method}`);
                const tier = tip => ({ maxFeePerGas: hex(2n * chain.baseFee + tip), maxPriorityFeePerGas: hex(tip) });
                return { result: { slow: tier(bundler.pimlicoTip / 2n), standard: tier(bundler.pimlicoTip), fast: tier(bundler.pimlicoTip * 2n) } };
            }
            case 'eth_estimateUserOperationGas': {
                if (bundler.estimate instanceof Error) return rpcError(-32500, bundler.estimate.message);
                // Below every kind's cap (an estimate under the pinned defaults is ignored).
                return { result: bundler.estimate || { preVerificationGas: '0xc350', verificationGasLimit: '0x186a0', callGasLimit: '0x13880',
                    paymasterVerificationGasLimit: '0x6ddd0', paymasterPostOpGasLimit: '0x3d090' } };
            }
            case 'eth_sendUserOperation': {
                const [op, target] = params;
                assert.equal(lower(target), lower(entryPoint), 'the op names the pinned EntryPoint');
                assertUserOperationShape(op);
                const hash = userOperationHashFromJson(op, entryPoint, chainId);
                bundler.sent.push({ op: structuredClone(op), hash });
                if (bundler.failSend) {
                    const failure = typeof bundler.failSend === 'function' ? bundler.failSend(op, hash) : bundler.failSend;
                    if (failure) return rpcError(failure.code ?? -32500, failure.message, failure.data ?? null);
                }
                const hook = await bundler.onSend?.(op, hash);
                if (hook?.error) return rpcError(hook.error.code ?? -32500, hook.error.message, hook.error.data ?? null);
                if (!bundler.drop) bundler.ops.set(hash, { op: structuredClone(op), sentAt: Date.now() });
                if (bundler.autoMine && !bundler.hold && !bundler.drop) {
                    const script = typeof bundler.autoMine === 'function' ? bundler.autoMine(op, hash) : bundler.autoMine;
                    if (script) bundler.mine(hash, script);
                }
                return { result: bundler.returnHash || hash };
            }
            case 'eth_getUserOperationByHash': {
                const entry = bundler.ops.get(lower(params[0]));
                if (!entry) return { result: null };
                const mined = bundler.mined.get(lower(params[0]));
                return { result: { userOperation: entry.op, entryPoint, transactionHash: mined?.transactionHash ?? null,
                    blockNumber: mined ? hex(mined.blockNumber) : null } };
            }
            case 'eth_getUserOperationReceipt': {
                const mined = bundler.mined.get(lower(params[0]));
                if (!mined || bundler.forgetReceipts) return { result: null };
                return { result: { userOpHash: lower(params[0]), sender: mined.sender, success: mined.success,
                    receipt: { transactionHash: mined.transactionHash, blockNumber: hex(mined.blockNumber) } } };
            }
            default: return rpcError(-32601, `Method not found: ${method}`);
        }
    };
    bundler.fetch = async (target, init) => {
        assert.equal(target, bundler.url, 'the bundler URL');
        assert.equal(init.credentials, 'omit');
        const body = JSON.parse(init.body);
        if (bundler.unreachable || bundler.unreachableMethods.has(body.method)) {
            bundler.calls.push({ method: body.method, params: structuredClone(body.params), unreachable: true });
            throw new TypeError('fetch failed');
        }
        const answer = await bundler.handle(body);
        return { ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: body.id, ...answer }) };
    };
    bundler.request = async payload => {
        const answer = await bundler.handle(payload);
        if (answer.error) throw Object.assign(new Error(answer.error.message), { rpcCode: answer.error.code, data: answer.error.data ?? null });
        return answer.result;
    };
    /** Include a sent operation on the chain. */
    bundler.mine = (hash, script = {}) => {
        const entry = bundler.ops.get(lower(hash)) || bundler.sent.find(item => item.hash === lower(hash));
        assert.ok(entry, `the bundler knows ${hash}`);
        const mined = chain.mineUserOperation({ hash: lower(hash), op: entry.op, ...script });
        bundler.mined.set(lower(hash), { ...mined, sender: entry.op.sender, success: script.success !== false });
        return mined;
    };
    bundler.release = () => { bundler.hold = false; };
    return bundler;
}

/** The exact v0.7 unpacked JSON a bundler takes; factory fields only with initCode. */
export function assertUserOperationShape(op) {
    const quantity = /^0x([1-9a-f][0-9a-f]*|0)$/;
    const bytes = /^0x([0-9a-f]{2})*$/;
    const address = /^0x[0-9a-f]{40}$/;
    const required = ['sender', 'nonce', 'callData', 'callGasLimit', 'verificationGasLimit', 'preVerificationGas', 'maxFeePerGas',
        'maxPriorityFeePerGas', 'paymaster', 'paymasterVerificationGasLimit', 'paymasterPostOpGasLimit', 'paymasterData', 'signature'];
    const optional = ['factory', 'factoryData'];
    assert.deepEqual(Object.keys(op).filter(key => !optional.includes(key)).sort(), [...required].sort(), 'the v0.7 field names');
    assert.equal('factory' in op, 'factoryData' in op, 'factory and factoryData come together');
    for (const key of ['nonce', 'callGasLimit', 'verificationGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas',
        'paymasterVerificationGasLimit', 'paymasterPostOpGasLimit']) assert.match(op[key], quantity, `${key} is a 0x quantity`);
    for (const key of ['callData', 'paymasterData', 'signature', ...('factoryData' in op ? ['factoryData'] : [])]) assert.match(op[key], bytes, `${key} is hex bytes`);
    for (const key of ['sender', 'paymaster', ...('factory' in op ? ['factory'] : [])]) assert.match(op[key], address, `${key} is an address`);
    assert.equal(strip(op.paymasterData).length, 24, 'paymasterData is the 12-byte feeCapWei');
}

// ---- the wallet ----

/**
 * An EIP-1193 provider: eth_requestAccounts, eth_chainId and personal_sign
 * (a real secp256k1 signature of the EIP-191 digest, asserting the message is
 * the expected hash when one is set); every other method throws unless the
 * scenario allows it (`allow`), and eth_sendTransaction is recorded.
 */
export function fakeWallet({ owner, privateKey, chainId, chain = null, allow = [] } = {}) {
    const wallet = {
        owner: lower(owner),
        privateKey,
        signatures: [],
        sent: [],
        calls: [],
        allow: new Set(allow),
        expectedHash: null,
        rejectSign: false,
        gasPrice: null,
        async request({ method, params = [] }) {
            wallet.calls.push({ method, params: structuredClone(params) });
            if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [wallet.owner];
            if (method === 'eth_chainId') return hex(chainId);
            if (method === 'personal_sign') {
                const [message, from] = params;
                assert.equal(lower(from), wallet.owner, 'signs with the connected account');
                assert.match(message, /^0x[0-9a-f]{64}$/, 'signs the 32 raw bytes of the hash');
                if (wallet.expectedHash) assert.equal(lower(message), lower(wallet.expectedHash), 'the hash the SDK asked to sign');
                if (wallet.rejectSign) throw { code: 4001, message: 'User rejected the request.' };
                const prefix = new TextEncoder().encode('\x19Ethereum Signed Message:\n32');
                const digest = keccak256(Uint8Array.from([...prefix, ...hexBytes(message)]));
                const signature = sign(digest, wallet.privateKey);
                wallet.signatures.push({ message: lower(message), digest, signature });
                return signature;
            }
            if (method === 'eth_gasPrice' && wallet.gasPrice != null) return hex(wallet.gasPrice);
            if (method === 'eth_estimateGas' && wallet.allow.has('eth_estimateGas')) return '0x9c40';
            if (method === 'eth_getTransactionCount' && wallet.allow.has('eth_getTransactionCount')) return '0x5';
            if (method === 'eth_sendTransaction') {
                if (!wallet.allow.has('eth_sendTransaction')) throw new Error('the sponsored path never sends a transaction from the wallet');
                wallet.sent.push(structuredClone(params[0]));
                return wallet.onSend ? wallet.onSend(params[0]) : `0x${'ab'.repeat(32)}`;
            }
            if (wallet.allow.has(method) && chain) return chain.request({ method, params });
            throw new Error(`unexpected wallet RPC ${method}`);
        }
    };
    return wallet;
}
