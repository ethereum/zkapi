const CONTRACT_ERRORS = Object.freeze({
    '0x09bde339': {
        code: 'invalid_proof',
        message: 'The vault rejected the withdrawal proof. Refresh the page and prepare the withdrawal again.'
    },
    // StaleRoot(): a deposit's (or retirement's) siblings no longer match
    // the live root. Exits do no Merkle work on vault revision 3.
    '0x607447de': {
        code: 'stale_root',
        message: 'The vault changed while the deposit was being prepared. Its Merkle path must be refreshed.'
    },
    // UnknownRoot(): the vault never held the proof's root.
    '0x8c520116': {
        code: 'unknown_root',
        message: 'The vault does not know this withdrawal proof’s Merkle root. The proof must be generated again.'
    },
    // ChallengedNullifier(): an escape from this state was defeated by
    // successor evidence: another device spent the next state.
    '0x2845df70': {
        code: 'challenged_nullifier',
        message: 'An escape from this balance state was already defeated: another device spent its next state. Restore the newest backup or exit kit.'
    },
    // SupersededState(): an escape from the next state was defeated.
    '0x4e8225b5': {
        code: 'superseded_state',
        message: 'An escape from this balance’s next state was already defeated: another device holds a newer state.'
    },
    // ProofExpired(): the block is past the proof's valid_until.
    '0xb67a7713': {
        code: 'proof_expired',
        message: 'The withdrawal proof expired before it was included. It must be generated again.'
    },
    // WrongWithdrawalKind(): an ownership proof, or a close sent as an escape.
    '0x06868d53': {
        code: 'wrong_withdrawal_kind',
        message: 'The vault refused this kind of withdrawal proof.'
    },
    // InvalidDestination(): a zero payout address.
    '0xac6b05f5': {
        code: 'invalid_destination',
        message: 'The vault rejected the withdrawal address.'
    },
    // Paused(): the owner paused the vault (exits reopen after maxPauseDuration).
    '0x9e87fac8': {
        code: 'vault_paused',
        message: 'The vault is paused by its owner. Escapes and closes reopen at the latest when its pause limit ends.'
    },
    '0x947e59c5': {
        code: 'replayed_nullifier',
        message: 'This private state was already used or reserved. Check the withdrawal’s on-chain status before retrying.'
    },
    '0x61a83aab': {
        code: 'note_not_active',
        message: 'This private note is no longer active. Check its on-chain withdrawal status.'
    },
    '0xc52e3eff': {
        code: 'invalid_balance',
        message: 'The withdrawal balance is not valid for this private note.'
    },
    '0x9722445b': {
        code: 'invalid_deployment',
        message: 'The withdrawal proof does not match this zkAPI deployment.'
    },
    '0xd9876be8': {
        code: 'invalid_siblings',
        message: 'The vault rejected the withdrawal Merkle path. Prepare a fresh withdrawal and try again.'
    },
    '0x3be553f2': {
        code: 'not_pending_withdrawal',
        message: 'This note does not have an escape withdrawal waiting to be finalized.'
    },
    '0xf4b3b1bc': {
        code: 'native_transfer_failed',
        message: 'The vault could not return ETH to the withdrawal address.'
    },
    '0x2723e9c2': {
        code: 'invalid_native_value',
        message: 'The ETH transaction value does not match the private-note amount.'
    },
    '0x151f07fe': {
        code: 'challenge_not_expired',
        message: 'The escape safety window has not finished yet.'
    },
    // ZeroAmount(): for claimEscapePayout, the vault holds nothing for that
    // address; for the paymaster's claimCredit, no credited payout.
    '0x1f2a2005': {
        code: 'zero_amount',
        message: 'The vault has nothing to pay for this request.'
    },

    // ---- Gasless withdrawals (protocol/contracts/src/gasless). Each selector
    // is the keccak of the signature in its comment; a refusal of
    // validatePaymasterUserOp reaches the client as the inner bytes of an
    // AA33 FailedOpWithRevert (decodeEntryPointRevert below). ----
    // NotEntryPoint()
    '0xd663742a': { code: 'not_entry_point', message: 'Only the EntryPoint may call this contract.' },
    // SponsorshipPaused()
    '0x36592bab': { code: 'sponsorship_paused', message: 'The operator paused sponsored withdrawals. Pay the network fee from a wallet instead.' },
    // SponsorshipInFlight(bytes32)
    '0x15d072ef': { code: 'sponsorship_in_flight', message: 'A sponsored operation for this withdrawal is already in flight in this bundle.', args: ['key'] },
    // BadPaymasterData()
    '0xa1cf47c2': { code: 'bad_paymaster_data', message: 'The sponsored operation carries malformed paymaster data.' },
    // FeeAboveCap(uint256,uint256)
    '0x7159abd8': { code: 'gasless_fee_above_cap', message: 'The paymaster’s flat fee is above the fee cap this withdrawal accepted. Prepare it again with the current fee.', args: ['fee', 'cap'] },
    // FeeAboveCeiling()
    '0x81382d2e': { code: 'gas_above_paymaster_ceiling', message: 'Network fees are above what the paymaster sponsors right now. Try again later, or pay the fee from a wallet.' },
    // GasLimitOutOfRange(uint8,uint256,uint256,uint256)
    '0x0ce9cb2c': { code: 'gas_limit_out_of_range', message: 'The sponsored operation’s gas limits are outside the paymaster’s policy. Update this app.', args: ['field', 'value', 'floor', 'cap'] },
    // MaxCostAbovePolicy(uint256,uint256)
    '0x64bfcd47': { code: 'max_cost_above_policy', message: 'The sponsored operation would cost more than the paymaster’s policy allows. Try again at a lower fee, or pay the fee from a wallet.', args: ['maxCost', 'cap'] },
    // NotTransitAccount()
    '0x9ceec4c2': { code: 'not_transit_account', message: 'The sender of the sponsored operation is not a transit account of this deployment.' },
    // UnsupportedCall()
    '0xddcfed35': { code: 'unsupported_call', message: 'The paymaster does not sponsor this call.' },
    // WrongNonceKey()
    '0x3992194a': { code: 'wrong_nonce_key', message: 'The sponsored operation uses the wrong nonce key.' },
    // AttemptsExhausted(bytes32)
    '0x2e67b119': { code: 'gasless_attempts_exhausted', message: 'This balance state used its sponsored attempts. Pay the network fee from a wallet.', args: ['key'] },
    // BindingMismatch()
    '0x438c4873': { code: 'binding_mismatch', message: 'The withdrawal proof does not match this deployment.' },
    // DestinationNotSender()
    '0xedab562d': { code: 'destination_not_sender', message: 'The withdrawal proof does not pay the transit account.' },
    // InvalidValidUntil()
    '0x488b16b7': { code: 'invalid_valid_until', message: 'The withdrawal proof has no usable expiry.' },
    // NullifierUsed()
    '0x92814985': { code: 'nullifier_used', message: 'This private state was already used. Check the withdrawal’s on-chain status before retrying.' },
    // InvalidFelt()
    '0x2ab898cc': { code: 'invalid_felt', message: 'The withdrawal proof carries an invalid field element.' },
    // WrongKind()
    '0x35a08a07': { code: 'wrong_withdrawal_kind', message: 'The paymaster refused this kind of withdrawal proof.' },
    // BadSuccessor()
    '0x13549e75': { code: 'bad_successor', message: 'The escape proof does not name its successor nullifier.' },
    // EscapesDisabled()
    '0xead7d4d4': { code: 'escapes_disabled', message: 'The operator does not sponsor escape initiations. Start the escape from a wallet. Its finalization can be sponsored only when the escape pays this withdrawal’s transit account (it continues a sponsored withdrawal already proved for it); otherwise finalize it from the wallet as well.' },
    // EscapeAlreadySponsored(uint32)
    '0x7fcde504': { code: 'escape_already_sponsored', message: 'An escape of this balance was already sponsored once.', args: ['noteId'] },
    // EscapeEvidencePending(uint32)
    '0x0364d35f': { code: 'escape_evidence_pending', message: 'This transit account still has an open sponsored escape. Collect its payout first.', args: ['noteId'] },
    // PayoutBelowCost(uint256,uint256)
    '0x860123e1': { code: 'payout_below_gas', message: 'The payout does not cover the sponsored network fee. Pay the fee from a wallet instead.', args: ['required', 'available'] },
    // ExitsPaused(uint64)
    '0x28980b7e': { code: 'exits_paused', message: 'The vault is paused by its owner. Sponsored closes and escapes reopen at the latest when its pause limit ends.', args: ['reopenAt'] },
    // NotPendingEscape()
    '0x9c279d37': { code: 'not_pending_escape', message: 'This balance has no escape waiting to be finalized.' },
    // NotStranded()
    '0x8f50e417': { code: 'not_stranded', message: 'The paymaster has no record of a payout waiting in this transit account. Sweep it from a funded wallet instead.' },
    // NotRepayable()
    '0xed9e539b': { code: 'not_repayable', message: 'Only a transit account may forward funds to the paymaster.' },
    // CreditsReserved()
    '0xab518467': { code: 'credits_reserved', message: 'Credited payouts are reserved for their payees.' },
    // NotProxy()
    '0xbf10dd3a': { code: 'not_proxy', message: 'The transit account logic cannot be called directly.' },
    // VaultCallFailed(bytes)
    '0xc3076dea': { code: 'vault_call_failed', message: 'The vault refused the sponsored withdrawal.', args: ['reason'] },
    // NothingToSweep()
    '0x351261fc': { code: 'nothing_to_sweep', message: 'The transit account holds nothing to sweep.' },
    // UnknownCall()
    '0x35c169a5': { code: 'unknown_call', message: 'The transit account does not accept this call.' },
    // InvalidPayee()
    '0xb387a238': { code: 'invalid_payee', message: 'The payout address cannot be the vault, the paymaster, the EntryPoint, the factory or zero.' },
    // CreateFailed()
    '0x7e16b8cd': { code: 'create_failed', message: 'The transit account could not be created.' },
    // NotPaymasterOwner()
    '0x77a796bd': { code: 'not_paymaster_owner', message: 'Only the paymaster owner may do this.' },
    // StakeTermsLocked()
    '0x56129abc': { code: 'stake_terms_locked', message: 'Only the owner may set the stake terms.' },
    // InvalidKind()
    '0x2b79ed30': { code: 'invalid_kind', message: 'Unknown sponsored operation kind.' }
});

// The EntryPoint v0.7.0 reasons of FailedOp / FailedOpWithRevert, by their
// AA code (eth-infinitism/account-abstraction EntryPoint.sol). An AA33 maps
// the inner bytes through CONTRACT_ERRORS; the codes marked `silent` are
// handled by the client without a prompt (AA10: rebuild without initCode;
// AA25: re-read the nonce).
export const ENTRY_POINT_ERRORS = Object.freeze({
    AA10: { code: 'sender_already_constructed', message: 'The transit account already exists; the operation is rebuilt without its creation code.', silent: true },
    AA13: { code: 'init_code_failed', message: 'The transit account could not be created (its creation ran out of gas or reverted).' },
    AA14: { code: 'init_code_wrong_sender', message: 'The factory created an account at another address than the transit account.' },
    AA15: { code: 'init_code_no_sender', message: 'The factory did not create the transit account.' },
    AA20: { code: 'account_not_deployed', message: 'The transit account is not deployed and the operation carries no creation code.' },
    AA21: { code: 'account_prefund', message: 'The operation is not sponsored and the transit account holds no deposit.' },
    AA22: { code: 'account_time_window', message: 'The operation is outside the account’s validity window.' },
    AA23: { code: 'account_validation_reverted', message: 'The transit account’s validation reverted.' },
    AA24: { code: 'signature_rejected', message: 'The EntryPoint rejected the signature: the connected account is not the owner of this withdrawal’s transit account.' },
    AA25: { code: 'nonce_rejected', message: 'The operation’s nonce is no longer valid; it is rebuilt with the current one.', silent: true },
    AA26: { code: 'verification_gas_exceeded', message: 'The account’s validation needs more gas than the operation allows.' },
    AA30: { code: 'paymaster_not_deployed', message: 'The paymaster is not deployed at the pinned address.' },
    AA31: { code: 'paymaster_underfunded', message: 'The paymaster’s float cannot cover this operation right now. Try again later, or pay the fee from a wallet.' },
    AA32: { code: 'paymaster_time_window', message: 'The operation is outside the paymaster’s validity window: the proof expired, or the escape’s safety window has not finished.' },
    AA33: { code: 'paymaster_rejected', message: 'The paymaster refused to sponsor this operation.' },
    AA34: { code: 'paymaster_signature', message: 'The paymaster rejected the operation’s signature.' },
    AA36: { code: 'paymaster_verification_gas_exceeded', message: 'The paymaster’s validation needs more gas than the operation allows.' },
    AA40: { code: 'verification_gas_exceeded', message: 'The operation’s validation exceeded its gas limit.' },
    AA41: { code: 'verification_gas_exceeded', message: 'The operation’s validation exceeded its gas limit.' },
    AA50: { code: 'post_op_reverted', message: 'The paymaster’s settlement reverted. Report this to the operator.' },
    AA51: { code: 'prefund_too_low', message: 'The operation cost more than its prefund. Report this to the operator.' },
    AA90: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA91: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA92: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA93: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA94: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA95: { code: 'bundler_rejected', message: 'The bundler refused the operation.' },
    AA96: { code: 'bundler_rejected', message: 'The bundler refused the operation.' }
});

const FAILED_OP_SELECTOR = '0x220266b6';
const FAILED_OP_WITH_REVERT_SELECTOR = '0x65c8fd4d';
const ERROR_STRING_SELECTOR = '0x08c379a0';

function abiWordAt(hex, index) {
    const word = hex.slice(index * 64, (index + 1) * 64);
    return word.length === 64 ? BigInt(`0x${word}`) : null;
}

function abiBytesAt(hex, offsetWords) {
    const length = abiWordAt(hex, offsetWords);
    if (length == null || length > BigInt(hex.length / 2)) return null;
    const start = (offsetWords + 1) * 64;
    const size = Number(length) * 2;
    return hex.length >= start + size ? hex.slice(start, start + size) : null;
}

function utf8(hex) {
    try {
        return new TextDecoder().decode(Uint8Array.from(hex.match(/../g) || [], byte => parseInt(byte, 16)));
    } catch {
        return '';
    }
}

/** Every 0x-hex blob of at least 4 bytes reachable in an error value. */
function revertDataCandidates(error) {
    const found = [];
    const queue = [error];
    const seen = new Set();
    while (queue.length) {
        const value = queue.shift();
        if (value == null) continue;
        if (typeof value === 'string') {
            for (const match of value.matchAll(/0x[0-9a-fA-F]{8,}/g)) found.push(match[0].toLowerCase());
            try {
                queue.push(JSON.parse(value));
            } catch {
                // Plain provider text.
            }
            continue;
        }
        if (typeof value !== 'object' || seen.has(value)) continue;
        seen.add(value);
        for (const nested of Object.values(value)) queue.push(nested);
    }
    return found;
}

/**
 * The decoded arguments of a known custom error's revert data: the selector,
 * its code and message, and its static arguments (bigint; `reason` bytes as
 * hex) when CONTRACT_ERRORS names them. Null for unknown data.
 */
export function decodeContractRevert(data) {
    const hex = String(data || '').toLowerCase();
    if (!/^0x[0-9a-f]{8}/.test(hex)) return null;
    const selector = hex.slice(0, 10);
    const detail = CONTRACT_ERRORS[selector];
    if (!detail) {
        if (selector === ERROR_STRING_SELECTOR) {
            const reason = abiBytesAt(hex.slice(10), 1);
            return { selector, code: 'reverted', message: reason ? utf8(reason) : 'Reverted.', args: {} };
        }
        return null;
    }
    const args = {};
    const body = hex.slice(10);
    (detail.args || []).forEach((name, index) => {
        if (name === 'reason') {
            const bytes = abiBytesAt(body, Number(abiWordAt(body, index) ?? 0n) / 32);
            args[name] = bytes == null ? null : `0x${bytes}`;
        } else {
            const value = abiWordAt(body, index);
            args[name] = value == null ? null : (name === 'key' ? `0x${value.toString(16).padStart(64, '0')}` : value);
        }
    });
    return { selector, code: detail.code, message: detail.message, args };
}

/**
 * Decode the EntryPoint's FailedOp(opIndex, reason) or
 * FailedOpWithRevert(opIndex, reason, inner) from an error or revert data:
 * { opIndex, reason, aa, inner, innerError }. The AA code is the reason's
 * leading "AAnn" token; a known inner custom error is decoded. Null when the
 * value carries neither.
 */
export function decodeEntryPointRevert(errorOrData) {
    for (const hex of revertDataCandidates(errorOrData)) {
        const selector = hex.slice(0, 10);
        if (selector !== FAILED_OP_SELECTOR && selector !== FAILED_OP_WITH_REVERT_SELECTOR) continue;
        const body = hex.slice(10);
        const opIndex = abiWordAt(body, 0);
        const reasonOffset = abiWordAt(body, 1);
        if (opIndex == null || reasonOffset == null || reasonOffset % 32n !== 0n) continue;
        const reasonHex = abiBytesAt(body, Number(reasonOffset / 32n));
        const reason = reasonHex == null ? '' : utf8(reasonHex);
        const match = /^(AA\d\d)\b/.exec(reason);
        let inner = null;
        if (selector === FAILED_OP_WITH_REVERT_SELECTOR) {
            const innerOffset = abiWordAt(body, 2);
            const innerHex = innerOffset != null && innerOffset % 32n === 0n ? abiBytesAt(body, Number(innerOffset / 32n)) : null;
            inner = innerHex ? `0x${innerHex}` : null;
        }
        return {
            opIndex: Number(opIndex),
            reason,
            aa: match ? match[1] : null,
            inner,
            innerError: inner ? decodeContractRevert(inner) : null
        };
    }
    return null;
}

/**
 * An error for a failed EntryPoint dry run (eth_call handleOps) or a bundler
 * refusal: the AA code's message and code, refined by a known inner custom
 * error for AA33. `error.data` carries the decoded details; `error.silent`
 * marks the refusals the client handles without a prompt (AA10, AA25).
 */
export function entryPointError(error) {
    const decoded = decodeEntryPointRevert(error);
    if (!decoded) {
        const selector = contractRevertSelector(error);
        if (selector) {
            const detail = decodeContractRevert(selector) || CONTRACT_ERRORS[selector];
            const wrapped = new Error(detail.message);
            wrapped.name = 'ZkapiEntryPointError';
            wrapped.code = detail.code;
            wrapped.shortMessage = detail.message;
            wrapped.selector = selector;
            wrapped.data = { ...(detail.args || {}) };
            wrapped.cause = error;
            return wrapped;
        }
        return null;
    }
    const aa = decoded.aa ? ENTRY_POINT_ERRORS[decoded.aa] : null;
    const inner = decoded.innerError;
    const detail = decoded.aa === 'AA33' && inner ? inner
        : aa || { code: 'entry_point_rejected', message: `The EntryPoint refused the operation (${decoded.reason || 'unknown reason'}).` };
    const wrapped = new Error(detail.message);
    wrapped.name = 'ZkapiEntryPointError';
    wrapped.code = detail.code;
    wrapped.shortMessage = detail.message;
    wrapped.aa = decoded.aa;
    wrapped.reason = decoded.reason;
    wrapped.silent = Boolean(aa?.silent);
    wrapped.selector = inner?.selector || null;
    wrapped.data = { opIndex: decoded.opIndex, aa: decoded.aa, reason: decoded.reason, inner: decoded.inner, ...(inner?.args || {}) };
    wrapped.cause = error;
    return wrapped;
}

function matchingSelector(value) {
    if (typeof value !== 'string') return null;
    for (const match of value.matchAll(/0x[0-9a-fA-F]{8,}/g)) {
        const selector = match[0].slice(0, 10).toLowerCase();
        if (CONTRACT_ERRORS[selector]) return selector;
    }
    return null;
}

export function contractRevertSelector(error) {
    const queue = [error];
    const seen = new Set();
    while (queue.length) {
        const value = queue.shift();
        if (value == null || seen.has(value)) continue;
        if (typeof value === 'string') {
            const selector = matchingSelector(value);
            if (selector) return selector;
            try {
                queue.push(JSON.parse(value));
            } catch {
                // Most provider messages are plain text rather than JSON.
            }
            continue;
        }
        if (typeof value !== 'object') continue;
        seen.add(value);
        for (const nested of Object.values(value)) queue.push(nested);
    }
    return null;
}

export function contractEstimateError(error) {
    const selector = contractRevertSelector(error);
    const detail = selector ? CONTRACT_ERRORS[selector] : null;
    const providerMessage = error?.shortMessage || error?.message || String(error);
    const wrapped = new Error(detail?.message
        || `Transaction simulation failed: ${providerMessage}`);
    wrapped.name = 'ZkapiContractError';
    wrapped.code = detail?.code || 'gas_estimation_failed';
    wrapped.selector = selector;
    wrapped.cause = error;
    return wrapped;
}
