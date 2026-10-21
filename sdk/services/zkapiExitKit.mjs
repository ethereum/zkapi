// The browser exit kit (design §6.4 E7): an encrypted, user-held copy of
// everything an escape needs without the browser host, the operator or its
// indexer. `zkapi-walletd exit-kit escape --kit <file>` (WP-E) runs E4 from it.
//
// Envelope (JSON):
//   { format: 'zkapi-exit-kit-v1',
//     kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: <base64, 16 bytes> },
//     cipher: { name: 'AES-256-GCM', iv: <base64, 12 bytes> },
//     ciphertext: <base64> }
// The AES-GCM additional data is the UTF-8 format string. The plaintext is
// the JSON payload of buildExitKitPayload.

export const EXIT_KIT_FORMAT = 'zkapi-exit-kit-v1';
export const EXIT_KIT_PBKDF2_ITERATIONS = 600_000;
export const EXIT_KIT_MIN_PASSPHRASE_LENGTH = 10;

// The note state fields an escape proof needs (the companion's NoteState
// names): s, note_id, D, expiry, B, r, τ, τ_prev, σ and the commitment.
const NOTE_FIELDS = Object.freeze(['protocol_version', 'chain_id', 'contract_address', 'note_id', 'secret_s',
    'deposit_amount', 'expiry_ts', 'current_balance', 'balance_blinding', 'current_commitment_x',
    'current_commitment_y', 'current_anchor', 'prev_anchor', 'is_genesis', 'state_signature']);

function kitError(message, code) {
    return Object.assign(new Error(message), { code });
}

function base64(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function unbase64(value, label) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
        throw kitError(`The exit kit's ${label} is not base64.`, 'exit_kit_invalid');
    }
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

function subtle(cryptoImpl) {
    const value = cryptoImpl?.subtle;
    if (!value) throw kitError('This browser has no WebCrypto, so it cannot encrypt an exit kit.', 'exit_kit_unavailable');
    return value;
}

async function deriveKey(cryptoImpl, passphrase, salt, iterations) {
    const material = await subtle(cryptoImpl).importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2',
        false, ['deriveKey']);
    return subtle(cryptoImpl).deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * The kit's plaintext: the build-pinned trusted_deployment profile, the note
 * state an escape needs, bound_at_state, the state's sequence number and the
 * export time. `merklePath` is the deposit-time path at a root the vault
 * holds (Amendment A1), when the wallet saved one.
 */
export function buildExitKitPayload({ trustedDeployment, state, stateSeq, exportedAt, merklePath = null }) {
    if (!trustedDeployment || typeof trustedDeployment !== 'object') {
        throw kitError('An exit kit needs the build-pinned deployment profile.', 'exit_kit_invalid');
    }
    if (!state || state.secret_s == null || state.note_id == null) {
        throw kitError('There is no private balance to put in an exit kit.', 'exit_kit_invalid');
    }
    const note = {};
    for (const field of NOTE_FIELDS) note[field] = state[field] ?? null;
    return {
        format: EXIT_KIT_FORMAT,
        trusted_deployment: structuredClone(trustedDeployment),
        note,
        bound_at_state: String(state.bound_at_state ?? 0),
        state_seq: Number(stateSeq) || 0,
        exported_at: Number(exportedAt),
        merkle_path: merklePath?.active_root != null && Array.isArray(merklePath.siblings)
            ? { active_root: String(merklePath.active_root), siblings: merklePath.siblings.map(String) }
            : null
    };
}

/** Encrypt an exit kit payload with a passphrase. */
export async function sealExitKit(payload, passphrase, { crypto: cryptoImpl = globalThis.crypto,
    iterations = EXIT_KIT_PBKDF2_ITERATIONS } = {}) {
    if (typeof passphrase !== 'string' || passphrase.length < EXIT_KIT_MIN_PASSPHRASE_LENGTH) {
        throw kitError(`Choose an exit-kit passphrase of at least ${EXIT_KIT_MIN_PASSPHRASE_LENGTH} characters.`,
            'exit_kit_passphrase_weak');
    }
    if (payload?.format !== EXIT_KIT_FORMAT) throw kitError('The exit kit payload has another format.', 'exit_kit_invalid');
    const salt = cryptoImpl.getRandomValues(new Uint8Array(16));
    const iv = cryptoImpl.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(cryptoImpl, passphrase, salt, iterations);
    const ciphertext = new Uint8Array(await subtle(cryptoImpl).encrypt({ name: 'AES-GCM', iv,
        additionalData: new TextEncoder().encode(EXIT_KIT_FORMAT) }, key, new TextEncoder().encode(JSON.stringify(payload))));
    return {
        format: EXIT_KIT_FORMAT,
        kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: base64(salt) },
        cipher: { name: 'AES-256-GCM', iv: base64(iv) },
        ciphertext: base64(ciphertext)
    };
}

/** Decrypt an exit kit; a wrong passphrase or any change fails. */
export async function openExitKit(envelope, passphrase, { crypto: cryptoImpl = globalThis.crypto } = {}) {
    const kit = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
    if (kit?.format !== EXIT_KIT_FORMAT || kit.kdf?.name !== 'PBKDF2' || kit.kdf.hash !== 'SHA-256'
        || kit.cipher?.name !== 'AES-256-GCM' || !Number.isSafeInteger(kit.kdf.iterations)
        || kit.kdf.iterations < 100_000) {
        throw kitError('This file is not a zkapi-exit-kit-v1 exit kit.', 'exit_kit_invalid');
    }
    const key = await deriveKey(cryptoImpl, String(passphrase ?? ''), unbase64(kit.kdf.salt, 'salt'), kit.kdf.iterations);
    let plaintext;
    try {
        plaintext = await subtle(cryptoImpl).decrypt({ name: 'AES-GCM', iv: unbase64(kit.cipher.iv, 'iv'),
            additionalData: new TextEncoder().encode(EXIT_KIT_FORMAT) }, key, unbase64(kit.ciphertext, 'ciphertext'));
    } catch {
        throw kitError('The passphrase is wrong or the exit kit was changed.', 'exit_kit_passphrase');
    }
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    if (payload?.format !== EXIT_KIT_FORMAT) throw kitError('The exit kit payload has another format.', 'exit_kit_invalid');
    return payload;
}
