// The operator's close relay, from the browser wallet's side (serverd's
// close relay: GET /v2/withdraw/relay/terms, POST /v2/withdraw/relay/fee,
// POST /v2/withdraw/relay, GET /v2/withdraw/relay/{N}).
//
// Relay mode is opt-in. The fee is one ordinary metered request at the note's
// current state, made before the withdrawal is prepared, whose payload is
// `closeRelayFeePayload(fee, secret)`: its successor carries the fee as spent,
// so the cooperative close proved at that successor pays the fee inside its
// treasury share (no circuit change). Only the hash of the ticket secret is
// in the request; the secret goes with the close (`submitCloseRelay`), and
// redeems that one fee once.
//
// The relay cannot redirect the payout (the proof binds destination and
// amount) and never holds funds. The wallet keeps the proof:
// `followCloseRelay` submits it through the wallet's own path once the relay
// gives it back or has not landed it by valid_until minus a margin, and the
// withdrawal stays pending until the vault's MutualClose event for it is
// seen (`mutualCloseLogMatches`).
import { hexBytes, keccak256 } from './zkapiKeccak.mjs';

export const CLOSE_RELAY_FEE_MODE = 'close_relay_fee';
export const CLOSE_RELAY_FEE_VERSION = 1;
const TICKET_DOMAIN = new TextEncoder().encode('zkapi:v2c:close-relay-ticket\0');
/** keccak256("MutualClose(uint32,uint256,uint128,address)"). */
export const MUTUAL_CLOSE_TOPIC = '0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031';
/**
 * Seconds before valid_until at which the wallet stops waiting for the relay
 * and submits the close itself: below the relay's default urgent margin
 * (1800 s, when it sends at once), above its default cutoff (300 s).
 */
export const DEFAULT_SELF_SUBMIT_MARGIN_SECONDS = 1_200;
export const DEFAULT_POLL_MS = 30_000;
const STATUSES = new Set(['queued', 'submitted', 'landed', 'closed', 'failed', 'expired', 'unknown']);

function secretBytes(secret) {
    const bytes = secret instanceof Uint8Array ? secret : hexBytes(secret);
    if (bytes.length !== 32) throw new Error('A close relay ticket secret is 32 bytes.');
    return bytes;
}

/** A fresh 32-byte ticket secret as 0x-prefixed hex (keep it with the note). */
export function newTicketSecret(random = globalThis.crypto) {
    const bytes = new Uint8Array(32);
    random.getRandomValues(bytes);
    return `0x${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

/** keccak256(domain || secret): the ticket's public handle. */
export function closeRelayTicketHash(secret) {
    const bytes = secretBytes(secret);
    const input = new Uint8Array(TICKET_DOMAIN.length + 32);
    input.set(TICKET_DOMAIN);
    input.set(bytes, TICKET_DOMAIN.length);
    return keccak256(input);
}

/**
 * The fee request's canonical payload, byte for byte what the server parses
 * (field order mode, version, fee_units, ticket_hash).
 */
export function closeRelayFeePayload(feeUnits, secret) {
    const fee = BigInt(feeUnits);
    if (fee <= 0n) throw new Error('The close relay fee must be positive.');
    return JSON.stringify({
        mode: CLOSE_RELAY_FEE_MODE,
        version: CLOSE_RELAY_FEE_VERSION,
        fee_units: fee.toString(),
        ticket_hash: closeRelayTicketHash(secret)
    });
}

function relayUrl(serverUrl, path) {
    return `${String(serverUrl).replace(/\/+$/, '')}${path}`;
}

async function readJson(response) {
    const text = await response.text();
    try {
        return text ? JSON.parse(text) : null;
    } catch {
        return null;
    }
}

function relayError(response, body) {
    const error = new Error(body?.error_message || `close relay request failed (HTTP ${response.status})`);
    error.code = body?.error_code || 'close_relay_failed';
    error.status = response.status;
    return error;
}

function defaultFetch(url, init) {
    return globalThis.fetch(url, { ...init, credentials: 'omit', redirect: 'error' });
}

/** The relay's terms: `{ enabled: false }` when the server does not relay. */
export async function fetchCloseRelayTerms(serverUrl, { fetchImpl = defaultFetch } = {}) {
    const response = await fetchImpl(relayUrl(serverUrl, '/v2/withdraw/relay/terms'), { method: 'GET' });
    const body = await readJson(response);
    if (!response.ok || typeof body?.enabled !== 'boolean') throw relayError(response, body);
    if (body.enabled && !/^[1-9][0-9]*$/.test(String(body.fee_units ?? ''))) {
        throw new Error('The relay terms name no valid fee.');
    }
    return body;
}

/**
 * POST the proved fee request (an ApiRequestV2 whose payload is
 * `closeRelayFeePayload`); returns the signed successor (RequestResponseV2),
 * which the wallet verifies and installs like any request's.
 */
export async function payCloseRelayFee(serverUrl, request, { fetchImpl = defaultFetch } = {}) {
    const response = await fetchImpl(relayUrl(serverUrl, '/v2/withdraw/relay/fee'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request)
    });
    const body = await readJson(response);
    if (!response.ok) throw relayError(response, body);
    return body;
}

function relayStatus(body) {
    if (!STATUSES.has(body?.status)) throw new Error('Invalid close relay status.');
    return body;
}

/**
 * Hand the proved cooperative close (the kind-1 statement and proof exactly
 * as mutualClose takes them) to the relay with its ticket secret. The same
 * close again returns its status.
 */
export async function submitCloseRelay(serverUrl, { publicInputs, proof, ticketSecret }, { fetchImpl = defaultFetch } = {}) {
    secretBytes(ticketSecret);
    const response = await fetchImpl(relayUrl(serverUrl, '/v2/withdraw/relay'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ public_inputs: publicInputs, proof, ticket_secret: ticketSecret })
    });
    const body = await readJson(response);
    if (!response.ok) throw relayError(response, body);
    return relayStatus(body);
}

/** The relay's status of the close at `withdrawalNullifier` (`unknown` if none). */
export async function closeRelayStatus(serverUrl, withdrawalNullifier, { fetchImpl = defaultFetch } = {}) {
    const response = await fetchImpl(relayUrl(serverUrl, `/v2/withdraw/relay/${withdrawalNullifier}`), { method: 'GET' });
    const body = await readJson(response);
    if (response.status === 404 && body?.status === 'not_found') return { status: 'unknown', self_submit: false };
    if (!response.ok) throw relayError(response, body);
    return relayStatus(body);
}

/**
 * The wallet's rule for a relayed close valid until `validUntil` (seconds):
 * 'confirm' once the relay reports it landed or closed (the wallet then waits
 * for the MutualClose event itself), 'self_submit' once the relay gives it
 * back (failed, expired) or once now is within `margin` of validUntil,
 * 'resubmit' for a close the relay does not hold, otherwise 'wait'. A status
 * that could not be read (null) counts as no landing.
 */
export function decideCloseRelay(status, validUntil, nowSeconds, marginSeconds = DEFAULT_SELF_SUBMIT_MARGIN_SECONDS) {
    const late = nowSeconds >= Number(validUntil) - marginSeconds;
    if (status) {
        if (status.status === 'landed' || status.status === 'closed') return 'confirm';
        if (status.self_submit === true || status.status === 'failed' || status.status === 'expired') return 'self_submit';
        if (late) return 'self_submit';
        if (status.status === 'unknown') return 'resubmit';
        return 'wait';
    }
    return late ? 'self_submit' : 'wait';
}

/**
 * Follow a relayed close until the vault's MutualClose event for it is seen
 * ('relayed'), or until the wallet submits it itself ('self_submitted').
 * `closeSeen` reads the event through the wallet's own RPC; `selfSubmit`
 * is the wallet's ordinary (wallet-paid or gasless) close path.
 */
export async function followCloseRelay({
    status,
    resubmit,
    closeSeen,
    selfSubmit,
    validUntil,
    now = () => Math.floor(Date.now() / 1000),
    sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
    pollMs = DEFAULT_POLL_MS,
    marginSeconds = DEFAULT_SELF_SUBMIT_MARGIN_SECONDS,
    signal
}) {
    const seen = async () => {
        try {
            return (await closeSeen()) === true;
        } catch {
            return false;
        }
    };
    const submitSelf = async () => {
        // The event may have appeared meanwhile: never send a close that
        // would only revert.
        if (await seen()) return 'relayed';
        await selfSubmit();
        return 'self_submitted';
    };
    for (;;) {
        if (signal?.aborted) throw signal.reason ?? new Error('aborted');
        if (await seen()) return 'relayed';
        let current = null;
        try {
            current = await status();
        } catch {
            current = null;
        }
        const action = decideCloseRelay(current, validUntil, now(), marginSeconds);
        if (action === 'self_submit') return submitSelf();
        if (action === 'resubmit' && resubmit) {
            try {
                await resubmit();
            } catch {
                // Read again next poll; the deadline still applies.
            }
        }
        if (action === 'confirm' && now() >= Number(validUntil) - marginSeconds) return submitSelf();
        await sleep(pollMs);
    }
}

function word(value) {
    return BigInt(value).toString(16).padStart(64, '0');
}

/**
 * Whether `logs` (receipt or eth_getLogs entries) hold the vault's MutualClose
 * of exactly this close: emitted by `vault`, for `noteId`, at `nullifier`,
 * paying `finalBalance` (native units) to `destination`. Which transaction
 * carried it (the relay's batch or anyone's) does not matter.
 */
export function mutualCloseLogMatches(logs, { vault, noteId, nullifier, finalBalance, destination }) {
    const data = `0x${word(nullifier)}${word(finalBalance)}${word(destination)}`;
    const note = `0x${word(noteId)}`;
    return (logs || []).some(log => log
        && log.removed !== true
        && String(log.address).toLowerCase() === String(vault).toLowerCase()
        && Array.isArray(log.topics) && log.topics.length === 2
        && String(log.topics[0]).toLowerCase() === MUTUAL_CLOSE_TOPIC
        && String(log.topics[1]).toLowerCase() === note
        && String(log.data).toLowerCase() === data);
}

/**
 * The relay fee authorization of a prepared request (an ApiRequestV2), or
 * null for any other request (a lease).
 */
export function closeRelayFeeOf(request) {
    let payload;
    try {
        payload = typeof request?.payload === 'string' ? JSON.parse(request.payload) : request?.payload;
    } catch {
        return null;
    }
    if (payload?.mode !== CLOSE_RELAY_FEE_MODE || payload?.version !== CLOSE_RELAY_FEE_VERSION
        || !/^[1-9][0-9]*$/.test(String(payload.fee_units ?? ''))
        || !/^0x[0-9a-f]{64}$/.test(String(payload.ticket_hash ?? ''))) return null;
    return { feeUnits: String(payload.fee_units), ticketHash: payload.ticket_hash };
}

/**
 * The server answers an exact retry of a request only while its request_time
 * is fresh (300 s, plus 30 s of skew). A relay fee request older than this,
 * whose nullifier the server reports unknown, can never be admitted any more,
 * so its journal may be set aside.
 */
export const RELAY_FEE_UNADMITTABLE_AFTER_SECONDS = 600;
