// ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount, uint256 newRoot)
// claimExpired closes the note and sends its entire deposit to the service treasury.
export const EXPIRED_CLAIMED_TOPIC = '0x5534ce4a9fb7fe545375064cc186660ac10ba2152cb1592b29b244d2fe169ae4';
const HASH = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const integer = value => Number.isSafeInteger(value) && value >= 0;
const seconds = value => integer(value) && value > 0 && value * 1000 <= 8.64e15;
const hex = value => `0x${value.toString(16)}`;

class ExpiryHistoryValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ExpiryHistoryValidationError';
        this.code = 'expiry_history_invalid_event';
    }
}

function quantity(value) {
    if (typeof value !== 'string' || !QUANTITY.test(value)) return null;
    const number = Number(BigInt(value));
    return integer(number) ? number : null;
}

function confirmedClaim(deposit) {
    const claim = deposit.expiryClaim;
    return claim && seconds(deposit.expiryTs) && integer(claim.amount) && claim.amount > 0
        && claim.amount === deposit.amount && integer(claim.blockNumber)
        && HASH.test(claim.transactionHash || '') && HASH.test(claim.blockHash || '')
        && integer(claim.claimedAt) && claim.claimedAt >= deposit.expiryTs * 1000
        && claim.claimedAt <= 8.64e15 ? claim : null;
}

export function deriveExpiryRecords(deposits = [], withdrawals = [], nowMs = Date.now()) {
    return deposits.flatMap(deposit => {
        if (deposit.status !== 'confirmed' || !seconds(deposit.expiryTs)) return [];
        const claim = confirmedClaim(deposit);
        if (!claim && (!Number.isFinite(nowMs) || deposit.expiryTs * 1000 > nowMs || withdrawals.some(record =>
            record.deploymentId === deposit.deploymentId && record.noteId === deposit.noteId
            // A credited escape closed the note too: the vault holds its
            // payout for the destination, so expiry can no longer claim it.
            && (((record.payoutVerified === true || record.payoutCredited === true)
                && ['closed', 'closed_unconfirmed'].includes(record.phase))
                || (record.mode === 'escape'
                && record.chainStatus === 'pending_withdrawal' && integer(record.startBlockNumber)
                && record.startBlockNumber > 0 && integer(record.finalizedBlockNumber)
                && record.finalizedBlockNumber >= record.startBlockNumber))))) return [];
        return [{
            recordId: `${deposit.recordId}:expiry`, type: 'expiry',
            status: claim ? 'claimed' : 'expired', deploymentId: deposit.deploymentId,
            noteId: deposit.noteId, expiryTs: deposit.expiryTs,
            createdAt: claim?.claimedAt ?? deposit.expiryTs * 1000,
            amount: claim?.amount ?? null, claimedAt: claim?.claimedAt ?? null,
            transactionHash: claim?.transactionHash ?? null,
            blockHash: claim?.blockHash ?? null, blockNumber: claim?.blockNumber ?? null,
            detail: claim ? 'Claimed by the service treasury. This was not a refund.'
                : 'No automatic refund. Expiry alone does not transfer funds.'
        }];
    });
}

function parsedLog(log, vaultAddress, from, to) {
    if (String(log?.address || '').toLowerCase() !== vaultAddress
        || String(log?.topics?.[0] || '').toLowerCase() !== EXPIRED_CLAIMED_TOPIC) return null;
    // Once an event matches the public vault/topic, dropping malformed data
    // would permanently skip a possible claim when the caller saves its cursor.
    if (log.removed !== false || !Array.isArray(log.topics) || log.topics.length !== 2
        || !HASH.test(log.topics[1]) || !/^0x[0-9a-f]{128}$/i.test(log.data || '')
        || !HASH.test(log.transactionHash || '') || !HASH.test(log.blockHash || '')) {
        throw new ExpiryHistoryValidationError('The RPC returned a malformed or removed expiry event. Retry the scan.');
    }
    const noteId = Number(BigInt(log.topics[1]));
    // Public deposits may exceed this UI's safe-integer amount range. Retain
    // their exact uint128 value while validating every event's canonical block.
    const amount = BigInt(`0x${log.data.slice(2, 66)}`);
    const blockNumber = quantity(log.blockNumber);
    if (!integer(noteId) || noteId > 0xffffffff || amount <= 0n || amount > (1n << 128n) - 1n
        || blockNumber == null || blockNumber < from || blockNumber > to) {
        throw new ExpiryHistoryValidationError('The RPC returned invalid expiry event values. Retry the scan.');
    }
    return { noteId, amount, blockNumber, transactionHash: log.transactionHash.toLowerCase(),
        blockHash: log.blockHash.toLowerCase() };
}

function validatedBlock(block, expectedNumber = null) {
    const number = quantity(block?.number);
    const timestamp = quantity(block?.timestamp);
    if (number == null || (expectedNumber != null && number !== expectedNumber)
        || !seconds(timestamp) || !HASH.test(block?.hash || '')) {
        throw new Error('The RPC returned an invalid finalized expiry block.');
    }
    return { number, timestamp, hash: block.hash.toLowerCase() };
}

// This discovery uses only the public contract address and public block heights.
async function firstContractBlock(request, vaultAddress, head) {
    const exists = async number => {
        const code = await request({ method: 'eth_getCode', params: [vaultAddress, hex(number)] });
        if (!/^0x(?:[0-9a-f]{2})*$/i.test(code || '')) throw new Error('Invalid vault bytecode response.');
        return code !== '0x';
    };
    if (!await exists(head)) throw new Error('The vault has no code at the finalized block.');
    let low = 0;
    let high = head;
    while (low < high) {
        const middle = low + Math.floor((high - low) / 2);
        if (await exists(middle)) high = middle;
        else low = middle + 1;
    }
    return low;
}

/** Read only public, finalized expiry events. No account, note lookup, or wallet mutation RPCs.
 * A partial result advances only through completely scanned and validated public blocks.
 */
export async function readFinalizedExpiryClaims({ request, vaultAddress, chainId, deposits = [],
    fromBlock = 0, deploymentBlock = null, chunkSize = 10_000, maxLogRequests = 128,
    maxBlockRequests = 256 }) {
    if (typeof request !== 'function' || !ADDRESS.test(vaultAddress || '') || !integer(chainId)
        || chainId === 0 || !integer(fromBlock) || !integer(chunkSize) || chunkSize === 0
        || !integer(maxLogRequests) || maxLogRequests === 0 || !integer(maxBlockRequests)
        || maxBlockRequests === 0 || (deploymentBlock != null && !integer(deploymentBlock))) {
        throw new Error('Invalid public expiry-history request.');
    }
    vaultAddress = vaultAddress.toLowerCase();
    if (quantity(await request({ method: 'eth_chainId', params: [] })) !== chainId) {
        throw new Error('Switch to the configured network before checking expiry history.');
    }
    const head = validatedBlock(await request({ method: 'eth_getBlockByNumber', params: ['finalized', false] }));
    let scannedTo = fromBlock - 1;
    let logRequests = 0;
    const load = async (from, to) => {
        logRequests += 1;
        const logs = await request({ method: 'eth_getLogs', params: [{ address: vaultAddress,
            topics: [EXPIRED_CLAIMED_TOPIC], fromBlock: hex(from), toBlock: hex(to) }] });
        if (!Array.isArray(logs)) throw new ExpiryHistoryValidationError('The RPC returned invalid expiry logs.');
        return logs.map(log => parsedLog(log, vaultAddress, from, to)).filter(Boolean);
    };
    let logs = [];
    if (fromBlock <= head.number) {
        try { logs = await load(fromBlock, head.number); scannedTo = head.number; }
        catch (error) {
            if (error instanceof ExpiryHistoryValidationError) throw error;
            deploymentBlock ??= await firstContractBlock(request, vaultAddress, head.number);
            let next = Math.max(fromBlock, deploymentBlock);
            scannedTo = next - 1;
            let size = chunkSize;
            while (next <= head.number && logRequests < maxLogRequests) {
                const end = Math.min(head.number, next + size - 1);
                try {
                    logs.push(...await load(next, end));
                    scannedTo = end;
                    next = end + 1;
                } catch (error) {
                    if (error instanceof ExpiryHistoryValidationError || size === 1) throw error;
                    size = Math.max(1, Math.floor(size / 2));
                }
            }
        }
    }
    logs.sort((left, right) => left.blockNumber - right.blockNumber);
    const blocks = new Map();
    const canonicalLogs = [];
    // Read block timestamps for every public event, before any owned-note
    // filtering. Selecting block RPCs by owned notes would leak that ownership.
    for (const log of logs) {
        if (!blocks.has(log.blockNumber)) {
            if (blocks.size >= maxBlockRequests) { scannedTo = log.blockNumber - 1; break; }
            const block = validatedBlock(await request({ method: 'eth_getBlockByNumber',
                params: [hex(log.blockNumber), false] }), log.blockNumber);
            blocks.set(log.blockNumber, block);
        }
        const block = blocks.get(log.blockNumber);
        if (block.hash !== log.blockHash || block.timestamp > head.timestamp) {
            throw new Error('Expiry history changed during the finalized block check. Retry the scan.');
        }
        canonicalLogs.push({ ...log, claimedAt: block.timestamp * 1000 });
    }
    const checkedHead = validatedBlock(await request({ method: 'eth_getBlockByNumber',
        params: [hex(head.number), false] }), head.number);
    if (checkedHead.hash !== head.hash) throw new Error('The finalized expiry-history head changed. Retry the scan.');
    const owned = new Map(deposits.filter(deposit => deposit.status === 'confirmed')
        .map(deposit => [deposit.noteId, deposit]));
    const claims = new Map();
    for (const log of canonicalLogs) {
        const deposit = owned.get(log.noteId);
        if (!deposit || !integer(deposit.amount) || BigInt(deposit.amount) !== log.amount || !seconds(deposit.expiryTs)
            || log.claimedAt < deposit.expiryTs * 1000) continue;
        const claim = { ...log, amount: deposit.amount };
        const previous = claims.get(log.noteId);
        if (previous && JSON.stringify(previous) !== JSON.stringify(claim)) {
            throw new Error('The RPC returned conflicting expiry claims for one note.');
        }
        claims.set(log.noteId, claim);
    }
    return { claims: [...claims.values()], scannedTo: Math.min(scannedTo, head.number),
        deploymentBlock, complete: scannedTo >= head.number };
}
