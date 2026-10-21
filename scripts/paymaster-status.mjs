#!/usr/bin/env node
// The operator's view of a gasless-withdrawal paymaster (docs/deployment.md, "Gasless
// withdrawals"): from a finalized deployment manifest and an RPC it prints, as one JSON object,
// the float and both stakes (entryPoint.balanceOf / getDepositInfo), the live policy, fee
// ceilings, call caps, keeper and owner, the paymaster's loss metrics (lostWei, shortfallWei,
// totalCredits), and what its events say since deployBlock: sponsorships and settlements, failed
// sponsorships, shortfalls, credited payouts, the escape debt still open per transit account
// (EscapeInitiationOwed minus Settled.owedPaid, Collected.owedPaid and DebtWrittenOff, checked
// against owed(S)), transit accounts stranded without a later FORWARD settlement or sweep (each
// with the event that listed it, Stranded or ForwardAllowed, and whether it has code yet), and
// the EntryPoint's alarms for the paymaster's senders (PostOpRevertReason,
// UserOperationPrefundTooLow: the float paid and recorded nothing).
//
//   node scripts/paymaster-status.mjs --deployment .demo/deployment.json --rpc URL \
//     [--from-block N] [--to-block N] [--log-chunk N]
//
// --from-block defaults to the manifest's deployBlock and --to-block to the latest block;
// --log-chunk splits eth_getLogs into ranges of N blocks for providers that cap a query's range.
// The paymaster's own logs are read whole; the EntryPoint, shared by every ERC-4337 app on the
// chain, is asked only for the paymaster's UserOperationEvents (topic 3) and for the two alarms
// of the senders Sponsored named (topic 2), so the query stays within a provider's result cap.
// Wei amounts print as decimal strings. Exits 2 on any failure; the output is a report, not a
// verdict (alert thresholds are the runbook's).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { callWords, jsonRpc, keccak256, parseDeployment } from './expected-codehashes.mjs';

const KINDS = ['close', 'escape', 'finalize', 'forward'];

function fail(message) {
    throw new Error(message);
}

function topic(signature) {
    return keccak256(new TextEncoder().encode(signature));
}

const EVENTS = {
    Sponsored: 'Sponsored(bytes32,address,address,uint8,uint32,uint256)',
    Settled: 'Settled(bytes32,address,address,uint8,uint32,uint256,uint256,uint256,uint256)',
    SponsorshipFailed: 'SponsorshipFailed(bytes32,address,uint8,uint32,uint256)',
    EscapeInitiationOwed: 'EscapeInitiationOwed(address,uint32,uint256)',
    Shortfall: 'Shortfall(address,uint32,uint256)',
    PayoutCredited: 'PayoutCredited(address,uint256)',
    CreditClaimed: 'CreditClaimed(address,uint256)',
    Collected: 'Collected(address,address,uint256,uint256,uint256)',
    Stranded: 'Stranded(address)',
    ForwardAllowed: 'ForwardAllowed(address)',
    DebtWrittenOff: 'DebtWrittenOff(address,uint256)',
    // EntryPoint
    UserOperationEvent: 'UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)',
    PostOpRevertReason: 'PostOpRevertReason(bytes32,address,uint256,bytes)',
    UserOperationPrefundTooLow: 'UserOperationPrefundTooLow(bytes32,address,uint256)',
};
const TOPICS = Object.fromEntries(Object.entries(EVENTS).map(([name, signature]) => [topic(signature), name]));

const addressOf = value => `0x${BigInt(value).toString(16).padStart(40, '0')}`;
const hex = value => `0x${value.toString(16)}`;
const str = value => value.toString();
/// An address (or any value) as the 32-byte word a log topic holds.
const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
// How many senders one eth_getLogs topic position names at once (providers cap the array).
const SENDERS_PER_QUERY = 500;

function dataWords(data) {
    if (typeof data !== 'string' || !/^0x([0-9a-fA-F]{64})*$/.test(data)) fail(`log data is not whole words: ${data}`);
    const words = [];
    for (let i = 2; i < data.length; i += 64) words.push(BigInt(`0x${data.slice(i, i + 64)}`));
    return words;
}

/// Every log of `address` between the blocks (those matching the positional `topics` filter, when
/// given: null matches anything, an array any of its values), in chain order, decoded by name.
async function logsOf(rpc, address, fromBlock, toBlock, chunk, topics = null) {
    const logs = [];
    for (let start = fromBlock; start <= toBlock; start += chunk) {
        const end = start + chunk - 1n < toBlock ? start + chunk - 1n : toBlock;
        const filter = { address, fromBlock: hex(start), toBlock: hex(end) };
        if (topics) filter.topics = topics;
        const batch = await rpc('eth_getLogs', [filter]);
        if (!Array.isArray(batch)) fail(`eth_getLogs: unexpected ${JSON.stringify(batch)}`);
        logs.push(...batch);
    }
    return logs
        .map(log => ({
            name: TOPICS[String(log.topics?.[0]).toLowerCase()] ?? null,
            topics: (log.topics ?? []).slice(1).map(value => BigInt(value)),
            words: dataWords(log.data),
            block: BigInt(log.blockNumber),
            index: BigInt(log.logIndex ?? 0),
            tx: log.transactionHash,
        }))
        .sort((a, b) => (a.block === b.block ? Number(a.index - b.index) : Number(a.block - b.block)));
}

function parseArgs(argv) {
    const args = { chunk: null };
    for (let i = 0; i < argv.length; i++) {
        const flag = argv[i];
        const next = () => argv[++i] ?? fail(`${flag} needs a value`);
        if (flag === '--deployment') args.deployment = resolve(next());
        else if (flag === '--rpc') args.rpc = next();
        else if (flag === '--from-block') args.fromBlock = BigInt(next());
        else if (flag === '--to-block') args.toBlock = BigInt(next());
        else if (flag === '--log-chunk') args.chunk = BigInt(next());
        else fail(`unknown argument ${flag}`);
    }
    if (!args.deployment || !args.rpc) fail('--deployment (a finalized manifest) and --rpc are required');
    if (args.chunk !== null && args.chunk <= 0n) fail('--log-chunk must be positive');
    return args;
}

export async function paymasterStatus({ deployment, rpc, fromBlock, toBlock, chunk }) {
    if (deployment.deploymentStatus !== 'deployed') fail(`deploymentStatus is ${JSON.stringify(deployment.deploymentStatus ?? null)}: pass the finalized manifest`);
    if (deployment.withdrawalPaymaster == null) fail('this deployment has no gasless withdrawal paymaster (withdrawalPaymaster is null)');
    const paymaster = String(deployment.withdrawalPaymaster).toLowerCase();
    const factory = String(deployment.withdrawalAccountFactory).toLowerCase();
    const entryPoint = String(deployment.entryPoint).toLowerCase();
    const chainId = BigInt(await rpc('eth_chainId', []));
    if (chainId !== BigInt(deployment.chainId)) fail(`the RPC serves chain ${chainId}, the manifest is for chain ${deployment.chainId}`);
    const latest = BigInt(await rpc('eth_blockNumber', []));
    const from = fromBlock ?? BigInt(deployment.deployBlock);
    const to = toBlock ?? latest;
    if (from > to) fail(`--from-block ${from} is after --to-block ${to}`);
    const range = chunk ?? (to - from + 1n);

    // ----------------------------------------------------------------------- state (latest)
    const [deposit] = await callWords(rpc, entryPoint, 'balanceOf(address)', [paymaster], 1);
    const stakeOf = async target => {
        const [stakeDeposit, staked, stake, unstakeDelaySec, withdrawTime] = await callWords(rpc, entryPoint, 'getDepositInfo(address)', [target], 5);
        return { deposit_wei: str(stakeDeposit), staked: staked === 1n, stake_wei: str(stake), unstake_delay_seconds: Number(unstakeDelaySec),
            withdraw_time: Number(withdrawTime) };
    };
    const [maxSponsoredCost, flatFee, minEscapeNet, escapes, paused] = await callWords(rpc, paymaster, 'policy()', [], 5);
    const [maxFeeCeiling] = await callWords(rpc, paymaster, 'maxFeeCeiling()', [], 1);
    const [priorityFeeCeiling] = await callWords(rpc, paymaster, 'priorityFeeCeiling()', [], 1);
    const [feeKeeper] = await callWords(rpc, paymaster, 'feeKeeper()', [], 1);
    const [owner] = await callWords(rpc, paymaster, 'owner()', [], 1);
    const [pendingOwner] = await callWords(rpc, paymaster, 'pendingOwner()', [], 1);
    const [lostWei] = await callWords(rpc, paymaster, 'lostWei()', [], 1);
    const [shortfallWei] = await callWords(rpc, paymaster, 'shortfallWei()', [], 1);
    const [totalCredits] = await callWords(rpc, paymaster, 'totalCredits()', [], 1);
    const callCaps = {};
    for (let kind = 1; kind <= 4; kind++) {
        const [cap] = await callWords(rpc, paymaster, 'callCap(uint8)', [kind], 1);
        callCaps[KINDS[kind - 1]] = Number(cap);
    }
    const paymasterBalance = BigInt(await rpc('eth_getBalance', [paymaster, 'latest']));

    // ------------------------------------------------------------------------------ events
    const logs = await logsOf(rpc, paymaster, from, to, range);
    const counts = Object.fromEntries(Object.keys(EVENTS).slice(0, 11).map(name => [name, 0]));
    const owedByAccount = new Map();
    const strandedAt = new Map();
    const settledAt = new Map();
    const senders = new Set();
    const totals = { settled_received_wei: 0n, settled_charged_wei: 0n, settled_owed_paid_wei: 0n, settled_paid_out_wei: 0n,
        failed_actual_gas_cost_wei: 0n, shortfall_wei: 0n, credited_wei: 0n, claimed_wei: 0n, collected_received_wei: 0n, collected_owed_paid_wei: 0n };
    const byKind = Object.fromEntries(KINDS.map(kind => [kind, { sponsored: 0, settled: 0, failed: 0 }]));
    const addOwed = (account, delta) => owedByAccount.set(account, (owedByAccount.get(account) ?? 0n) + delta);
    for (const log of logs) {
        if (!log.name || !(log.name in counts)) continue;
        counts[log.name] += 1;
        const at = { block: log.block, index: log.index, tx: log.tx };
        switch (log.name) {
            case 'Sponsored': {
                const sender = addressOf(log.topics[1]);
                senders.add(sender);
                byKind[KINDS[Number(log.words[0]) - 1]].sponsored += 1;
                break;
            }
            case 'Settled': {
                const sender = addressOf(log.topics[1]);
                const [kind, , received, charged, owedPaid, paidOut] = log.words;
                byKind[KINDS[Number(kind) - 1]].settled += 1;
                totals.settled_received_wei += received;
                totals.settled_charged_wei += charged;
                totals.settled_owed_paid_wei += owedPaid;
                totals.settled_paid_out_wei += paidOut;
                if (owedPaid !== 0n) addOwed(sender, -owedPaid);
                // A FORWARD settles whatever was stranded in S (its evidence was consumed).
                if (Number(kind) === 4) settledAt.set(sender, at);
                break;
            }
            case 'SponsorshipFailed': {
                byKind[KINDS[Number(log.words[0]) - 1]].failed += 1;
                totals.failed_actual_gas_cost_wei += log.words[2];
                break;
            }
            case 'EscapeInitiationOwed':
                addOwed(addressOf(log.topics[0]), log.words[0]);
                break;
            case 'Shortfall':
                totals.shortfall_wei += log.words[1];
                break;
            case 'PayoutCredited':
                totals.credited_wei += log.words[0];
                break;
            case 'CreditClaimed':
                totals.claimed_wei += log.words[0];
                break;
            case 'Collected': {
                const sender = addressOf(log.topics[0]);
                totals.collected_received_wei += log.words[0];
                totals.collected_owed_paid_wei += log.words[1];
                if (log.words[1] !== 0n) addOwed(sender, -log.words[1]);
                settledAt.set(sender, at);
                break;
            }
            case 'Stranded':
            case 'ForwardAllowed':
                strandedAt.set(addressOf(log.topics[0]), { ...at, evidence: log.name === 'Stranded' ? 'stranded' : 'forward_allowed' });
                break;
            case 'DebtWrittenOff':
                addOwed(addressOf(log.topics[0]), -log.words[0]);
                break;
            default:
        }
    }
    const later = (a, b) => !b || a.block > b.block || (a.block === b.block && a.index > b.index);
    const openOwed = {};
    let openOwedTotal = 0n;
    for (const [account, amount] of owedByAccount) {
        if (amount <= 0n) continue;
        const [onChain] = await callWords(rpc, paymaster, 'owed(address)', [account], 1);
        openOwed[account] = { from_events_wei: str(amount), on_chain_wei: str(onChain) };
        openOwedTotal += onChain;
    }
    const strandedOpen = [];
    for (const [account, at] of strandedAt) {
        if (!later(at, settledAt.get(account))) continue;
        const [flag] = await callWords(rpc, paymaster, 'stranded(address)', [account], 1);
        // Stranded is emitted in postOp, after S's own operation ran, so S has code. ForwardAllowed
        // (the owner's allowForward) may name an S whose creating operation never landed (a close
        // replayed before any sponsored operation): sweep() on an S without code is a no-op
        // transfer, so has_code says whether factory.createAccount(owner, payee) comes first.
        const code = await rpc('eth_getCode', [account, 'latest']);
        strandedOpen.push({ account, since_block: Number(at.block), transaction: at.tx, evidence: at.evidence,
            stranded_flag_on_chain: flag === 1n, has_code: typeof code === 'string' && code !== '0x' && code !== '0x0',
            balance_wei: str(BigInt(await rpc('eth_getBalance', [account, 'latest']))) });
    }

    // The EntryPoint's view, filtered by the node (the EntryPoint logs every app's operations):
    // every operation the paymaster paid for (UserOperationEvent, paymaster in topic 3), and the
    // two alarms, which carry the sender, not the paymaster (topic 2, the senders Sponsored named,
    // SENDERS_PER_QUERY at a time; no senders, no query). The filter is re-applied here.
    const operations = { total: 0, succeeded: 0, failed: 0, actual_gas_cost_wei: 0n };
    const alarms = { post_op_revert_reason: 0, user_operation_prefund_too_low: 0 };
    const paymasterWord = BigInt(paymaster);
    const userOperationLogs = await logsOf(rpc, entryPoint, from, to, range, [topic(EVENTS.UserOperationEvent), null, null, word(paymaster)]);
    for (const log of userOperationLogs) {
        if (log.name !== 'UserOperationEvent' || log.topics[2] !== paymasterWord) continue;
        operations.total += 1;
        if (log.words[1] === 1n) operations.succeeded += 1;
        else operations.failed += 1;
        operations.actual_gas_cost_wei += log.words[2];
    }
    const senderWords = [...senders].map(word);
    for (let i = 0; i < senderWords.length; i += SENDERS_PER_QUERY) {
        const alarmLogs = await logsOf(rpc, entryPoint, from, to, range,
            [[topic(EVENTS.PostOpRevertReason), topic(EVENTS.UserOperationPrefundTooLow)], null, senderWords.slice(i, i + SENDERS_PER_QUERY)]);
        for (const log of alarmLogs) {
            if (!(log.name === 'PostOpRevertReason' || log.name === 'UserOperationPrefundTooLow') || !senders.has(addressOf(log.topics[1]))) continue;
            alarms[log.name === 'PostOpRevertReason' ? 'post_op_revert_reason' : 'user_operation_prefund_too_low'] += 1;
        }
    }

    return {
        chain_id: Number(chainId),
        block: Number(latest),
        entry_point: entryPoint,
        paymaster,
        factory,
        deposit_wei: str(deposit),
        // Bundlers reserve maxCost per pending operation: how many the float covers at once.
        deposit_covers_operations: maxSponsoredCost === 0n ? null : Number(deposit / maxSponsoredCost),
        paymaster_stake: await stakeOf(paymaster),
        factory_stake: await stakeOf(factory),
        policy: { max_sponsored_cost_wei: str(maxSponsoredCost), flat_fee_wei: str(flatFee), min_escape_net_wei: str(minEscapeNet),
            escapes_enabled: escapes === 1n, sponsorship_paused: paused === 1n },
        fee_ceilings: { max_fee_wei: str(maxFeeCeiling), priority_fee_wei: str(priorityFeeCeiling) },
        call_caps: callCaps,
        fee_keeper: addressOf(feeKeeper),
        owner: addressOf(owner),
        pending_owner: addressOf(pendingOwner),
        lost_wei: str(lostWei),
        shortfall_wei: str(shortfallWei),
        total_credits_wei: str(totalCredits),
        // Only credited payouts ever sit in the paymaster itself; more is a forced transfer.
        paymaster_balance_wei: str(paymasterBalance),
        unaccounted_balance_wei: str(paymasterBalance - totalCredits),
        open_owed_total_wei: str(openOwedTotal),
        open_owed: openOwed,
        stranded_open: strandedOpen,
        events: { from_block: Number(from), to_block: Number(to), counts, by_kind: byKind,
            totals: Object.fromEntries(Object.entries(totals).map(([key, value]) => [key, str(value)])) },
        user_operations: { ...operations, actual_gas_cost_wei: str(operations.actual_gas_cost_wei) },
        entry_point_alarms: alarms,
    };
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    const deployment = parseDeployment(readFileSync(args.deployment, 'utf8'));
    const status = await paymasterStatus({ deployment, rpc: jsonRpc(args.rpc), fromBlock: args.fromBlock, toBlock: args.toBlock, chunk: args.chunk });
    console.log(JSON.stringify(status, null, 2));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch(error => {
        console.error(`paymaster-status: ${error.message}`);
        process.exit(2);
    });
}
