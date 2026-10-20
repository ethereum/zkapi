import assert from 'node:assert/strict';
import test from 'node:test';

import {
    closeRelayFeePayload,
    closeRelayStatus,
    closeRelayTicketHash,
    decideCloseRelay,
    fetchCloseRelayTerms,
    followCloseRelay,
    mutualCloseLogMatches,
    MUTUAL_CLOSE_TOPIC,
    newTicketSecret,
    payCloseRelayFee,
    submitCloseRelay
} from '../services/zkapiCloseRelay.mjs';
import { keccak256 } from '../services/zkapiKeccak.mjs';

const SECRET = `0x${'11'.repeat(32)}`;
const VALID_UNTIL = 2_000_010_800;
const MARGIN = 1_200;

test('the ticket hash and fee payload match the server and the other clients', () => {
    // The vector zkapi-types pins (wire.rs).
    assert.equal(closeRelayTicketHash(SECRET), '0x091ea439259b6c58737dd512e9177a1536e08cfec8c27cb5c2aecc4524480ffe');
    assert.equal(
        closeRelayFeePayload(250_000, SECRET),
        '{"mode":"close_relay_fee","version":1,"fee_units":"250000","ticket_hash":"0x091ea439259b6c58737dd512e9177a1536e08cfec8c27cb5c2aecc4524480ffe"}'
    );
    assert.equal(MUTUAL_CLOSE_TOPIC, keccak256('MutualClose(uint32,uint256,uint128,address)'));
    assert.throws(() => closeRelayFeePayload(0, SECRET));
    assert.throws(() => closeRelayTicketHash('0x1234'));
    const fresh = newTicketSecret();
    assert.match(fresh, /^0x[0-9a-f]{64}$/);
    assert.notEqual(fresh, newTicketSecret());
});

test('the relay decision follows the status and the deadline', () => {
    const early = VALID_UNTIL - MARGIN - 60;
    const late = VALID_UNTIL - MARGIN;
    const cases = [
        [{ status: 'queued' }, early, 'wait'],
        [{ status: 'submitted' }, early, 'wait'],
        [{ status: 'queued' }, late, 'self_submit'],
        [{ status: 'failed', self_submit: true }, early, 'self_submit'],
        [{ status: 'expired', self_submit: true }, early, 'self_submit'],
        [{ status: 'landed' }, early, 'confirm'],
        [{ status: 'closed' }, late, 'confirm'],
        [{ status: 'unknown' }, early, 'resubmit'],
        [{ status: 'unknown' }, late, 'self_submit'],
        [null, early, 'wait'],
        [null, late, 'self_submit']
    ];
    for (const [status, now, expected] of cases) {
        assert.equal(decideCloseRelay(status, VALID_UNTIL, now, MARGIN), expected, JSON.stringify([status, now]));
    }
});

function script({ statuses = [], statusError = null, seenAt = 0, start = VALID_UNTIL - MARGIN - 600 }) {
    const state = { now: start, seenCalls: 0, selfSubmits: 0, resubmits: 0, sleeps: 0 };
    return {
        state,
        options: {
            validUntil: VALID_UNTIL,
            marginSeconds: MARGIN,
            pollMs: 60_000,
            now: () => state.now,
            sleep: async () => {
                state.sleeps += 1;
                state.now += 60;
                if (state.sleeps > 1_000) throw new Error('never ended');
            },
            status: async () => {
                if (statusError) throw statusError;
                return statuses.length > 1 ? statuses.shift() : statuses[0];
            },
            resubmit: async () => {
                state.resubmits += 1;
            },
            closeSeen: async () => {
                state.seenCalls += 1;
                return seenAt !== 0 && state.seenCalls >= seenAt;
            },
            selfSubmit: async () => {
                state.selfSubmits += 1;
            }
        }
    };
}

test('a relayed close waits for the MutualClose event or is submitted by the wallet', async () => {
    let run = script({ statuses: [{ status: 'queued' }, { status: 'submitted' }, { status: 'landed' }], seenAt: 5 });
    assert.equal(await followCloseRelay(run.options), 'relayed');
    assert.equal(run.state.selfSubmits, 0);

    run = script({ statuses: [{ status: 'failed', self_submit: true }] });
    assert.equal(await followCloseRelay(run.options), 'self_submitted');
    assert.equal(run.state.sleeps, 0);

    run = script({ statuses: [{ status: 'submitted' }] });
    assert.equal(await followCloseRelay(run.options), 'self_submitted');
    assert.ok(run.state.now >= VALID_UNTIL - MARGIN, 'not before the deadline');

    run = script({ statusError: new Error('offline') });
    assert.equal(await followCloseRelay(run.options), 'self_submitted');

    run = script({ statuses: [{ status: 'unknown' }, { status: 'queued' }, { status: 'landed' }], seenAt: 4 });
    assert.equal(await followCloseRelay(run.options), 'relayed');
    assert.equal(run.state.resubmits, 1);

    run = script({ statuses: [{ status: 'closed' }] });
    assert.equal(await followCloseRelay(run.options), 'self_submitted');

    run = script({ statuses: [{ status: 'submitted' }], seenAt: 2, start: VALID_UNTIL - MARGIN });
    assert.equal(await followCloseRelay(run.options), 'relayed');
    assert.equal(run.state.selfSubmits, 0);
});

test('only the vault MutualClose of this close matches', () => {
    const vault = '0x00000000000000000000000000000000000000aa';
    const log = {
        address: vault,
        topics: [MUTUAL_CLOSE_TOPIC, `0x${'0'.repeat(63)}7`],
        // The vault's golden MutualClose: nullifier 0x101, 900000 units,
        // destination 0x11..11.
        data: '0x000000000000000000000000000000000000000000000000000000000000010100000000000000000000000000000000000000000000000000000000000dbba00000000000000000000000001111111111111111111111111111111111111111'
    };
    const close = { vault, noteId: 7, nullifier: '0x101', finalBalance: 900_000n, destination: `0x${'11'.repeat(20)}` };
    assert.equal(mutualCloseLogMatches([log], close), true);
    for (const mutate of [
        l => { l.address = '0x00000000000000000000000000000000000000bb'; },
        l => { l.topics = [l.topics[0], `0x${'0'.repeat(63)}8`]; },
        l => { l.data = l.data.replace('dbba0', 'dbba1'); },
        l => { l.removed = true; }
    ]) {
        const copy = { ...log, topics: [...log.topics] };
        mutate(copy);
        assert.equal(mutualCloseLogMatches([copy], close), false);
    }
});

test('the relay endpoints are called as the server serves them', async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
        calls.push(`${init.method} ${url}`);
        const json = (status, body) => new Response(JSON.stringify(body), { status });
        if (url.endsWith('/terms')) return json(200, { enabled: true, fee_units: '250000' });
        if (url.endsWith('/fee')) return json(409, { error_code: 'relay_fee_changed', error_message: 'the relay fee is 1 units' });
        if (init.method === 'POST') {
            const body = JSON.parse(init.body);
            assert.equal(body.ticket_secret, SECRET);
            return json(202, { status: 'queued', self_submit: false });
        }
        if (url.endsWith('/0x99')) return json(404, { status: 'not_found' });
        return json(200, { status: 'landed', transaction_hash: `0x${'ab'.repeat(32)}`, self_submit: false });
    };
    const server = 'https://zkapi.example/';
    assert.equal((await fetchCloseRelayTerms(server, { fetchImpl })).fee_units, '250000');
    await assert.rejects(payCloseRelayFee(server, {}, { fetchImpl }), error => error.code === 'relay_fee_changed');
    assert.equal((await submitCloseRelay(server, { publicInputs: {}, proof: {}, ticketSecret: SECRET }, { fetchImpl })).status, 'queued');
    assert.equal((await closeRelayStatus(server, '0x99', { fetchImpl })).status, 'unknown');
    assert.equal((await closeRelayStatus(server, '0x12', { fetchImpl })).status, 'landed');
    assert.deepEqual(calls, [
        'GET https://zkapi.example/v2/withdraw/relay/terms',
        'POST https://zkapi.example/v2/withdraw/relay/fee',
        'POST https://zkapi.example/v2/withdraw/relay',
        'GET https://zkapi.example/v2/withdraw/relay/0x99',
        'GET https://zkapi.example/v2/withdraw/relay/0x12'
    ]);
});
