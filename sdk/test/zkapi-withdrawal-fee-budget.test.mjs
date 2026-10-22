import assert from 'node:assert/strict';
import test from 'node:test';

const values = new Map();
globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
};
globalThis.sessionStorage = globalThis.localStorage;
globalThis.window = new EventTarget();
globalThis.window.location = { search: '', hostname: 'localhost', origin: 'http://localhost' };
globalThis.zkapiWallet = (await import('../wallet.js')).default;
const { ZkapiClient } = await import('../services/zkapiClient.js');

const ACCOUNT = `0x${'ab'.repeat(20)}`;
const GAS_CEILING = 1n << 24n;

function client({ accounts = [ACCOUNT], chainId = 11155111, gasPrice = 2_000_000_000n, balance = 10n ** 18n } = {}) {
    const calls = [];
    const c = new ZkapiClient();
    c.config = { funding: { chain_id: 11155111 } };
    globalThis.ethereum = {
        request: async ({ method, params }) => {
            calls.push({ method, params });
            if (method === 'eth_accounts') return accounts;
            if (method === 'eth_chainId') return `0x${chainId.toString(16)}`;
            if (method === 'eth_gasPrice') return `0x${gasPrice.toString(16)}`;
            if (method === 'eth_getBalance') return `0x${balance.toString(16)}`;
            throw new Error(`unexpected ${method}`);
        }
    };
    return { c, calls };
}
test.afterEach(() => { delete globalThis.ethereum; });

test('the wallet fee budget reserves the gas ceiling at twice the gas price and reads only', async () => {
    const { c, calls } = client();
    const quote = await c.getWithdrawalFeeBudget('mutual');
    assert.equal(quote.address, ACCOUNT);
    assert.equal(quote.chainId, 11155111);
    assert.equal(quote.transactionFeeWei, String(GAS_CEILING * 2_000_000_000n * 2n));
    assert.equal(quote.feeReserveWei, quote.transactionFeeWei);
    assert.equal(quote.shortfallWei, '0');
    assert.ok(quote.expiresAt > Date.now());
    assert.deepEqual([...new Set(calls.map(call => call.method))].sort(),
        ['eth_accounts', 'eth_chainId', 'eth_gasPrice', 'eth_getBalance']);
});

test('an escape reserves a second transaction and a short balance reports its shortfall', async () => {
    const { c } = client({ balance: 1n });
    const quote = await c.getWithdrawalFeeBudget('escape');
    assert.equal(BigInt(quote.feeReserveWei), BigInt(quote.transactionFeeWei) * 2n);
    assert.equal(BigInt(quote.shortfallWei), BigInt(quote.feeReserveWei) - 1n);
});

test('a missing, disconnected or wrong-network wallet and a bad mode fail closed', async () => {
    delete globalThis.ethereum;
    const none = new ZkapiClient();
    none.config = { funding: { chain_id: 11155111 } };
    await assert.rejects(none.getWithdrawalFeeBudget('mutual'), { code: 'withdrawal_wallet_disconnected' });
    await assert.rejects(client({ accounts: [] }).c.getWithdrawalFeeBudget('mutual'), { code: 'withdrawal_wallet_disconnected' });
    await assert.rejects(client({ chainId: 1 }).c.getWithdrawalFeeBudget('mutual'), { code: 'wrong_network' });
    await assert.rejects(client().c.getWithdrawalFeeBudget('other'), /Choose a withdrawal method/);
});
