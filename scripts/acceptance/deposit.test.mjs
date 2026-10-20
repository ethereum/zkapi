import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Interface } from '../../docker/aws/signer/node_modules/ethers/lib.esm/index.js';
import { depositNativeNote } from '../v2-acceptance.mjs';

// Run after forge build: this must use the actual vault ABI, rather than a
// handwritten interface that could silently retain a retired deposit shape.
test('driver and companion deposits encode against the compiled vault ABI', async () => {
    const artifact = JSON.parse(await readFile(new URL('../../protocol/contracts/out/ZkApiVault.sol/ZkApiVault.json', import.meta.url)));
    const vault = new Interface(artifact.abi);
    const from = '0x0000000000000000000000000000000000000001';
    const receipt = { status: '0x1' };
    for (const [commitment, amount] of [['0x42', 1_000_000], ['0x43', 2_000_000]]) {
        let sends = 0;
        const result = await depositNativeNote(async (sender, method, args, options) => {
            sends++;
            assert.equal(sender, from);
            assert.equal(method, 'deposit');
            const data = vault.encodeFunctionData(method, args);
            const decoded = vault.decodeFunctionData(method, data);
            assert.equal(decoded.commitment, `0x${BigInt(commitment).toString(16).padStart(64, '0')}`);
            assert.equal(decoded.amount, BigInt(amount));
            assert.deepEqual(options, { value: BigInt(amount) * 1_000_000_000n, operation: 'deposit' });
            return receipt;
        }, from, commitment, amount);
        assert.equal(sends, 1);
        assert.equal(result, receipt);
    }
});
