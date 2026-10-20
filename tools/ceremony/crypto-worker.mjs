// A fresh process per operation bounds the lifetime of snarkjs's worker pool
// and private contribution randomness. No entropy is sent over IPC or argv.
import { randomBytes } from 'node:crypto';
import { zKey, powersOfTau } from 'snarkjs';

process.once('message', async ({ operation, args }) => {
  try {
    let result;
    switch (operation) {
      case 'new': result = await zKey.newZKey(...args); break;
      case 'verify': result = await zKey.verifyFromR1cs(...args); break;
      case 'verify-ptau': result = await powersOfTau.verify(...args); break;
      case 'contribute': {
        // snarkjs mixes this with its own OS randomness. This value is never
        // written to disk, environment variables, command arguments or logs.
        const entropy = randomBytes(64);
        try { result = await zKey.contribute(...args, entropy.toString('hex')); }
        finally { entropy.fill(0); }
        // JS strings/library copies cannot be reliably erased. Process exit
        // releases them; this is not a guarantee against swap/core dumps.
        break;
      }
      case 'beacon': result = await zKey.beacon(...args); break;
      default: throw new Error('Unknown cryptographic operation');
    }
    if (result === false || result == null) throw new Error('Cryptographic operation failed');
    if ((operation === 'verify' || operation === 'verify-ptau') && result !== true) {
      throw new Error('Verification did not return true');
    }
    if (['new', 'contribute', 'beacon'].includes(operation)
      && (!(result instanceof Uint8Array) || result.length !== 64)) {
      throw new Error('Expected a public 64-byte transcript hash');
    }
    process.send({ ok: true }, () => process.exit(0));
  } catch {
    // Do not print library exception objects: contribution internals may be
    // attached to them. The caller reports the public operation that failed.
    process.send({ ok: false }, () => process.exit(1));
  }
});
