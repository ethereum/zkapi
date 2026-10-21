// secp256k1 ECDSA for tests only: deterministic signing (RFC 6979 with
// HMAC-SHA256 from node:crypto) and public-key recovery, over BigInts. The
// SDK itself never signs (the wallet does) and never recovers (the EntryPoint
// does); the tests use this to pin the EIP-191 digest of a user operation to
// the signature in protocol/contracts/test/fixtures/transit-vectors.json and
// to let the fake wallet produce recoverable signatures.
import { createHmac } from 'node:crypto';
import { keccak256 } from '../../services/zkapiKeccak.mjs';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];

const mod = (a, m) => ((a % m) + m) % m;
function inverse(a, m) {
  let [old, r] = [mod(a, m), m];
  let [s, t] = [1n, 0n];
  while (r !== 0n) {
    const q = old / r;
    [old, r] = [r, old - q * r];
    [s, t] = [t, s - q * t];
  }
  return mod(s, m);
}
function add(a, b) {
  if (!a) return b;
  if (!b) return a;
  const [x1, y1] = a;
  const [x2, y2] = b;
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null;
    const l = mod(3n * x1 * x1 * inverse(2n * y1, P), P);
    const x3 = mod(l * l - 2n * x1, P);
    return [x3, mod(l * (x1 - x3) - y1, P)];
  }
  const l = mod((y2 - y1) * inverse(x2 - x1, P), P);
  const x3 = mod(l * l - x1 - x2, P);
  return [x3, mod(l * (x1 - x3) - y1, P)];
}
function multiply(point, scalar) {
  let result = null;
  let base = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = add(result, base);
    base = add(base, base);
    k >>= 1n;
  }
  return result;
}
const toBytes = (value, length) => Uint8Array.from(Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex'));
const fromBytes = bytes => BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
const hmac = (key, ...parts) => {
  const h = createHmac('sha256', key);
  for (const part of parts) h.update(part);
  return Uint8Array.from(h.digest());
};

/** RFC 6979 nonce for (privateKey, digest). */
function deterministicNonce(privateKey, digest) {
  const x = toBytes(privateKey, 32);
  const h1 = toBytes(digest, 32);
  let v = new Uint8Array(32).fill(1);
  let k = new Uint8Array(32);
  k = hmac(k, v, Uint8Array.from([0]), x, h1);
  v = hmac(k, v);
  k = hmac(k, v, Uint8Array.from([1]), x, h1);
  v = hmac(k, v);
  for (;;) {
    v = hmac(k, v);
    const candidate = fromBytes(v);
    if (candidate >= 1n && candidate < N) return candidate;
    k = hmac(k, v, Uint8Array.from([0]));
    v = hmac(k, v);
  }
}

/** The uncompressed public key of a private key. */
export function publicKey(privateKey) {
  return multiply(G, BigInt(privateKey));
}

/** The Ethereum address of a private key. */
export function addressOf(privateKey) {
  const [x, y] = publicKey(privateKey);
  return `0x${keccak256(Uint8Array.from([...toBytes(x, 32), ...toBytes(y, 32)])).slice(-40)}`;
}

/** Sign a 32-byte digest: 65 bytes r ‖ s ‖ v with low s and v ∈ {27, 28}. */
export function sign(digest, privateKey) {
  const d = BigInt(privateKey);
  const z = BigInt(digest);
  for (let extra = 0n; ; extra += 1n) {
    const k = mod(deterministicNonce(d, z) + extra, N) || 1n;
    const point = multiply(G, k);
    const r = mod(point[0], N);
    if (r === 0n) continue;
    let s = mod(inverse(k, N) * (z + r * d), N);
    if (s === 0n) continue;
    let v = 27 + Number(point[1] & 1n);
    if (s > N / 2n) {
      s = N - s;
      v = v === 27 ? 28 : 27;
    }
    return `0x${r.toString(16).padStart(64, '0')}${s.toString(16).padStart(64, '0')}${v.toString(16)}`;
  }
}

/** ecrecover: the address that signed `digest` with r ‖ s ‖ v, or null. */
export function recover(digest, signature) {
  const hex = String(signature).replace(/^0x/, '');
  if (hex.length !== 130) return null;
  const r = BigInt(`0x${hex.slice(0, 64)}`);
  const s = BigInt(`0x${hex.slice(64, 128)}`);
  let v = Number.parseInt(hex.slice(128), 16);
  if (v < 27) v += 27;
  if (r === 0n || r >= N || s === 0n || s >= N || (v !== 27 && v !== 28)) return null;
  const x = r;
  const alpha = mod(x * x * x + 7n, P);
  let y = modPow(alpha, (P + 1n) / 4n, P);
  if (Number(y & 1n) !== v - 27) y = P - y;
  if (mod(y * y, P) !== alpha) return null;
  const z = BigInt(digest);
  const rInverse = inverse(r, N);
  const point = add(multiply([x, y], mod(s * rInverse, N)), multiply(G, mod(-z * rInverse, N)));
  if (!point) return null;
  return `0x${keccak256(Uint8Array.from([...toBytes(point[0], 32), ...toBytes(point[1], 32)])).slice(-40)}`;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b, modulus);
    b = mod(b * b, modulus);
    e >>= 1n;
  }
  return result;
}
