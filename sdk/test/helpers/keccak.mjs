// Keccak-256 (the Ethereum variant, padding 0x01), for tests that recompute
// selectors and event topics from their signatures. Node's crypto has only
// the FIPS SHA3 padding. Lanes are BigInts: slow, and only for short inputs.
const MASK = (1n << 64n) - 1n;
const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROTATIONS = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const rotate = (value, bits) => (bits === 0 ? value : ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & MASK);

function permute(state) {
  for (const constant of ROUND_CONSTANTS) {
    const c = Array.from({ length: 5 }, (_, x) => state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]);
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5] ^ rotate(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y += 1) state[x][y] ^= d;
    }
    const b = Array.from({ length: 5 }, () => new Array(5).fill(0n));
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) b[y][(2 * x + 3 * y) % 5] = rotate(state[x][y], ROTATIONS[x][y]);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) state[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & MASK & b[(x + 2) % 5][y]);
    }
    state[0][0] ^= constant;
  }
}

export function keccak256(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : Uint8Array.from(input);
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = Array.from({ length: 5 }, () => new Array(5).fill(0n));
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) {
      let value = 0n;
      for (let byte = 7; byte >= 0; byte -= 1) value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]);
      state[lane % 5][Math.floor(lane / 5)] ^= value;
    }
    permute(state);
  }
  let hex = '';
  for (let lane = 0; lane < 4; lane += 1) {
    let value = state[lane % 5][Math.floor(lane / 5)];
    for (let byte = 0; byte < 8; byte += 1) {
      hex += (value & 0xffn).toString(16).padStart(2, '0');
      value >>= 8n;
    }
  }
  return `0x${hex}`;
}

export const selector = signature => keccak256(signature).slice(2, 10);
