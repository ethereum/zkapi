// Keccak-256 (Ethereum's pre-standard padding, not SHA3-256). The wallet uses
// it to hash runtime bytecode (eth_getCode) for the codehash pins of design
// §6.5: no WebCrypto algorithm computes it.

const ROUND_CONSTANTS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];
const ROTATIONS = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const LANE = (1n << 64n) - 1n;
const RATE = 136;

const rotateLeft = (value, bits) => bits === 0 ? value
    : ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & LANE;

function permute(state) {
    for (const constant of ROUND_CONSTANTS) {
        const parity = [0, 1, 2, 3, 4].map(x =>
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
        for (let index = 0; index < 25; index += 1) {
            const x = index % 5;
            state[index] ^= parity[(x + 4) % 5] ^ rotateLeft(parity[(x + 1) % 5], 1);
        }
        const rotated = new Array(25);
        for (let x = 0; x < 5; x += 1) {
            for (let y = 0; y < 5; y += 1) {
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLeft(state[x + 5 * y], ROTATIONS[x][y]);
            }
        }
        for (let x = 0; x < 5; x += 1) {
            for (let y = 0; y < 5; y += 1) {
                state[x + 5 * y] = rotated[x + 5 * y]
                    ^ ((~rotated[(x + 1) % 5 + 5 * y] & LANE) & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
}

/** The bytes of a 0x-prefixed (or bare) even-length hex string. */
export function hexBytes(value) {
    const hex = String(value ?? '').replace(/^0x/i, '');
    if (hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex byte string.');
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
}

/** Keccak-256 of bytes (Uint8Array), a UTF-8 string, as 0x-prefixed hex. */
export function keccak256(input) {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : Uint8Array.from(input);
    const padded = new Uint8Array(Math.ceil((bytes.length + 1) / RATE) * RATE);
    padded.set(bytes);
    padded[bytes.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    const state = new Array(25).fill(0n);
    for (let offset = 0; offset < padded.length; offset += RATE) {
        for (let lane = 0; lane < RATE / 8; lane += 1) {
            let value = 0n;
            for (let byte = 7; byte >= 0; byte -= 1) value = (value << 8n) | BigInt(padded[offset + lane * 8 + byte]);
            state[lane] ^= value;
        }
        permute(state);
    }
    let digest = '';
    for (let lane = 0; lane < 4; lane += 1) {
        let value = state[lane];
        for (let byte = 0; byte < 8; byte += 1) {
            digest += Number(value & 0xffn).toString(16).padStart(2, '0');
            value >>= 8n;
        }
    }
    return `0x${digest}`;
}

/** keccak256 of runtime bytecode given as an eth_getCode hex result. */
export function codehash(code) {
    return keccak256(hexBytes(code));
}
