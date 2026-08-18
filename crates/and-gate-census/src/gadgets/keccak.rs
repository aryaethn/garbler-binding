//! Keccak-f[1600] and Keccak-256 as Boolean circuits.
//!
//! Measured as Keccak-256 of a short message (< 136 bytes), which is exactly
//! one permutation. Validated against `tiny-keccak`.
//!
//! Keccak is the interesting counterexample to "hash functions are expensive
//! to garble". Theta, rho, pi and iota are all GF(2)-linear or constant, hence
//! FREE. Only chi costs anything: one AND per state bit per round, so exactly
//! 24 * 1600 = 38,400 non-free gates for the permutation, with zero carry
//! chains anywhere.
//!
//! Per byte of throughput (rate 136 B) that is ~282 non-free gates/byte,
//! versus SHA-256 at ~410/byte and BLAKE3 at ~163/byte. But Keccak's ANDs are
//! structurally different: they are a single algebraic-degree-2 layer, which
//! is exactly the shape a binary-field proof system wants.

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{and_not, xor, FALSE, TRUE};

const ROUNDS: usize = 24;

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// FREE: rotate a 64-bit lane left by n (pure rewiring).
fn rotl64(a: &[WireId], n: u32) -> Vec<WireId> {
    let n = (n % 64) as usize;
    (0..64).map(|i| a[(i + 64 - n) % 64]).collect()
}

/// Keccak-f[1600]. State is 25 lanes of 64 bits, little-endian within a lane.
pub fn keccak_f<C: CircuitContext>(c: &mut C, state: &mut Vec<Vec<WireId>>) {
    assert_eq!(state.len(), 25);

    for round in 0..ROUNDS {
        // theta: FREE
        let mut bc: Vec<Vec<WireId>> = Vec::with_capacity(5);
        for i in 0..5 {
            let mut acc = state[i].clone();
            for j in 1..5 {
                acc = (0..64)
                    .map(|b| xor(c, acc[b], state[i + 5 * j][b]))
                    .collect();
            }
            bc.push(acc);
        }
        for i in 0..5 {
            let rot = rotl64(&bc[(i + 1) % 5], 1);
            let t: Vec<WireId> = (0..64)
                .map(|b| xor(c, bc[(i + 4) % 5][b], rot[b]))
                .collect();
            for j in 0..5 {
                state[i + 5 * j] = (0..64)
                    .map(|b| xor(c, state[i + 5 * j][b], t[b]))
                    .collect();
            }
        }

        // rho + pi: FREE
        let mut t = state[1].clone();
        for i in 0..24 {
            let j = PI[i];
            let tmp = state[j].clone();
            state[j] = rotl64(&t, RHO[i]);
            t = tmp;
        }

        // chi: 1 non-free gate per state bit -> 1600 per round
        for j in 0..5 {
            let row: Vec<Vec<WireId>> = (0..5).map(|i| state[5 * j + i].clone()).collect();
            for i in 0..5 {
                let a1 = &row[(i + 1) % 5];
                let a2 = &row[(i + 2) % 5];
                state[5 * j + i] = (0..64)
                    .map(|b| {
                        // a[i] ^ ((~a[i+1]) & a[i+2])  ==  a[i] ^ (a[i+2] AND NOT a[i+1])
                        let t = and_not(c, a2[b], a1[b]);
                        xor(c, row[i][b], t)
                    })
                    .collect();
            }
        }

        // iota: FREE
        let rc = RC[round];
        state[0] = (0..64)
            .map(|b| {
                if (rc >> b) & 1 == 1 {
                    xor(c, state[0][b], TRUE)
                } else {
                    state[0][b]
                }
            })
            .collect();
    }
}

/// Keccak-256 (Ethereum flavour, 0x01 padding) of a message shorter than the
/// 136-byte rate: exactly one permutation.
pub fn keccak256_one_block<C: CircuitContext>(
    c: &mut C,
    msg_bits: &[WireId],
    msg_len: usize,
) -> Vec<WireId> {
    assert!(msg_len < 136);
    assert_eq!(msg_bits.len(), msg_len * 8);

    // Build the 136-byte padded rate block as a flat little-endian bit array.
    let mut block: Vec<WireId> = Vec::with_capacity(136 * 8);
    block.extend_from_slice(msg_bits);
    // pad10*1 with 0x01 ... 0x80
    block.push(TRUE); // 0x01 low bit
    for _ in 1..8 {
        block.push(FALSE);
    }
    while block.len() < 136 * 8 - 8 {
        block.push(FALSE);
    }
    for i in 0..8 {
        block.push(if i == 7 { TRUE } else { FALSE }); // 0x80
    }
    assert_eq!(block.len(), 136 * 8);

    // Absorb into a zero state: first 17 lanes.
    let mut state: Vec<Vec<WireId>> = (0..25).map(|_| vec![FALSE; 64]).collect();
    for lane in 0..17 {
        state[lane] = (0..64).map(|b| block[lane * 64 + b]).collect();
    }

    keccak_f(c, &mut state);

    // Squeeze 32 bytes = 4 lanes, little-endian bytes.
    let mut out = Vec::with_capacity(256);
    for lane in 0..4 {
        for byte in 0..8 {
            for bit in 0..8 {
                out.push(state[lane][byte * 8 + bit]);
            }
        }
    }
    out
}

/// Bytes to a flat little-endian-within-byte bit vector, matching the layout
/// `keccak256_one_block` expects.
pub fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .collect()
}

pub fn bits_le_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (i, &v)| if v { acc | (1 << i) } else { acc })
        })
        .collect()
}
