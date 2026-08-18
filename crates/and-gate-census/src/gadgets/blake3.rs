//! BLAKE3 compression as a Boolean circuit.
//!
//! Measured as a single-chunk, single-block root hash (input <= 64 bytes),
//! which is exactly one invocation of the compression function. Validated
//! against the `blake3` crate.
//!
//! BLAKE3 matters here for two reasons: it is the compression function the
//! BitVM chunker already uses in Bitcoin Script, and it is the hash Flock
//! proves fastest (82k compressions/sec/core). Its garbled cost is roughly
//! half of SHA-256's because the G function is pure ARX with no Ch/Maj, so
//! every non-free gate is an addition carry.

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{add_mod2w, rotr, xor_word, FALSE, TRUE};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub const CHUNK_START: u32 = 1 << 0;
pub const CHUNK_END: u32 = 1 << 1;
pub const ROOT: u32 = 1 << 3;

fn const_word(v: u32) -> Vec<WireId> {
    (0..32)
        .map(|i| if (v >> i) & 1 == 1 { TRUE } else { FALSE })
        .collect()
}

/// The G function. Six 32-bit additions -> 6 * 31 = 186 non-free gates.
/// Everything else (XOR, rotate) is free.
#[allow(clippy::too_many_arguments)]
fn g<C: CircuitContext>(
    c: &mut C,
    v: &mut Vec<Vec<WireId>>,
    a: usize,
    b: usize,
    cc: usize,
    d: usize,
    mx: &[WireId],
    my: &[WireId],
) {
    let t = add_mod2w(c, &v[a], &v[b]);
    v[a] = add_mod2w(c, &t, mx);
    let t = xor_word(c, &v[d], &v[a]);
    v[d] = rotr(&t, 16);
    v[cc] = add_mod2w(c, &v[cc], &v[d]);
    let t = xor_word(c, &v[b], &v[cc]);
    v[b] = rotr(&t, 12);

    let t = add_mod2w(c, &v[a], &v[b]);
    v[a] = add_mod2w(c, &t, my);
    let t = xor_word(c, &v[d], &v[a]);
    v[d] = rotr(&t, 8);
    v[cc] = add_mod2w(c, &v[cc], &v[d]);
    let t = xor_word(c, &v[b], &v[cc]);
    v[b] = rotr(&t, 7);
}

fn round<C: CircuitContext>(c: &mut C, v: &mut Vec<Vec<WireId>>, m: &[Vec<WireId>]) {
    // Columns
    let m0 = m[0].clone();
    let m1 = m[1].clone();
    g(c, v, 0, 4, 8, 12, &m0, &m1);
    let m2 = m[2].clone();
    let m3 = m[3].clone();
    g(c, v, 1, 5, 9, 13, &m2, &m3);
    let m4 = m[4].clone();
    let m5 = m[5].clone();
    g(c, v, 2, 6, 10, 14, &m4, &m5);
    let m6 = m[6].clone();
    let m7 = m[7].clone();
    g(c, v, 3, 7, 11, 15, &m6, &m7);
    // Diagonals
    let m8 = m[8].clone();
    let m9 = m[9].clone();
    g(c, v, 0, 5, 10, 15, &m8, &m9);
    let m10 = m[10].clone();
    let m11 = m[11].clone();
    g(c, v, 1, 6, 11, 12, &m10, &m11);
    let m12 = m[12].clone();
    let m13 = m[13].clone();
    g(c, v, 2, 7, 8, 13, &m12, &m13);
    let m14 = m[14].clone();
    let m15 = m[15].clone();
    g(c, v, 3, 4, 9, 14, &m14, &m15);
}

/// BLAKE3 compression. Returns the 16-word output vector `v`.
pub fn compress<C: CircuitContext>(
    c: &mut C,
    chaining: &[Vec<WireId>],
    block: &[Vec<WireId>],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> Vec<Vec<WireId>> {
    assert_eq!(chaining.len(), 8);
    assert_eq!(block.len(), 16);

    let mut v: Vec<Vec<WireId>> = Vec::with_capacity(16);
    for w in chaining.iter() {
        v.push(w.clone());
    }
    for i in 0..4 {
        v.push(const_word(IV[i]));
    }
    v.push(const_word(counter as u32));
    v.push(const_word((counter >> 32) as u32));
    v.push(const_word(block_len));
    v.push(const_word(flags));

    let mut m: Vec<Vec<WireId>> = block.to_vec();
    for r in 0..7 {
        round(c, &mut v, &m);
        if r < 6 {
            let permuted: Vec<Vec<WireId>> =
                MSG_PERMUTATION.iter().map(|&i| m[i].clone()).collect();
            m = permuted;
        }
    }

    // FREE: v[i] ^= v[i+8]; v[i+8] ^= chaining[i]
    let mut out: Vec<Vec<WireId>> = Vec::with_capacity(16);
    for i in 0..8 {
        out.push(xor_word(c, &v[i], &v[i + 8]));
    }
    for i in 0..8 {
        out.push(xor_word(c, &v[i + 8], &chaining[i]));
    }
    out
}

/// BLAKE3 of an input of at most 64 bytes: one compression, root output,
/// first 32 bytes.
///
/// `msg_bits` is the input as a little-endian-within-word bit layout produced
/// by `bytes_to_words_le`.
pub fn hash_one_block<C: CircuitContext>(
    c: &mut C,
    block_words: &[Vec<WireId>],
    input_len: usize,
) -> Vec<WireId> {
    let chaining: Vec<Vec<WireId>> = IV.iter().map(|v| const_word(*v)).collect();
    let flags = CHUNK_START | CHUNK_END | ROOT;
    let out = compress(c, &chaining, block_words, 0, input_len as u32, flags);

    // First 8 words, emitted as little-endian bytes.
    let mut res = Vec::with_capacity(256);
    for word in out.iter().take(8) {
        for byte in 0..4 {
            for bit in 0..8 {
                res.push(word[byte * 8 + bit]);
            }
        }
    }
    res
}

/// Split a byte slice into 16 little-endian 32-bit words of bits, zero padded.
pub fn bytes_to_word_bits_le(bytes: &[u8]) -> Vec<Vec<bool>> {
    let mut padded = bytes.to_vec();
    padded.resize(64, 0);
    (0..16)
        .map(|i| {
            let w = u32::from_le_bytes([
                padded[i * 4],
                padded[i * 4 + 1],
                padded[i * 4 + 2],
                padded[i * 4 + 3],
            ]);
            (0..32).map(|b| (w >> b) & 1 == 1).collect()
        })
        .collect()
}

/// Same layout, but as wire slices grouped into words.
pub fn group_words(wires: &[WireId]) -> Vec<Vec<WireId>> {
    assert_eq!(wires.len(), 512);
    (0..16).map(|i| wires[i * 32..(i + 1) * 32].to_vec()).collect()
}

pub const _UNUSED: WireId = FALSE;
