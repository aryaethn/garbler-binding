//! SHA-256 as a Boolean circuit.
//!
//! Measured as a single-block hash (message <= 55 bytes), which is exactly one
//! invocation of the compression function plus free padding. Validated against
//! the `sha2` crate.
//!
//! Expected cost is ~22-23k non-free gates, matching the long-standing
//! literature figure for SHA-256's multiplicative complexity. That agreement
//! is the second calibration check in this crate (the first being the 2.7e9
//! BN254 Groth16 anchor).
//!
//! Where the ANDs go:
//!   - Ch(e,f,g)  = g ^ (e & (f ^ g))          -> 32 per round
//!   - Maj(a,b,c) = b ^ ((a^b) & (b^c))        -> 32 per round
//!   - every mod-2^32 addition                 -> 31 each
//!   - Sigma/sigma rotations and shifts        -> FREE
//!
//! So SHA-256 is dominated by *addition carries*, not by its logical
//! operations. This matters: it means an ARX hash is a bad choice for a
//! garbled verifier, and a hash built from XOR plus a small number of ANDs
//! (see `lowmc.rs`) is dramatically cheaper.

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{add_mod2w, and, rotr, shr, xor, xor_word, FALSE, TRUE};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn const_word(v: u32) -> Vec<WireId> {
    (0..32)
        .map(|i| if (v >> i) & 1 == 1 { TRUE } else { FALSE })
        .collect()
}

/// Ch(e,f,g) = (e & f) ^ (~e & g) = g ^ (e & (f ^ g)). 32 non-free gates.
fn ch<C: CircuitContext>(c: &mut C, e: &[WireId], f: &[WireId], g: &[WireId]) -> Vec<WireId> {
    (0..32)
        .map(|i| {
            let fg = xor(c, f[i], g[i]);
            let t = and(c, e[i], fg);
            xor(c, g[i], t)
        })
        .collect()
}

/// Maj(a,b,c) = b ^ ((a ^ b) & (b ^ c)). 32 non-free gates.
fn maj<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId], cc: &[WireId]) -> Vec<WireId> {
    (0..32)
        .map(|i| {
            let ab = xor(c, a[i], b[i]);
            let bc = xor(c, b[i], cc[i]);
            let t = and(c, ab, bc);
            xor(c, b[i], t)
        })
        .collect()
}

/// FREE
fn big_sigma0<C: CircuitContext>(c: &mut C, x: &[WireId]) -> Vec<WireId> {
    let a = rotr(x, 2);
    let b = rotr(x, 13);
    let d = rotr(x, 22);
    let t = xor_word(c, &a, &b);
    xor_word(c, &t, &d)
}

/// FREE
fn big_sigma1<C: CircuitContext>(c: &mut C, x: &[WireId]) -> Vec<WireId> {
    let a = rotr(x, 6);
    let b = rotr(x, 11);
    let d = rotr(x, 25);
    let t = xor_word(c, &a, &b);
    xor_word(c, &t, &d)
}

/// FREE
fn small_sigma0<C: CircuitContext>(c: &mut C, x: &[WireId]) -> Vec<WireId> {
    let a = rotr(x, 7);
    let b = rotr(x, 18);
    let d = shr(x, 3);
    let t = xor_word(c, &a, &b);
    xor_word(c, &t, &d)
}

/// FREE
fn small_sigma1<C: CircuitContext>(c: &mut C, x: &[WireId]) -> Vec<WireId> {
    let a = rotr(x, 17);
    let b = rotr(x, 19);
    let d = shr(x, 10);
    let t = xor_word(c, &a, &b);
    xor_word(c, &t, &d)
}

/// One SHA-256 compression: 512-bit block (as 16 little-endian-bit 32-bit
/// words) folded into an 8-word state.
pub fn compress<C: CircuitContext>(
    c: &mut C,
    state: &[Vec<WireId>],
    block: &[Vec<WireId>],
) -> Vec<Vec<WireId>> {
    assert_eq!(state.len(), 8);
    assert_eq!(block.len(), 16);

    // Message schedule.
    let mut w: Vec<Vec<WireId>> = block.to_vec();
    for t in 16..64 {
        let s0 = small_sigma0(c, &w[t - 15]);
        let s1 = small_sigma1(c, &w[t - 2]);
        let x = add_mod2w(c, &s1, &w[t - 7]);
        let y = add_mod2w(c, &s0, &w[t - 16]);
        let z = add_mod2w(c, &x, &y);
        w.push(z);
    }

    let mut a = state[0].clone();
    let mut b = state[1].clone();
    let mut cc = state[2].clone();
    let mut d = state[3].clone();
    let mut e = state[4].clone();
    let mut f = state[5].clone();
    let mut g = state[6].clone();
    let mut h = state[7].clone();

    for t in 0..64 {
        let s1 = big_sigma1(c, &e);
        let chv = ch(c, &e, &f, &g);
        let kt = const_word(K[t]);

        let t1a = add_mod2w(c, &h, &s1);
        let t1b = add_mod2w(c, &t1a, &chv);
        let t1c = add_mod2w(c, &t1b, &kt);
        let t1 = add_mod2w(c, &t1c, &w[t]);

        let s0 = big_sigma0(c, &a);
        let majv = maj(c, &a, &b, &cc);
        let t2 = add_mod2w(c, &s0, &majv);

        h = g;
        g = f;
        f = e;
        e = add_mod2w(c, &d, &t1);
        d = cc;
        cc = b;
        b = a;
        a = add_mod2w(c, &t1, &t2);
    }

    let ns = [a, b, cc, d, e, f, g, h];
    (0..8)
        .map(|i| add_mod2w(c, &state[i], &ns[i]))
        .collect()
}

/// Full SHA-256 of a message of at most 55 bytes: exactly one compression.
///
/// `msg_bits` is the message, MSB-first within each byte (the SHA-256
/// convention). Padding is applied with constant wires and is free.
pub fn hash_one_block<C: CircuitContext>(
    c: &mut C,
    msg_bits: &[WireId],
    msg_len_bytes: usize,
) -> Vec<WireId> {
    assert!(msg_len_bytes <= 55, "single-block path only");
    assert_eq!(msg_bits.len(), msg_len_bytes * 8);

    // Build the 512-bit padded block as a big-endian bit string.
    let mut be: Vec<WireId> = msg_bits.to_vec();
    be.push(TRUE); // the 0x80 leading 1 bit
    while be.len() < 448 {
        be.push(FALSE);
    }
    let bitlen = (msg_len_bytes as u64) * 8;
    for i in (0..64).rev() {
        be.push(if (bitlen >> i) & 1 == 1 { TRUE } else { FALSE });
    }
    assert_eq!(be.len(), 512);

    // Convert to 16 words, each stored little-endian-by-bit-index.
    let block: Vec<Vec<WireId>> = (0..16)
        .map(|i| {
            let chunk = &be[i * 32..(i + 1) * 32];
            // chunk is MSB-first; our words are LSB-first.
            chunk.iter().rev().copied().collect()
        })
        .collect();

    let state: Vec<Vec<WireId>> = H0.iter().map(|v| const_word(*v)).collect();
    let out = compress(c, &state, &block);

    // Emit as a big-endian bit string, 256 bits.
    let mut res = Vec::with_capacity(256);
    for word in out.iter() {
        for i in (0..32).rev() {
            res.push(word[i]);
        }
    }
    res
}
