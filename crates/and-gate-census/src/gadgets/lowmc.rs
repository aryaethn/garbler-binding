//! LowMC as a Boolean circuit: the low-multiplicative-complexity baseline.
//!
//! LowMC is the extreme point of the design space this crate is exploring. Its
//! linear layer is a full n x n binary matrix multiply, which under free-XOR
//! costs *nothing*. Its only non-free cost is the S-box layer: m 3-bit S-boxes
//! per round, 3 AND gates each. So:
//!
//!     non-free gates = 3 * m * r
//!
//! For LowMC-128 with m=10, r=20 that is 600 non-free gates for a 128-bit
//! block, versus ~22,700 for one SHA-256 compression. Roughly 38x cheaper per
//! block, and ~19x cheaper per byte of input.
//!
//! IMPORTANT CAVEAT, do not skip this. LowMC has a difficult cryptanalytic
//! history: several parameter sets have been broken or weakened by algebraic
//! attacks (difference enumeration, higher-order differentials), and the
//! recommended parameters have moved more than once. Nothing here should be
//! read as a recommendation to deploy LowMC in a Bitcoin bridge. It is
//! included because it establishes the *lower bound* of what a
//! garbling-friendly primitive can cost, which is the number you need in order
//! to know how much room a better hash choice actually buys you. If the answer
//! is "an order of magnitude", the design question is worth pursuing with a
//! primitive that has survived more scrutiny (Rain, or a fixed-key AES
//! construction, or a carefully chosen sponge over a binary field).

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{and, xor, FALSE, TRUE};

/// Deterministic xorshift so circuit and reference agree on the matrices.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    pub fn next_bit(&mut self) -> bool {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x & 1 == 1
    }
}

#[derive(Clone)]
pub struct Params {
    pub n: usize,
    pub m: usize,
    pub r: usize,
}

impl Params {
    /// Non-free gate count is fully determined by the parameters.
    pub fn predicted_nonfree(&self) -> u64 {
        (3 * self.m * self.r) as u64
    }
}

pub struct Constants {
    pub lin: Vec<Vec<Vec<bool>>>,   // r matrices, each n x n
    pub round_c: Vec<Vec<bool>>,    // r constants of n bits
    pub round_k: Vec<Vec<bool>>,    // r+1 round keys of n bits
}

pub fn gen_constants(p: &Params, seed: u64) -> Constants {
    let mut rng = Rng::new(seed);
    let lin = (0..p.r)
        .map(|_| {
            (0..p.n)
                .map(|_| (0..p.n).map(|_| rng.next_bit()).collect())
                .collect()
        })
        .collect();
    let round_c = (0..p.r)
        .map(|_| (0..p.n).map(|_| rng.next_bit()).collect())
        .collect();
    let round_k = (0..=p.r)
        .map(|_| (0..p.n).map(|_| rng.next_bit()).collect())
        .collect();
    Constants {
        lin,
        round_c,
        round_k,
    }
}

/// FREE: multiply the state by a constant binary matrix.
fn lin_layer<C: CircuitContext>(c: &mut C, state: &[WireId], mat: &[Vec<bool>]) -> Vec<WireId> {
    let n = state.len();
    (0..n)
        .map(|row| {
            let mut acc: Option<WireId> = None;
            for col in 0..n {
                if mat[row][col] {
                    acc = Some(match acc {
                        None => state[col],
                        Some(prev) => xor(c, prev, state[col]),
                    });
                }
            }
            acc.unwrap_or(FALSE)
        })
        .collect()
}

/// FREE: XOR in a constant.
fn add_const<C: CircuitContext>(c: &mut C, state: &[WireId], k: &[bool]) -> Vec<WireId> {
    state
        .iter()
        .zip(k)
        .map(|(w, &b)| if b { xor(c, *w, TRUE) } else { *w })
        .collect()
}

/// 3 non-free gates per S-box.
fn sbox_layer<C: CircuitContext>(c: &mut C, state: &[WireId], m: usize) -> Vec<WireId> {
    let mut out = state.to_vec();
    for i in 0..m {
        let a = state[3 * i];
        let b = state[3 * i + 1];
        let d = state[3 * i + 2];

        let bd = and(c, b, d);       // non-free
        let ad = and(c, a, d);       // non-free
        let ab = and(c, a, b);       // non-free

        out[3 * i] = xor(c, a, bd);
        let t = xor(c, a, b);
        out[3 * i + 1] = xor(c, t, ad);
        let t2 = xor(c, t, d);
        out[3 * i + 2] = xor(c, t2, ab);
    }
    out
}

pub fn encrypt<C: CircuitContext>(
    c: &mut C,
    p: &Params,
    k: &Constants,
    block: &[WireId],
) -> Vec<WireId> {
    let mut state = add_const(c, block, &k.round_k[0]);
    for round in 0..p.r {
        state = sbox_layer(c, &state, p.m);
        state = lin_layer(c, &state, &k.lin[round]);
        state = add_const(c, &state, &k.round_c[round]);
        state = add_const(c, &state, &k.round_k[round + 1]);
    }
    state
}

// --- native reference, same construction ---

fn ref_lin(state: &[bool], mat: &[Vec<bool>]) -> Vec<bool> {
    let n = state.len();
    (0..n)
        .map(|row| {
            let mut acc = false;
            for col in 0..n {
                if mat[row][col] {
                    acc ^= state[col];
                }
            }
            acc
        })
        .collect()
}

fn ref_add(state: &[bool], k: &[bool]) -> Vec<bool> {
    state.iter().zip(k).map(|(a, b)| a ^ b).collect()
}

fn ref_sbox(state: &[bool], m: usize) -> Vec<bool> {
    let mut out = state.to_vec();
    for i in 0..m {
        let (a, b, d) = (state[3 * i], state[3 * i + 1], state[3 * i + 2]);
        out[3 * i] = a ^ (b & d);
        out[3 * i + 1] = a ^ b ^ (a & d);
        out[3 * i + 2] = a ^ b ^ d ^ (a & b);
    }
    out
}

pub fn ref_encrypt(p: &Params, k: &Constants, block: &[bool]) -> Vec<bool> {
    let mut state = ref_add(block, &k.round_k[0]);
    for round in 0..p.r {
        state = ref_sbox(&state, p.m);
        state = ref_lin(&state, &k.lin[round]);
        state = ref_add(&state, &k.round_c[round]);
        state = ref_add(&state, &k.round_k[round + 1]);
    }
    state
}
