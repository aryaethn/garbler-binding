//! Binary field GF(2^k) arithmetic as Boolean circuits.
//!
//! The headline facts this module exists to *measure* rather than assert:
//!
//!   1. Field addition is XOR. FREE. Zero non-free gates.
//!   2. Multiplication by a fixed constant is a GF(2)-linear map. FREE.
//!   3. Squaring is the Frobenius endomorphism, also GF(2)-linear. FREE.
//!   4. General multiplication via Karatsuba costs 3^log2(k) non-free gates,
//!      i.e. k^1.585, with the reduction step free.
//!   5. Inversion via Itoh-Tsujii is ~log2(k) multiplications plus free
//!      squarings.
//!
//! Contrast with a prime field (see `primefield.rs`), where addition costs
//! about one non-free gate per bit because of carry propagation, and
//! multiplication costs roughly 2k^2 because both the partial products and
//! the accumulation tree are AND-bearing.
//!
//! Note on binary towers: Binius uses a Wiedemann-style tower
//! T_{i+1} = T_i[X]/(X^2 + X_{i-1} X + 1). Its multiplication recursion is
//! also "3 half-size multiplications plus GF(2)-linear glue", so its non-free
//! gate count is identical to the Karatsuba figure measured here. The tower's
//! advantage over a monolithic field is in the *free* part (fewer XORs, better
//! SIMD packing) and in embedding small subfields cheaply, neither of which
//! changes the garbling cost. We therefore measure Karatsuba as a faithful
//! proxy for tower multiplication and say so explicitly.

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{and, xor, FALSE};

/// Irreducible polynomial for GF(2^k), given as the exponents of the terms
/// below the leading x^k term. Standard low-weight choices.
pub fn irreducible_taps(k: usize) -> &'static [usize] {
    match k {
        8 => &[4, 3, 1, 0],      // x^8 + x^4 + x^3 + x + 1
        16 => &[5, 3, 1, 0],     // x^16 + x^5 + x^3 + x + 1
        32 => &[7, 3, 2, 0],     // x^32 + x^7 + x^3 + x^2 + 1
        64 => &[4, 3, 1, 0],     // x^64 + x^4 + x^3 + x + 1
        128 => &[7, 2, 1, 0],    // x^128 + x^7 + x^2 + x + 1
        _ => panic!("no irreducible polynomial registered for k={k}"),
    }
}

// ---------------------------------------------------------------------------
// Native reference implementation (bit-vector arithmetic, obviously correct)
// ---------------------------------------------------------------------------

/// Carry-less multiply of two little-endian bit vectors. Result is
/// `a.len() + b.len() - 1` bits.
pub fn ref_clmul(a: &[bool], b: &[bool]) -> Vec<bool> {
    let mut out = vec![false; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai {
            for (j, &bj) in b.iter().enumerate() {
                if bj {
                    out[i + j] ^= true;
                }
            }
        }
    }
    out
}

/// Reduce a `>= k` bit polynomial modulo the registered irreducible for k.
pub fn ref_reduce(p: &[bool], k: usize) -> Vec<bool> {
    let taps = irreducible_taps(k);
    let mut p = p.to_vec();
    if p.len() < k {
        p.resize(k, false);
    }
    for i in (k..p.len()).rev() {
        if p[i] {
            p[i] = false;
            for &t in taps {
                p[i - k + t] ^= true;
            }
        }
    }
    p.truncate(k);
    p
}

pub fn ref_mul(a: &[bool], b: &[bool], k: usize) -> Vec<bool> {
    ref_reduce(&ref_clmul(a, b), k)
}

pub fn ref_square(a: &[bool], k: usize) -> Vec<bool> {
    ref_mul(a, a, k)
}

/// a^(2^k - 2) = a^-1 for nonzero a.
pub fn ref_inv(a: &[bool], k: usize) -> Vec<bool> {
    // Simple square-and-multiply over the exponent 2^k - 2.
    let mut result = vec![false; k];
    result[0] = true; // 1
    let mut base = a.to_vec();
    // exponent 2^k - 2 = binary 111...10 (k-1 ones then a zero)
    // process LSB first
    let mut exp_bits = vec![false];
    exp_bits.extend(std::iter::repeat(true).take(k - 1));
    for bit in exp_bits {
        if bit {
            result = ref_mul(&result, &base, k);
        }
        base = ref_square(&base, k);
    }
    result
}

// ---------------------------------------------------------------------------
// Circuits
// ---------------------------------------------------------------------------

/// FREE: reduce a `2k-1` bit product down to `k` bits. Pure XOR.
fn reduce<C: CircuitContext>(c: &mut C, p: &[WireId], k: usize) -> Vec<WireId> {
    let taps = irreducible_taps(k);
    let mut p = p.to_vec();
    if p.len() < k {
        p.resize(k, FALSE);
    }
    for i in (k..p.len()).rev() {
        let hi = p[i];
        p[i] = FALSE;
        for &t in taps {
            let idx = i - k + t;
            p[idx] = xor(c, p[idx], hi);
        }
    }
    p.truncate(k);
    p
}

/// Schoolbook carry-less multiply. Exactly `k*k` non-free gates.
pub fn clmul_schoolbook<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    b: &[WireId],
) -> Vec<WireId> {
    let (n, m) = (a.len(), b.len());
    let mut acc: Vec<Option<WireId>> = vec![None; n + m - 1];
    for i in 0..n {
        for j in 0..m {
            let p = and(c, a[i], b[j]);
            acc[i + j] = Some(match acc[i + j] {
                None => p,
                Some(prev) => xor(c, prev, p),
            });
        }
    }
    acc.into_iter().map(|o| o.unwrap_or(FALSE)).collect()
}

/// Recursive Karatsuba carry-less multiply. `3^ceil(log2 k)` non-free gates.
pub fn clmul_karatsuba<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    b: &[WireId],
) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    if n == 1 {
        return vec![and(c, a[0], b[0])];
    }
    // Pad to even.
    if n % 2 == 1 {
        let mut a2 = a.to_vec();
        let mut b2 = b.to_vec();
        a2.push(FALSE);
        b2.push(FALSE);
        let mut r = clmul_karatsuba(c, &a2, &b2);
        r.truncate(2 * n - 1);
        return r;
    }

    let h = n / 2;
    let (a0, a1) = (&a[..h], &a[h..]);
    let (b0, b1) = (&b[..h], &b[h..]);

    let z0 = clmul_karatsuba(c, a0, b0); // 2h-1 bits
    let z2 = clmul_karatsuba(c, a1, b1); // 2h-1 bits

    // FREE: a0 ^ a1, b0 ^ b1
    let as_: Vec<WireId> = a0.iter().zip(a1).map(|(x, y)| xor(c, *x, *y)).collect();
    let bs: Vec<WireId> = b0.iter().zip(b1).map(|(x, y)| xor(c, *x, *y)).collect();
    let z1 = clmul_karatsuba(c, &as_, &bs);

    // FREE: z1 = z1 - z0 - z2 (XOR in char 2)
    let mid: Vec<WireId> = (0..2 * h - 1)
        .map(|i| {
            let t = xor(c, z1[i], z0[i]);
            xor(c, t, z2[i])
        })
        .collect();

    // FREE: assemble z0 + mid<<h + z2<<2h
    let mut out: Vec<WireId> = vec![FALSE; 2 * n - 1];
    for i in 0..2 * h - 1 {
        out[i] = z0[i];
    }
    for i in 0..2 * h - 1 {
        let idx = i + h;
        out[idx] = if out[idx] == FALSE {
            mid[i]
        } else {
            xor(c, out[idx], mid[i])
        };
    }
    for i in 0..2 * h - 1 {
        let idx = i + 2 * h;
        out[idx] = if out[idx] == FALSE {
            z2[i]
        } else {
            xor(c, out[idx], z2[i])
        };
    }
    out
}

/// GF(2^k) multiplication, schoolbook.
pub fn mul_schoolbook<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    b: &[WireId],
    k: usize,
) -> Vec<WireId> {
    let p = clmul_schoolbook(c, a, b);
    reduce(c, &p, k)
}

/// GF(2^k) multiplication, Karatsuba. This is the number that matters.
pub fn mul_karatsuba<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    b: &[WireId],
    k: usize,
) -> Vec<WireId> {
    let p = clmul_karatsuba(c, a, b);
    reduce(c, &p, k)
}

/// FREE: squaring. Frobenius is GF(2)-linear, so interleaving with zeros and
/// reducing costs only XOR gates. Expect exactly 0 non-free gates.
pub fn square<C: CircuitContext>(c: &mut C, a: &[WireId], k: usize) -> Vec<WireId> {
    let mut spread = vec![FALSE; 2 * k - 1];
    for i in 0..k {
        spread[2 * i] = a[i];
    }
    reduce(c, &spread, k)
}

/// FREE: multiplication by a compile-time constant. Expect 0 non-free gates.
pub fn mul_const<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    konst: &[bool],
    k: usize,
) -> Vec<WireId> {
    let mut acc: Vec<WireId> = vec![FALSE; a.len() + konst.len() - 1];
    for (j, &kj) in konst.iter().enumerate() {
        if !kj {
            continue;
        }
        for i in 0..a.len() {
            let idx = i + j;
            acc[idx] = if acc[idx] == FALSE {
                a[i]
            } else {
                xor(c, acc[idx], a[i])
            };
        }
    }
    reduce(c, &acc, k)
}

/// Inversion by square-and-multiply over exponent 2^k - 2.
///
/// All squarings are free, so the cost is exactly the number of
/// multiplications: k - 1 with the naive chain below. Itoh-Tsujii reduces this
/// to about `floor(log2(k-1)) + hw(k-1) - 1` multiplications; we measure the
/// naive chain here and report the Itoh-Tsujii figure as a multiple of the
/// measured multiplication cost, since the addition chain does not change the
/// per-multiplication price.
pub fn inv_naive<C: CircuitContext>(c: &mut C, a: &[WireId], k: usize) -> Vec<WireId> {
    let mut result: Vec<WireId> = vec![FALSE; k];
    result[0] = crate::bits::TRUE;
    let mut base = a.to_vec();
    let mut exp_bits = vec![false];
    exp_bits.extend(std::iter::repeat(true).take(k - 1));
    for bit in exp_bits {
        if bit {
            result = mul_karatsuba(c, &result, &base, k);
        }
        base = square(c, &base, k);
    }
    result
}
