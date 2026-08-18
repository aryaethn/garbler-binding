//! Prime field arithmetic as Boolean circuits, for the comparison baseline.
//!
//! The point of this module is to make the carry problem visible and countable.
//! In a prime field:
//!   - addition needs a carry chain: ~1 non-free gate per bit;
//!   - multiplication needs w^2 partial-product ANDs *plus* an accumulation
//!     tree whose every full adder costs another non-free gate, so ~2w^2;
//!   - reduction needs comparisons and conditional subtractions, more carries.
//!
//! In a binary field all three of those become XOR-only or cheap. That gap is
//! the entire thesis, and this module supplies the denominator.
//!
//! Fields measured:
//!   - M31       = 2^31 - 1              (Circle STARKs / Stwo)
//!   - Goldilocks = 2^64 - 2^32 + 1      (Plonky2/3)

use garbled_snark_verifier::{circuit::CircuitContext, WireId};

use crate::bits::{add_full, and, mux_word, not, xor, FALSE, TRUE};

/// Little-endian bits -> u128.
pub fn bits_to_u128(b: &[bool]) -> u128 {
    b.iter()
        .enumerate()
        .fold(0u128, |acc, (i, &v)| if v { acc | (1u128 << i) } else { acc })
}

pub fn u128_to_bits(v: u128, n: usize) -> Vec<bool> {
    (0..n).map(|i| (v >> i) & 1 == 1).collect()
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

/// Two's-complement subtract, returns (w bits of difference, borrow flag).
/// a - b computed as a + ~b + 1.
pub fn sub_with_borrow<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    b: &[WireId],
) -> (Vec<WireId>, WireId) {
    assert_eq!(a.len(), b.len());
    let w = a.len();
    let nb: Vec<WireId> = b.iter().map(|x| not(c, *x)).collect();

    // Ripple add with carry-in 1.
    let mut carry = TRUE;
    let mut out = Vec::with_capacity(w);
    for i in 0..w {
        let axc = xor(c, a[i], carry);
        let bxc = xor(c, nb[i], carry);
        let s = xor(c, a[i], bxc);
        out.push(s);
        let t = and(c, axc, bxc);
        carry = xor(c, carry, t);
    }
    // carry == 1 means no borrow (a >= b).
    let borrow = not(c, carry);
    (out, borrow)
}

/// Conditionally subtract the constant `p` if `a >= p`. Returns `a mod p`
/// assuming `a < 2p`.
pub fn cond_sub_const<C: CircuitContext>(
    c: &mut C,
    a: &[WireId],
    p: u128,
) -> Vec<WireId> {
    let w = a.len();
    let pbits: Vec<WireId> = (0..w)
        .map(|i| if (p >> i) & 1 == 1 { TRUE } else { FALSE })
        .collect();
    let (diff, borrow) = sub_with_borrow(c, a, &pbits);
    // borrow == 1 -> a < p -> keep a; else take diff.
    mux_word(c, borrow, a, &diff)
}

/// Unsigned schoolbook multiply, `w x w -> 2w` bits.
///
/// Cost: w^2 non-free gates for the partial products, plus roughly w^2 more
/// for the accumulation carries. This is the prime-field tax.
pub fn mul_unsigned<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    let w = a.len();
    assert_eq!(b.len(), w);

    let mut acc: Vec<WireId> = vec![FALSE; 2 * w];

    for j in 0..w {
        // Row j = a * b[j], shifted left by j.
        let row: Vec<WireId> = (0..w).map(|i| and(c, a[i], b[j])).collect();
        // Add row into acc starting at position j.
        let window: Vec<WireId> = acc[j..j + w].to_vec();
        let sum = add_full(c, &window, &row); // w+1 bits
        for i in 0..w {
            acc[j + i] = sum[i];
        }
        // Propagate the carry-out upward.
        let mut carry = sum[w];
        let mut pos = j + w;
        while pos < 2 * w {
            if carry == FALSE {
                break;
            }
            let s = xor(c, acc[pos], carry);
            let nc = and(c, acc[pos], carry);
            acc[pos] = s;
            carry = nc;
            pos += 1;
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// M31 = 2^31 - 1
// ---------------------------------------------------------------------------

pub const M31_P: u128 = (1 << 31) - 1;

/// Modular addition in M31. One full 31-bit add plus a conditional subtract.
pub fn m31_add<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    let s = add_full(c, a, b); // 32 bits
    let r = cond_sub_const(c, &s, M31_P);
    r[..31].to_vec()
}

/// Modular multiplication in M31, with the Mersenne fold.
pub fn m31_mul<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    let prod = mul_unsigned(c, a, b); // 62 bits
    // x = hi * 2^31 + lo, and 2^31 = 1 (mod p), so x = hi + lo (mod p).
    let lo: Vec<WireId> = prod[..31].to_vec();
    let hi: Vec<WireId> = prod[31..62].to_vec();
    let s = add_full(c, &lo, &hi); // 32 bits
    let r = cond_sub_const(c, &s, M31_P);
    // One more fold is enough: s < 2p.
    r[..31].to_vec()
}

// ---------------------------------------------------------------------------
// Goldilocks = 2^64 - 2^32 + 1
// ---------------------------------------------------------------------------

pub const GOLDILOCKS_P: u128 = (1u128 << 64) - (1u128 << 32) + 1;

/// Modular addition in Goldilocks.
pub fn goldilocks_add<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    let s = add_full(c, a, b); // 65 bits
    let r = cond_sub_const(c, &s, GOLDILOCKS_P);
    r[..64].to_vec()
}

/// Modular multiplication in Goldilocks using the standard fast reduction.
///
/// With x = x0 + x1*2^64 + x2*2^96 (x0 64 bits, x1 and x2 32 bits each):
///   2^64 = 2^32 - 1  (mod p)
///   2^96 = -1        (mod p)
/// so  x = x0 + x1*(2^32 - 1) - x2  (mod p).
pub fn goldilocks_mul<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    let prod = mul_unsigned(c, a, b); // 128 bits

    let x0: Vec<WireId> = prod[..64].to_vec();
    let x1: Vec<WireId> = prod[64..96].to_vec();
    let x2: Vec<WireId> = prod[96..128].to_vec();

    // x1 * (2^32 - 1) = (x1 << 32) - x1, in 64+ bits. FREE shift.
    let mut x1_shift: Vec<WireId> = vec![FALSE; 32];
    x1_shift.extend_from_slice(&x1); // 64 bits
    let mut x1_ext: Vec<WireId> = x1.clone();
    x1_ext.extend(std::iter::repeat(FALSE).take(32)); // 64 bits

    let (t1, _b1) = sub_with_borrow(c, &x1_shift, &x1_ext);

    // acc = x0 + t1
    let s = add_full(c, &x0, &t1); // 65 bits
    let s64: Vec<WireId> = s[..64].to_vec();
    let carry = s[64];

    // Fold the carry: 2^64 = 2^32 - 1 (mod p).
    let mut carry_term: Vec<WireId> = vec![FALSE; 64];
    carry_term[32] = carry; // carry << 32
    let (ct, _) = {
        let mut c_ext = vec![FALSE; 64];
        c_ext[0] = carry;
        sub_with_borrow(c, &carry_term, &c_ext)
    };
    let s2 = add_full(c, &s64, &ct);
    let s2_64: Vec<WireId> = s2[..64].to_vec();

    // subtract x2
    let mut x2_ext: Vec<WireId> = x2.clone();
    x2_ext.extend(std::iter::repeat(FALSE).take(32));
    let (d, borrow) = sub_with_borrow(c, &s2_64, &x2_ext);

    // If we borrowed, add p back.
    let pbits: Vec<WireId> = (0..64)
        .map(|i| if (GOLDILOCKS_P >> i) & 1 == 1 { TRUE } else { FALSE })
        .collect();
    let fixed = add_full(c, &d, &pbits);
    let fixed64: Vec<WireId> = fixed[..64].to_vec();
    let r = mux_word(c, borrow, &fixed64, &d);

    // Final conditional reductions (up to two, cheap relative to the multiply).
    let mut r_ext = r.clone();
    r_ext.push(FALSE);
    let r1 = cond_sub_const(c, &r_ext, GOLDILOCKS_P);
    let mut r1_ext = r1[..64].to_vec();
    r1_ext.push(FALSE);
    let r2 = cond_sub_const(c, &r1_ext, GOLDILOCKS_P);
    r2[..64].to_vec()
}

// ---------------------------------------------------------------------------
// Native references
// ---------------------------------------------------------------------------

pub fn ref_m31_add(a: u128, b: u128) -> u128 {
    (a + b) % M31_P
}
pub fn ref_m31_mul(a: u128, b: u128) -> u128 {
    (a * b) % M31_P
}
pub fn ref_goldilocks_add(a: u128, b: u128) -> u128 {
    (a + b) % GOLDILOCKS_P
}
pub fn ref_goldilocks_mul(a: u128, b: u128) -> u128 {
    (a * b) % GOLDILOCKS_P
}
pub fn ref_mul_unsigned(a: u128, b: u128) -> u128 {
    a * b
}
