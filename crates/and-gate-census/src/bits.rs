//! Bit-level helpers over the `garbled-snark-verifier` circuit DSL.
//!
//! Cost convention, which is the whole point of this crate:
//!   - `xor`, `xnor`, `not`  -> FREE (0 ciphertexts, free-XOR)
//!   - `and` and friends     -> 1 non-free gate (2 ciphertexts under half-gates)
//!
//! Anything expressible as a GF(2)-linear map of the input wires is therefore
//! free. That includes, notably, multiplication by a *constant* in a binary
//! field, and all of the bit permutations / rotations below.

use garbled_snark_verifier::{
    circuit::{CircuitContext, TRUE_WIRE},
    Gate, GateType, WireId,
};

/// FREE: c = a XOR b
pub fn xor<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let o = c.issue_wire();
    c.add_gate(Gate::new(GateType::Xor, a, b, o));
    o
}

/// FREE: c = NOT a, realized as a XOR 1.
pub fn not<C: CircuitContext>(c: &mut C, a: WireId) -> WireId {
    let o = c.issue_wire();
    c.add_gate(Gate::new(GateType::Xor, a, TRUE_WIRE, o));
    o
}

/// NON-FREE: c = a AND b. This is the only thing we are counting.
pub fn and<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let o = c.issue_wire();
    c.add_gate(Gate::new(GateType::And, a, b, o));
    o
}

/// NON-FREE: c = a OR b, as a single odd-parity gate (still 2 ciphertexts).
pub fn or<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let o = c.issue_wire();
    c.add_gate(Gate::new(GateType::Or, a, b, o));
    o
}

/// NON-FREE: c = a AND (NOT b), one gate.
pub fn and_not<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let o = c.issue_wire();
    c.add_gate(Gate::new(GateType::Nimp, a, b, o));
    o
}

/// FREE: elementwise XOR of two equal-length words.
pub fn xor_word<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| xor(c, *x, *y)).collect()
}

/// NON-FREE: elementwise AND, one non-free gate per bit.
pub fn and_word<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| and(c, *x, *y)).collect()
}

/// FREE: elementwise NOT.
pub fn not_word<C: CircuitContext>(c: &mut C, a: &[WireId]) -> Vec<WireId> {
    a.iter().map(|x| not(c, *x)).collect()
}

/// FREE: rotate right by `n` on a little-endian word (bit 0 = LSB).
/// Pure rewiring, zero gates.
pub fn rotr(a: &[WireId], n: usize) -> Vec<WireId> {
    let w = a.len();
    let n = n % w;
    (0..w).map(|i| a[(i + n) % w]).collect()
}

/// FREE: rotate left.
pub fn rotl(a: &[WireId], n: usize) -> Vec<WireId> {
    let w = a.len();
    rotr(a, w - (n % w))
}

/// FREE: shift right, zero-filled.
pub fn shr(a: &[WireId], n: usize) -> Vec<WireId> {
    let w = a.len();
    (0..w)
        .map(|i| if i + n < w { a[i + n] } else { FALSE })
        .collect()
}

pub const FALSE: WireId = garbled_snark_verifier::circuit::FALSE_WIRE;
pub const TRUE: WireId = TRUE_WIRE;

/// Ripple-carry adder, ignoring final carry (i.e. mod 2^w).
///
/// Cost: exactly `w - 1` non-free gates for a w-bit add (the LSB is a half
/// adder whose carry costs 1 AND; each subsequent full adder costs 1 AND; the
/// final carry-out is discarded so the top full adder's carry AND is skipped).
/// This is the cheapest known generic adder in the free-XOR model and it is
/// the reason prime-field arithmetic is expensive: every modular addition and
/// every partial-product accumulation pays roughly one non-free gate per bit.
pub fn add_mod2w<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    let w = a.len();
    let mut out = Vec::with_capacity(w);

    // Half adder for bit 0.
    let s0 = xor(c, a[0], b[0]);
    out.push(s0);
    if w == 1 {
        return out;
    }
    let mut carry = and(c, a[0], b[0]);

    for i in 1..w {
        // Full adder: sum = a ^ b ^ c (free);
        // carry' = c ^ ((a ^ c) & (b ^ c))  -> 1 non-free gate.
        let axc = xor(c, a[i], carry);
        let bxc = xor(c, b[i], carry);
        let s = xor(c, a[i], bxc);
        out.push(s);
        if i + 1 < w {
            let t = and(c, axc, bxc);
            carry = xor(c, carry, t);
        }
    }
    out
}

/// Full-width adder returning `w + 1` bits.
pub fn add_full<C: CircuitContext>(c: &mut C, a: &[WireId], b: &[WireId]) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    let w = a.len();
    let mut out = Vec::with_capacity(w + 1);

    let s0 = xor(c, a[0], b[0]);
    out.push(s0);
    let mut carry = and(c, a[0], b[0]);

    for i in 1..w {
        let axc = xor(c, a[i], carry);
        let bxc = xor(c, b[i], carry);
        let s = xor(c, a[i], bxc);
        out.push(s);
        let t = and(c, axc, bxc);
        carry = xor(c, carry, t);
    }
    out.push(carry);
    out
}

/// NON-FREE (1 gate per bit): select `if s { a } else { b }`, bitwise.
/// mux(s, a, b) = b XOR (s AND (a XOR b)).
pub fn mux_word<C: CircuitContext>(
    c: &mut C,
    s: WireId,
    a: &[WireId],
    b: &[WireId],
) -> Vec<WireId> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(x, y)| {
            let d = xor(c, *x, *y);
            let t = and(c, s, d);
            xor(c, *y, t)
        })
        .collect()
}

/// Constant zero word.
pub fn zero_word(w: usize) -> Vec<WireId> {
    vec![FALSE; w]
}

/// FREE: XOR in a compile-time constant. Bits that are 0 cost nothing at all.
pub fn xor_const<C: CircuitContext>(c: &mut C, a: &[WireId], k: u64) -> Vec<WireId> {
    a.iter()
        .enumerate()
        .map(|(i, w)| {
            if (k >> i) & 1 == 1 {
                not(c, *w)
            } else {
                *w
            }
        })
        .collect()
}
