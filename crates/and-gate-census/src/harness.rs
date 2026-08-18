//! Measurement harness.
//!
//! Every gadget in this crate is measured the same way: build it as a real
//! circuit in the `garbled-snark-verifier` DSL, run it in `ExecuteMode` on
//! concrete inputs, compare the circuit's output against a native reference
//! implementation, and report the gate census.
//!
//! The correctness check is not optional decoration. A gate count for a circuit
//! that computes the wrong function is worthless, and it is very easy to write
//! a "cheap" circuit that is simply wrong.
//!
//! Free vs non-free follows `GateType::is_free()` upstream: XOR, XNOR and NOT
//! are free under free-XOR; the eight odd-parity gates (AND, NAND, NIMP, IMP,
//! NCIMP, CIMP, NOR, OR) each cost two ciphertexts under half-gates.

use garbled_snark_verifier::{
    circuit::{
        modes::CircuitMode, CircuitBuilder, CircuitInput, EncodeInput, ExecuteMode, StreamingResult,
    },
    WireId,
};
use serde::Serialize;

/// A flat bit-vector circuit input. Every gadget here takes `&[WireId]` and
/// returns `Vec<WireId>`, so one input type covers the whole crate.
pub struct BitVecInput {
    pub bits: Vec<bool>,
}

impl BitVecInput {
    pub fn new(bits: Vec<bool>) -> Self {
        Self { bits }
    }

    /// Little-endian bit expansion of `v`, `n` bits wide.
    pub fn from_u64(v: u64, n: usize) -> Vec<bool> {
        (0..n).map(|i| (v >> i) & 1 == 1).collect()
    }

    /// Big-endian byte string to bits, MSB-first within each byte.
    /// This is the convention SHA-256 and Keccak specs use.
    pub fn from_bytes_be(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
            .collect()
    }
}

impl CircuitInput for BitVecInput {
    type WireRepr = Vec<WireId>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.bits.len()).map(|_| issue()).collect()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.clone()
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for BitVecInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        for (w, b) in repr.iter().zip(self.bits.iter()) {
            cache.feed_wire(*w, *b);
        }
    }
}

/// One measured gadget.
#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    /// Gadget name, e.g. "gf2_128_tower_mul".
    pub name: String,
    /// Family used for grouping in the report, e.g. "binary_field".
    pub family: String,
    /// Free-form note carried into the report.
    pub note: String,
    /// Non-free (AND-variant) gate count. This is the number that matters:
    /// garbled circuit size is 2 ciphertexts x 16 B per non-free gate.
    pub nonfree: u64,
    /// Free (XOR / XNOR / NOT) gate count.
    pub free: u64,
    pub total: u64,
    /// Per-`GateType` breakdown, indices matching upstream `GateType`.
    pub breakdown: [u64; 11],
    /// Did the circuit reproduce the native reference output?
    pub verified: bool,
    /// Denominator for the normalized column, e.g. bits of field element,
    /// or bytes of hash input. `None` suppresses normalization.
    pub unit_size: Option<u64>,
    pub unit_label: String,
}

impl Measurement {
    /// Garbled size in bytes under half-gates: 2 ciphertexts of 16 B per
    /// non-free gate. This is the convention the BitVM3 paper uses when it
    /// quotes 2.7e9 non-free gates as 41.2 GB.
    pub fn garbled_bytes(&self) -> u64 {
        self.nonfree * 16
    }

    pub fn nonfree_per_unit(&self) -> Option<f64> {
        self.unit_size
            .filter(|u| *u > 0)
            .map(|u| self.nonfree as f64 / u as f64)
    }
}

/// Build, execute, verify and census a gadget.
///
/// `f` receives the input wires and returns the output wires. `expected` is the
/// native reference output, compared bit for bit against the circuit's output.
pub fn measure<F>(
    name: &str,
    family: &str,
    note: &str,
    input_bits: Vec<bool>,
    expected: &[bool],
    unit_size: Option<u64>,
    unit_label: &str,
    f: F,
) -> Measurement
where
    F: Fn(&mut garbled_snark_verifier::circuit::StreamingMode<ExecuteMode>, &[WireId]) -> Vec<WireId>,
{
    let input = BitVecInput::new(input_bits);

    let result: StreamingResult<ExecuteMode, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(input, 200_000, |ctx, wires| f(ctx, wires));

    let got = result.output_value;
    let verified = got.len() == expected.len() && got.iter().zip(expected).all(|(a, b)| a == b);

    if !verified {
        eprintln!(
            "WARNING: {name} failed verification (got {} bits, expected {} bits)",
            got.len(),
            expected.len()
        );
        if got.len() == expected.len() {
            let diff = got
                .iter()
                .zip(expected)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .count();
            eprintln!("         {diff} bits differ");
        }
    }

    let gc = result.gate_count;
    let nonfree = gc.nonfree_gate_count();
    let total = gc.total_gate_count();

    Measurement {
        name: name.to_string(),
        family: family.to_string(),
        note: note.to_string(),
        nonfree,
        free: total.saturating_sub(nonfree),
        total,
        breakdown: gc.0,
        verified,
        unit_size,
        unit_label: unit_label.to_string(),
    }
}
