//! Step 2: does the real BN254 Groth16 verifier circuit contain an exploitable
//! affine split near its output?
//!
//! Attack 4 in `garbler-binding-attack.md` needs the output label to factor as
//! `Z = g(L_S) ⊕ h(L_T)` for disjoint input-wire sets `S`, `T`. The proof of
//! concept in `garbling-attack/` demonstrates the attack on a circuit built to
//! have that structure. This asks whether the circuit BitVM3-core actually
//! garbles has it.
//!
//! Method. A custom `CircuitMode` runs the real verifier circuit and does two
//! things at once:
//!
//!   1. **Dependency sketch.** Every wire carries a 64-bit value; input wire `i`
//!      is seeded with bit `i mod 64`, and every gate ORs its inputs. So a
//!      wire's sketch records which of the 64 residue classes of input wires it
//!      depends on. Popcount 64 means the wire depends on inputs drawn from
//!      every class, which is strong evidence of a broad cone.
//!
//!   2. **Tail recording.** The last `RING` gates are kept in a circular buffer
//!      with their wire ids and sketches, so the *linear frontier* of the output
//!      can be reconstructed exactly by an offline backward walk: from the
//!      output wire, step back through free (XOR/XNOR/NOT) gates only, and stop
//!      at non-free gates or circuit inputs. Atoms reached with even parity
//!      cancel, matching the label algebra.
//!
//! The frontier is exact. The independence test between frontier atoms is
//! evidence rather than proof: a low popcount is a lead to chase, a popcount of
//! 64 on every atom means no split is detectable at this resolution.
//!
//! Run:  cargo run --release

use std::{collections::HashMap, num::NonZero};

use ark_ec::AffineRepr;
use garbled_snark_verifier::{
    ark::{self, CircuitSpecificSetupSNARK, UniformRand, SNARK},
    circuit::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult,
    },
    garbled_groth16,
    storage::{Credits, Storage},
    Gate, GateType, WireId,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const RING: usize = 1 << 21; // 2M gates of tail

// ---------------------------------------------------------------------------
// The analysis mode
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct GateRec {
    ty: u8,
    a: u32,
    b: u32,
    c: u32,
    sc: u64,
    atom: u64, // non-free index, or u64::MAX for free gates
}

struct Tail {
    ring: Vec<GateRec>,
    pos: usize,
    wrapped: bool,
    total_gates: u64,
    nonfree: u64,
}

impl Tail {
    fn new() -> Self {
        Self { ring: vec![GateRec::default(); RING], pos: 0, wrapped: false, total_gates: 0, nonfree: 0 }
    }
}

/// The streaming runner consumes the mode, so the recorded tail is held behind
/// a raw pointer owned by `main`. Single-threaded, freed exactly once.
struct AnalysisMode {
    storage: Storage<WireId, Option<u64>>,
    tail: *mut Tail,
}

impl std::fmt::Debug for AnalysisMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnalysisMode")
    }
}

impl AnalysisMode {
    fn with_capacity(cap: usize, tail: *mut Tail) -> Self {
        Self { storage: Storage::new(cap), tail }
    }
}

fn is_free(t: GateType) -> bool {
    matches!(t, GateType::Xor | GateType::Xnor | GateType::Not)
}

impl CircuitMode for AnalysisMode {
    type WireValue = u64;
    type CiphertextAcc = ();

    #[inline]
    fn false_value(&self) -> u64 {
        0
    }
    #[inline]
    fn true_value(&self) -> u64 {
        0
    }

    #[inline]
    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    #[inline]
    fn evaluate_gate(&mut self, gate: &Gate) {
        let a = self.lookup_wire(gate.wire_a).unwrap_or(0);
        let b = self.lookup_wire(gate.wire_b).unwrap_or(0);

        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        let sc = a | b;
        let free = is_free(gate.gate_type);

        // SAFETY: single-threaded; `tail` outlives the mode and is owned by main.
        let t = unsafe { &mut *self.tail };
        t.total_gates += 1;
        let atom = if free {
            u64::MAX
        } else {
            let id = t.nonfree;
            t.nonfree += 1;
            id
        };
        t.ring[t.pos] = GateRec {
            ty: gate.gate_type as u8,
            a: gate.wire_a.0 as u32,
            b: gate.wire_b.0 as u32,
            c: gate.wire_c.0 as u32,
            sc,
            atom,
        };
        t.pos += 1;
        if t.pos == RING {
            t.pos = 0;
            t.wrapped = true;
        }

        self.feed_wire(gate.wire_c, sc);
    }

    #[inline]
    fn lookup_wire(&mut self, wire_id: WireId) -> Option<u64> {
        use garbled_snark_verifier::circuit::{FALSE_WIRE, TRUE_WIRE};
        match wire_id {
            TRUE_WIRE | FALSE_WIRE => return Some(0),
            WireId::UNREACHABLE => return None,
            _ => (),
        }
        match self.storage.get(wire_id).as_deref() {
            Ok(Some(v)) => Some(*v),
            Ok(None) => Some(0),
            Err(_) => None,
        }
    }

    #[inline]
    fn feed_wire(&mut self, wire_id: WireId, value: u64) {
        use garbled_snark_verifier::circuit::{FALSE_WIRE, TRUE_WIRE};
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }
        let _ = self.storage.set(wire_id, |e| *e = Some(value));
    }

    #[inline]
    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for w in wires {
            let _ = self.storage.add_credits(*w, credits.get());
        }
    }
}

// ---------------------------------------------------------------------------
// Input wrapper: feed dependency sketches instead of bits
// ---------------------------------------------------------------------------

struct SketchInput(garbled_groth16::VerifierInput);

impl CircuitInput for SketchInput {
    type WireRepr = <garbled_groth16::VerifierInput as CircuitInput>::WireRepr;
    fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
        self.0.allocate(issue)
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        <garbled_groth16::VerifierInput as CircuitInput>::collect_wire_ids(repr)
    }
}

/// How input wires are mapped onto the 64 sketch classes.
#[derive(Clone, Copy, PartialEq)]
enum Mapping {
    /// i % 64: spreads each field element across all classes
    Interleaved,
    /// i / group: classes align with contiguous blocks of the input encoding
    Contiguous(usize),
    /// pseudorandom, to check the result is not an artifact of the mapping
    Hashed(u64),
}

fn class_of(i: usize, m: Mapping) -> u32 {
    match m {
        Mapping::Interleaved => (i % 64) as u32,
        Mapping::Contiguous(g) => ((i / g) % 64) as u32,
        Mapping::Hashed(seed) => {
            let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed;
            x ^= x >> 33;
            x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
            x ^= x >> 33;
            (x % 64) as u32
        }
    }
}

struct SketchInputM(garbled_groth16::VerifierInput, Mapping);

impl CircuitInput for SketchInputM {
    type WireRepr = <garbled_groth16::VerifierInput as CircuitInput>::WireRepr;
    fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
        self.0.allocate(issue)
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        <garbled_groth16::VerifierInput as CircuitInput>::collect_wire_ids(repr)
    }
}

impl EncodeInput<AnalysisMode> for SketchInputM {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut AnalysisMode) {
        let ids = Self::collect_wire_ids(repr);
        for (i, w) in ids.iter().enumerate() {
            cache.feed_wire(*w, 1u64 << class_of(i, self.1));
        }
    }
}

impl EncodeInput<AnalysisMode> for SketchInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut AnalysisMode) {
        let ids = Self::collect_wire_ids(repr);
        for (i, w) in ids.iter().enumerate() {
            cache.feed_wire(*w, 1u64 << (i % 64));
        }
    }
}

// ---------------------------------------------------------------------------
// Offline backward walk over the recorded tail
// ---------------------------------------------------------------------------

struct Frontier {
    atoms: Vec<(u64, u64)>, // (atom id, sketch)
    unresolved: Vec<u32>,   // wires whose producer fell outside the ring
    steps: usize,
}

fn linear_frontier(mode: &Tail, output: WireId) -> Frontier {
    // Records in chronological order, oldest first.
    let mut recs: Vec<GateRec> = Vec::with_capacity(RING);
    if mode.wrapped {
        recs.extend_from_slice(&mode.ring[mode.pos..]);
        recs.extend_from_slice(&mode.ring[..mode.pos]);
    } else {
        recs.extend_from_slice(&mode.ring[..mode.pos]);
    }

    // wanted: wire id -> parity (true = odd, contributes)
    let mut wanted: HashMap<u32, bool> = HashMap::new();
    wanted.insert(output.0 as u32, true);

    let mut atoms: HashMap<u64, (bool, u64)> = HashMap::new();
    let mut steps = 0usize;

    for r in recs.iter().rev() {
        if wanted.is_empty() {
            break;
        }
        let parity = match wanted.get(&r.c) {
            Some(&p) if p => true,
            _ => continue,
        };
        wanted.remove(&r.c);
        steps += 1;
        let _ = parity;

        if r.atom != u64::MAX {
            // non-free gate: this is an atom
            let e = atoms.entry(r.atom).or_insert((false, r.sc));
            e.0 = !e.0;
        } else {
            // free gate: XOR/XNOR contribute both inputs, NOT only wire_a
            let ty = r.ty;
            let mut push = |w: u32, wanted: &mut HashMap<u32, bool>| {
                let e = wanted.entry(w).or_insert(false);
                *e = !*e;
                if !*e {
                    wanted.remove(&w);
                }
            };
            if ty == GateType::Not as u8 {
                push(r.a, &mut wanted);
            } else {
                push(r.a, &mut wanted);
                push(r.b, &mut wanted);
            }
        }
    }

    Frontier {
        atoms: atoms
            .into_iter()
            .filter(|(_, (odd, _))| *odd)
            .map(|(id, (_, sk))| (id, sk))
            .collect(),
        unresolved: wanted.into_keys().collect(),
        steps,
    }
}

// ---------------------------------------------------------------------------

const K: usize = 6;

#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    a: Option<F>,
    b: Option<F>,
    num_variables: usize,
    num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ark::ConstraintSystemRef<F>) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;
        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

/// How many non-free gates in the recorded tail have operands whose sketches
/// have mutually exclusive classes, i.e. are separably controllable and so
/// admit the birthday attack of Attack 4 locally.
fn scan_tail_for_separable_gates(tail: &Tail) -> (usize, usize, Option<(u64, u64, u64)>) {
    let recs: Vec<GateRec> = if tail.wrapped {
        let mut v = tail.ring[tail.pos..].to_vec();
        v.extend_from_slice(&tail.ring[..tail.pos]);
        v
    } else {
        tail.ring[..tail.pos].to_vec()
    };

    // Most recent producer of each wire id within the window.
    let mut producer: HashMap<u32, u64> = HashMap::with_capacity(recs.len());
    let mut nonfree_seen = 0usize;
    let mut separable = 0usize;
    let mut shallowest: Option<(u64, u64, u64)> = None;

    for (pos, r) in recs.iter().enumerate() {
        if r.atom != u64::MAX {
            nonfree_seen += 1;
            let sa = producer.get(&r.a).map(|&p| recs[p as usize].sc);
            let sb = producer.get(&r.b).map(|&p| recs[p as usize].sc);
            if let (Some(x), Some(y)) = (sa, sb) {
                if x & !y != 0 && y & !x != 0 {
                    separable += 1;
                    // record the LAST one seen, i.e. closest to the output
                    shallowest = Some((r.atom, x & !y, y & !x));
                }
            }
        }
        producer.insert(r.c, pos as u64);
    }
    (nonfree_seen, separable, shallowest)
}

fn main() {
    println!("\n=== Step 2: affine-split analysis of the BN254 Groth16 verifier ===\n");

    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << K,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let vi = garbled_groth16::VerifierInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    };

    println!("running the real verifier circuit with dependency sketches");
    println!("(one full streaming pass over ~10.4e9 gates; this takes a while)\n");

    let tail_ptr = Box::into_raw(Box::new(Tail::new()));
    let result: StreamingResult<AnalysisMode, _, Vec<u64>> = CircuitBuilder::run_streaming(
        SketchInput(vi),
        AnalysisMode::with_capacity(160_000, tail_ptr),
        |ctx, wires| vec![garbled_groth16::verify(ctx, wires)],
    );
    // SAFETY: the mode has been dropped by run_streaming; we are the sole owner.
    let tail = unsafe { Box::from_raw(tail_ptr) };

    let out_wire = result.output_wires_ids[0];
    println!("input wires:            {}", result.input_wire_values.len());
    println!("gates executed:         {}", tail.total_gates);
    println!("non-free gates:         {}", tail.nonfree);
    println!("output wire:            {}", out_wire.0);
    println!(
        "output sketch popcount: {}/64",
        result.output_value[0].count_ones()
    );

    println!("\n--- linear frontier of the output ---");
    let f = linear_frontier(&tail, out_wire);
    println!("backward steps through free gates: {}", f.steps);
    println!("frontier atoms (odd parity):       {}", f.atoms.len());
    println!("unresolved wires (fell out of ring): {}", f.unresolved.len());

    let mut atoms = f.atoms.clone();
    atoms.sort_by_key(|(id, _)| *id);
    for (id, sk) in atoms.iter().take(32) {
        println!("  atom #{id:<12} sketch popcount {}/64", sk.count_ones());
    }
    if atoms.len() > 32 {
        println!("  ... {} more", atoms.len() - 32);
    }

    println!("\n--- split test ---");
    if atoms.len() < 2 {
        println!("VERDICT: no XOR split at the output. The output is a single");
        println!("         non-free gate, so the top-level birthday attack of");
        println!("         Attack 4 does not apply directly. See below.");
    } else {
        // A pair (i, j) admits the birthday attack if some residue class is in
        // atom i's cone and in no other atom's cone, and likewise for j.
        let all: u64 = atoms.iter().fold(0u64, |acc, (_, s)| acc | s);
        let _ = all;
        let mut found = Vec::new();
        for (ai, (ida, sa)) in atoms.iter().enumerate() {
            let others_a: u64 = atoms
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != ai)
                .fold(0u64, |acc, (_, (_, s))| acc | *s);
            let excl_a = sa & !others_a;
            if excl_a == 0 {
                continue;
            }
            for (bj, (idb, sb)) in atoms.iter().enumerate() {
                if bj <= ai {
                    continue;
                }
                let others_b: u64 = atoms
                    .iter()
                    .enumerate()
                    .filter(|(k, _)| *k != bj)
                    .fold(0u64, |acc, (_, (_, s))| acc | *s);
                let excl_b = sb & !others_b;
                if excl_b != 0 {
                    found.push((*ida, *idb, excl_a, excl_b));
                }
            }
        }
        if found.is_empty() {
            println!("VERDICT: frontier has {} atoms but no pair has mutually",
                     atoms.len());
            println!("         exclusive input residue classes at 64-bit");
            println!("         resolution. No split detectable.");
        } else {
            println!("VERDICT: SPLIT FOUND. {} candidate pair(s):", found.len());
            for (a, b, ea, eb) in found.iter().take(10) {
                println!(
                    "  atoms #{a} and #{b}, exclusive classes {:#018x} / {:#018x}",
                    ea, eb
                );
            }
        }
    }

    println!("\n--- one level deeper: the top non-free gate ---");
    let recs: Vec<GateRec> = if tail.wrapped {
        let mut v = tail.ring[tail.pos..].to_vec();
        v.extend_from_slice(&tail.ring[..tail.pos]);
        v
    } else {
        tail.ring[..tail.pos].to_vec()
    };
    if let Some(top) = recs.iter().rev().find(|r| r.atom != u64::MAX) {
        // Sketches of the two operands of the last non-free gate.
        let find_sketch = |w: u32| -> Option<u64> {
            recs.iter().rev().find(|r| r.c == w).map(|r| r.sc)
        };
        let sa = find_sketch(top.a);
        let sb = find_sketch(top.b);
        println!("last non-free gate: atom #{}", top.atom);
        match (sa, sb) {
            (Some(x), Some(y)) => {
                println!("  operand A sketch popcount {}/64", x.count_ones());
                println!("  operand B sketch popcount {}/64", y.count_ones());
                println!("  A-exclusive classes: {:#018x}", x & !y);
                println!("  B-exclusive classes: {:#018x}", y & !x);
                if x & !y != 0 && y & !x != 0 {
                    println!("  -> operands are separably controllable: BIRTHDAY APPLIES");
                } else {
                    println!("  -> no mutually exclusive classes: no birthday at this gate");
                }
            }
            _ => println!("  operand producers fell outside the recorded tail"),
        }
    }

    println!("\n--- how deep before a separable gate appears? ---");
    let (seen, sep, shallow) = scan_tail_for_separable_gates(&tail);
    println!("non-free gates in recorded tail: {seen}");
    println!("of those, with separably controllable operands: {sep}");
    match shallow {
        Some((atom, ea, eb)) => {
            let depth = tail.nonfree - atom;
            println!(
                "closest to the output: atom #{atom}, {depth} non-free gates before the end"
            );
            println!("  exclusive classes {:#018x} / {:#018x}", ea, eb);
        }
        None => println!("none found anywhere in the recorded tail"),
    }

    println!();
}
