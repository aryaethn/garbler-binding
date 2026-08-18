//! Working proof-of-concept for the attacks in `garbler-binding-attack.md`.
//!
//! This is a faithful implementation of the ZRE15 half-gates garbling scheme
//! (Zahur-Rosulek-Evans, "Two Halves Make a Whole", eprint 2014/756, Figure 2)
//! with free-XOR, parameterized by label length `k` so the birthday attack can
//! actually be run rather than argued about.
//!
//! Why a reimplementation instead of using `garbled-snark-verifier` directly:
//! that crate fixes `k = 128`, which puts the birthday attack at 2^64 and out
//! of reach of a demonstration. Everything here follows Figure 2 line by line,
//! and `validate()` checks correctness exhaustively on every circuit and every
//! input before any attack is run. If the garbling were wrong the attacks would
//! prove nothing.
//!
//! Run:  cargo run --release

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Labels and the hash
// ---------------------------------------------------------------------------

type Label = u128;

#[inline]
fn mask(k: u32) -> Label {
    if k >= 128 {
        Label::MAX
    } else {
        (1u128 << k) - 1
    }
}

/// H : {0,1}^k x Z -> {0,1}^k, the "hash suitable for use in garbled circuits"
/// of ZRE15 Section 4. Instantiated with BLAKE3 and truncated to k bits. The
/// tweak `j` is the NextIndex counter from Figure 2.
#[inline]
fn h(x: Label, j: u64, k: u32) -> Label {
    let mut buf = [0u8; 24];
    buf[..16].copy_from_slice(&x.to_le_bytes());
    buf[16..].copy_from_slice(&j.to_le_bytes());
    let d = blake3::hash(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d.as_bytes()[..16]);
    Label::from_le_bytes(out) & mask(k)
}

#[inline]
fn lsb(x: Label) -> bool {
    x & 1 == 1
}

// ---------------------------------------------------------------------------
// Circuits
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Gate {
    Xor { a: usize, b: usize, out: usize },
    And { a: usize, b: usize, out: usize },
}

#[derive(Clone, Debug)]
struct Circuit {
    name: &'static str,
    n_inputs: usize,
    n_wires: usize,
    gates: Vec<Gate>,
    output: usize,
}

impl Circuit {
    /// Plaintext evaluation, the reference the garbling is checked against.
    fn eval(&self, x: &[bool]) -> bool {
        let mut w = vec![false; self.n_wires];
        w[..self.n_inputs].copy_from_slice(x);
        for g in &self.gates {
            match *g {
                Gate::Xor { a, b, out } => w[out] = w[a] ^ w[b],
                Gate::And { a, b, out } => w[out] = w[a] & w[b],
            }
        }
        w[self.output]
    }
}

/// out = (a AND b) XOR (c AND d)
///
/// The minimal circuit exhibiting the split structure Attack 4 needs: the
/// output is an XOR of two AND gates whose input supports are disjoint, so the
/// output label is g(L_a) XOR h(L_c) with L_b, L_d held fixed. Two AND gates
/// and four inputs, deliberately echoing the two-AND-gate, three-input
/// counterexample Fairgate used against the RSA scheme.
fn circuit_split() -> Circuit {
    Circuit {
        name: "split: (a AND b) XOR (c AND d)",
        n_inputs: 4,
        n_wires: 7,
        gates: vec![
            Gate::And { a: 0, b: 1, out: 4 },
            Gate::And { a: 2, b: 3, out: 5 },
            Gate::Xor { a: 4, b: 5, out: 6 },
        ],
        output: 6,
    }
}

/// out = ((a XOR b) AND c) XOR d
///
/// Wires a and b meet at an XOR before any H is applied, which is what
/// Attack 3 exploits.
fn circuit_cancel() -> Circuit {
    Circuit {
        name: "cancel: ((a XOR b) AND c) XOR d",
        n_inputs: 4,
        n_wires: 7,
        gates: vec![
            Gate::Xor { a: 0, b: 1, out: 4 },
            Gate::And { a: 4, b: 2, out: 5 },
            Gate::Xor { a: 5, b: 3, out: 6 },
        ],
        output: 6,
    }
}

// ---------------------------------------------------------------------------
// ZRE15 Figure 2
// ---------------------------------------------------------------------------

struct Garbled {
    k: u32,
    r: Label,
    zero: Vec<Label>,           // W_i^0 for every wire
    tg: HashMap<usize, Label>,  // per AND gate, indexed by gate position
    te: HashMap<usize, Label>,
    out_zero: Label,
}

/// A tiny deterministic PRNG so runs are reproducible.
struct Rng(u128);
impl Rng {
    fn new(seed: u128) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u128 {
        // splitmix-ish over 128 bits, adequate for sampling labels
        let mut x = self.0;
        x ^= x << 31;
        x ^= x >> 17;
        x ^= x << 8;
        self.0 = x;
        let d = blake3::hash(&x.to_le_bytes());
        let mut b = [0u8; 16];
        b.copy_from_slice(&d.as_bytes()[..16]);
        u128::from_le_bytes(b)
    }
}

fn garble(c: &Circuit, k: u32, seed: u128) -> Garbled {
    let m = mask(k);
    let mut rng = Rng::new(seed);

    // R <- {0,1}^{k-1} 1   (free-XOR offset, lsb = 1)
    let r = (rng.next() & m) | 1;

    let mut zero = vec![0u128; c.n_wires];
    for i in 0..c.n_inputs {
        zero[i] = rng.next() & m;
    }

    let mut tg = HashMap::new();
    let mut te = HashMap::new();

    for (gi, g) in c.gates.iter().enumerate() {
        match *g {
            Gate::Xor { a, b, out } => {
                // free
                zero[out] = zero[a] ^ zero[b];
            }
            Gate::And { a, b, out } => {
                let (j, jp) = (2 * gi as u64, 2 * gi as u64 + 1);
                let wa0 = zero[a];
                let wa1 = wa0 ^ r;
                let wb0 = zero[b];
                let wb1 = wb0 ^ r;
                let pa = lsb(wa0);
                let pb = lsb(wb0);

                // First half gate (generator side)
                let t_g = h(wa0, j, k) ^ h(wa1, j, k) ^ if pb { r } else { 0 };
                let wg0 = h(wa0, j, k) ^ if pa { t_g } else { 0 };

                // Second half gate (evaluator side)
                let t_e = h(wb0, jp, k) ^ h(wb1, jp, k) ^ wa0;
                let we0 = h(wb0, jp, k) ^ if pb { t_e ^ wa0 } else { 0 };

                zero[out] = wg0 ^ we0;
                tg.insert(gi, t_g);
                te.insert(gi, t_e);
            }
        }
    }

    let out_zero = zero[c.output];
    Garbled { k, r, zero, tg, te, out_zero }
}

/// En(e, x): X_i = e_i XOR x_i R
fn encode(gc: &Garbled, x: &[bool]) -> Vec<Label> {
    x.iter()
        .enumerate()
        .map(|(i, &b)| gc.zero[i] ^ if b { gc.r } else { 0 })
        .collect()
}

/// Ev(F, X) from Figure 2.
fn ev(c: &Circuit, gc: &Garbled, inputs: &[Label]) -> Label {
    let mut w = vec![0u128; c.n_wires];
    w[..c.n_inputs].copy_from_slice(inputs);
    for (gi, g) in c.gates.iter().enumerate() {
        match *g {
            Gate::Xor { a, b, out } => w[out] = w[a] ^ w[b],
            Gate::And { a, b, out } => {
                w[out] = ev_and(gc, gi, w[a], w[b]);
            }
        }
    }
    w[c.output]
}

/// The AND branch of Ev, isolated so the attack can call it directly.
#[inline]
fn ev_and(gc: &Garbled, gi: usize, wa: Label, wb: Label) -> Label {
    let (j, jp) = (2 * gi as u64, 2 * gi as u64 + 1);
    let sa = lsb(wa);
    let sb = lsb(wb);
    let wg = h(wa, j, gc.k) ^ if sa { gc.tg[&gi] } else { 0 };
    let we = h(wb, jp, gc.k) ^ if sb { gc.te[&gi] ^ wa } else { 0 };
    wg ^ we
}

/// ZRE15's native decoding: y = d XOR lsb(Y), with d = lsb(W^0).
/// Note it never returns None: every label decodes to some bit.
fn de_native(gc: &Garbled, y: Label) -> bool {
    lsb(gc.out_zero) ^ lsb(y)
}

/// Authenticity-style decoding: commit to both output labels and return None
/// on anything else. This is the repair Attack 1 forces.
fn de_committed(gc: &Garbled, y: Label) -> Option<bool> {
    if y == gc.out_zero {
        Some(false)
    } else if y == gc.out_zero ^ gc.r {
        Some(true)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Validation: the garbling must be correct or nothing below means anything
// ---------------------------------------------------------------------------

fn validate(c: &Circuit, k: u32) -> bool {
    let gc = garble(c, k, 0xDEADBEEF_CAFEBABE);
    let n = c.n_inputs;
    for bits in 0..(1u32 << n) {
        let x: Vec<bool> = (0..n).map(|i| (bits >> i) & 1 == 1).collect();
        let y = ev(c, &gc, &encode(&gc, &x));
        let expect = c.eval(&x);
        if de_native(&gc, y) != expect {
            return false;
        }
        match de_committed(&gc, y) {
            Some(b) if b == expect => {}
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Attack 1: De never returns bottom
// ---------------------------------------------------------------------------

fn attack1(k: u32) {
    let c = circuit_split();
    let gc = garble(&c, k, 1);
    // An input on which the circuit is FALSE. The prover has no valid witness.
    let x = vec![false, false, false, false];
    assert!(!c.eval(&x));

    let mut rng = Rng::new(0xA77AC1);
    let m = mask(k);
    let mut trials = 0u64;
    loop {
        trials += 1;
        let junk: Vec<Label> = (0..c.n_inputs).map(|_| rng.next() & m).collect();
        let y = ev(&c, &gc, &junk);
        if de_native(&gc, y) {
            println!(
                "  Attack 1  k={k:<4} FORGED in {trials} trial(s). \
                 Garbage labels decode to True under ZRE15's native De.\n            \
                 committed-De verdict on the same label: {:?}",
                de_committed(&gc, y)
            );
            break;
        }
        if trials > 1000 {
            println!("  Attack 1  k={k:<4} unexpectedly failed");
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Attack 3: XOR cancellation, evaluation is bit-identical to honest
// ---------------------------------------------------------------------------

fn attack3(k: u32) {
    let c = circuit_cancel();
    let gc = garble(&c, k, 3);
    let m = mask(k);

    let x = vec![false, true, true, false];
    let honest = encode(&gc, &x);
    let y_honest = ev(&c, &gc, &honest);

    // rho arbitrary, not 0 and not R, applied to wires 0 and 1 which meet at
    // an XOR before any H.
    let mut rng = Rng::new(0x5151);
    let rho = loop {
        let v = rng.next() & m;
        if v != 0 && v != gc.r {
            break v;
        }
    };

    let mut forged = honest.clone();
    forged[0] ^= rho;
    forged[1] ^= rho;

    let y_forged = ev(&c, &gc, &forged);

    let on_manifold = |i: usize, l: Label| l == gc.zero[i] || l == gc.zero[i] ^ gc.r;
    let off0 = !on_manifold(0, forged[0]);
    let off1 = !on_manifold(1, forged[1]);

    println!(
        "  Attack 3  k={k:<4} identical={}  L_0 off-manifold={}  L_1 off-manifold={}  \
         decoded={:?}",
        y_forged == y_honest,
        off0,
        off1,
        de_committed(&gc, y_forged)
    );
}

// ---------------------------------------------------------------------------
// Attack 4: birthday on the split structure
// ---------------------------------------------------------------------------

struct AttackResult {
    k: u32,
    h_evals: u64,
    found: bool,
    off_manifold: bool,
    decoded: Option<bool>,
}

fn attack4(k: u32, cap_exp: u32) -> AttackResult {
    let c = circuit_split();
    let gc = garble(&c, k, 4);
    let m = mask(k);

    // Target: the output label meaning True.
    let z_true = gc.out_zero ^ gc.r;

    // Hold L_b and L_d at honest labels; vary L_a and L_c over garbage.
    let l_b = gc.zero[1];
    let l_d = gc.zero[3];

    let side = 1u64 << cap_exp; // 2^{k/2} nominally
    let mut h_evals = 0u64;

    // Left table: L_a  ->  W_u = ev_and(gate 0, L_a, L_b)
    let mut table: HashMap<Label, Label> = HashMap::with_capacity(side as usize);
    let mut rng = Rng::new(0xBEEF_0001);
    for _ in 0..side {
        let l_a = rng.next() & m;
        let w_u = ev_and(&gc, 0, l_a, l_b);
        h_evals += 2;
        table.entry(w_u).or_insert(l_a);
    }

    // Right sweep: want W_u ^ W_v = z_true, i.e. W_u = z_true ^ W_v
    let mut rng2 = Rng::new(0xBEEF_0002);
    for _ in 0..side {
        let l_c = rng2.next() & m;
        let w_v = ev_and(&gc, 1, l_c, l_d);
        h_evals += 2;
        if let Some(&l_a) = table.get(&(z_true ^ w_v)) {
            let forged = vec![l_a, l_b, l_c, l_d];
            let y = ev(&c, &gc, &forged);
            // Exhaustive check: forged is not En(e, x) for ANY of the 2^n inputs.
            let mut is_encoding = false;
            for bits in 0..(1u32 << c.n_inputs) {
                let x: Vec<bool> = (0..c.n_inputs).map(|i| (bits >> i) & 1 == 1).collect();
                if encode(&gc, &x) == forged {
                    is_encoding = true;
                    break;
                }
            }
            return AttackResult {
                k,
                h_evals,
                found: y == z_true,
                off_manifold: !is_encoding,
                decoded: de_committed(&gc, y),
            };
        }
    }

    AttackResult { k, h_evals, found: false, off_manifold: false, decoded: None }
}

/// Control: naive search for the same target, expected 2^k work.
fn control_bruteforce(k: u32, budget: u64) -> (bool, u64) {
    let c = circuit_split();
    let gc = garble(&c, k, 4);
    let m = mask(k);
    let z_true = gc.out_zero ^ gc.r;
    let l_b = gc.zero[1];
    let l_d = gc.zero[3];

    let mut rng = Rng::new(0xC0117501);
    let mut evals = 0u64;
    for _ in 0..budget {
        let l_a = rng.next() & m;
        let l_c = rng.next() & m;
        let y = ev(&c, &gc, &[l_a, l_b, l_c, l_d]);
        evals += 4;
        if y == z_true {
            return (true, evals);
        }
    }
    (false, evals)
}

// ---------------------------------------------------------------------------

fn main() {
    println!("\nZRE15 half-gates + free-XOR, parameterized by label length k.");
    println!("Implementation follows eprint 2014/756 Figure 2 line by line.\n");

    println!("=== VALIDATION (exhaustive over all inputs) ===");
    for c in [circuit_split(), circuit_cancel()] {
        for k in [16u32, 32, 64, 128] {
            let ok = validate(&c, k);
            println!("  {:<38} k={k:<4} correct={}", c.name, if ok { "YES" } else { "NO" });
            assert!(ok, "garbling incorrect, everything below is meaningless");
        }
    }

    println!("\n=== ATTACK 1: ZRE15 native De never returns bottom ===");
    for k in [32u32, 64, 128] {
        attack1(k);
    }

    println!("\n=== ATTACK 3: XOR cancellation is evaluation-invariant ===");
    for k in [32u32, 64, 128] {
        attack3(k);
    }

    println!("\n=== ATTACK 4: birthday on the split structure ===");
    println!("  target = Z^True, committed-De decoding, forged labels off-manifold\n");
    println!(
        "  {:<5} {:>12} {:>14} {:>14} {:>8} {:>8} {:>9}",
        "k", "H evals", "2^(k/2)", "2^k", "found", "off-mf", "decodes"
    );

    let mut results = Vec::new();
    for k in [24u32, 28, 32, 36, 40, 44] {
        let cap = (k / 2) + 1; // small margin over the birthday bound
        let r = attack4(k, cap);
        println!(
            "  {:<5} {:>12} {:>14} {:>14} {:>8} {:>8} {:>9}",
            r.k,
            r.h_evals,
            format!("{:.3e}", 2f64.powf(k as f64 / 2.0)),
            format!("{:.3e}", 2f64.powf(k as f64)),
            r.found,
            r.off_manifold,
            format!("{:?}", r.decoded)
        );
        results.push(r);
    }

    println!("\n=== HEAD TO HEAD: birthday vs naive search, same k, same target ===\n");
    println!("  {:<5} {:>14} {:>16} {:>12}", "k", "birthday H", "naive H", "speedup");
    for k in [20u32, 24, 28] {
        let cap = (k / 2) + 1;
        let b = attack4(k, cap);
        let (found, naive) = control_bruteforce(k, 1u64 << (k + 2));
        if b.found && found {
            println!(
                "  {:<5} {:>14} {:>16} {:>11.0}x",
                k,
                b.h_evals,
                naive,
                naive as f64 / b.h_evals as f64
            );
        }
    }

    println!("\n=== EXTRAPOLATION ===");
    let succeeded: Vec<&AttackResult> = results.iter().filter(|r| r.found).collect();
    if let (Some(first), Some(last)) = (succeeded.first(), succeeded.last()) {
        let ratio = (last.h_evals as f64 / first.h_evals as f64).log2()
            / ((last.k as f64 - first.k as f64) / 2.0);
        println!(
            "  measured scaling exponent over k={}..{}: {:.2} (birthday predicts 1.00)",
            first.k, last.k, ratio
        );
    }
    println!("  at k=128, as deployed by BitVM3-core: 2^64 hash evaluations");
    println!("  at ~1e9 H/core-second: ~585 core-years, ~3 weeks on 10k cores");
}
