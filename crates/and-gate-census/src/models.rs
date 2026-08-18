//! Composition models: from measured primitives to verifier-level estimates.
//!
//! Everything in `gadgets/` is *measured*. Everything in this file is a
//! *model*: an explicit arithmetic formula over those measurements plus
//! structural parameters (query counts, Merkle depths, folding factors). The
//! separation is deliberate. Measurements are facts; models are arguments, and
//! every parameter of the argument is surfaced here so it can be disputed.
//!
//! Do not quote a number out of this file without also quoting the parameters
//! that produced it.

use serde::Serialize;

/// Cost of the primitives a verifier is built from, in non-free gates.
#[derive(Debug, Clone, Serialize)]
pub struct PrimitiveCosts {
    /// Non-free gates for one hash compression.
    pub hash_compression: u64,
    /// Bytes of input absorbed per compression.
    pub hash_rate_bytes: u64,
    /// Non-free gates for one base-field multiplication.
    pub field_mul: u64,
    /// Non-free gates for one base-field addition (0 for binary fields).
    pub field_add: u64,
    /// Bits per base-field element.
    pub field_bits: u64,
    /// Degree of the extension field used for soundness (challenges live here).
    pub ext_degree: u64,
}

impl PrimitiveCosts {
    /// Karatsuba over the extension: ~ext_degree^1.585 base multiplications.
    pub fn ext_mul(&self) -> u64 {
        let d = self.ext_degree as f64;
        let mults = d.powf(1.584_962_5).ceil() as u64;
        mults * self.field_mul
    }
}

/// Structural parameters of a FRI-based verifier.
#[derive(Debug, Clone, Serialize)]
pub struct FriParams {
    /// Number of query repetitions (soundness parameter).
    pub queries: u64,
    /// log2 of the initial evaluation domain size = Merkle tree depth.
    pub log_domain: u64,
    /// Folding arity per FRI round (2 or 4 typically).
    pub fold_arity: u64,
    /// log2 of the final (directly-checked) domain size.
    pub log_final: u64,
    /// Number of committed oracles opened at each query in the first phase
    /// (trace columns are batched, so this is small).
    pub oracles: u64,
    /// Number of field elements per leaf (affects how many compressions a
    /// leaf hash costs).
    pub leaf_elements: u64,
}

impl FriParams {
    pub fn fold_rounds(&self) -> u64 {
        let steps = self.log_domain.saturating_sub(self.log_final);
        let per = (self.fold_arity as f64).log2() as u64;
        steps.div_ceil(per.max(1))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifierEstimate {
    pub name: String,
    pub nonfree_merkle: u64,
    pub nonfree_fold_arith: u64,
    pub nonfree_leaf_hash: u64,
    pub nonfree_transcript: u64,
    pub nonfree_total: u64,
    pub garbled_bytes: u64,
    pub primitives: PrimitiveCosts,
    pub params: FriParams,
    pub assumptions: Vec<String>,
}

/// Model a FRI/STARK-style verifier's non-free gate count.
///
/// Cost decomposition:
///   1. Merkle authentication paths. `queries * oracles * (log_domain +
///      sum of shrinking depths over fold rounds)` compressions. This
///      dominates every hash-based verifier, which is why the hash choice is
///      the single most important design decision.
///   2. Leaf hashing: each opened leaf holds `leaf_elements` field elements
///      which must be absorbed.
///   3. Folding arithmetic: per query, per fold round, a small number of
///      extension-field multiplications for the interpolation step.
///   4. Transcript / Fiat-Shamir: a few dozen compressions, negligible.
pub fn model_fri_verifier(
    name: &str,
    p: PrimitiveCosts,
    f: FriParams,
    assumptions: Vec<String>,
) -> VerifierEstimate {
    let rounds = f.fold_rounds();

    // Total Merkle path length across the commit phase: the first oracle has
    // depth log_domain, and each fold round halves (or quarters) the domain.
    let per_query_arity = (f.fold_arity as f64).log2().max(1.0) as u64;
    let mut path_nodes = f.log_domain * f.oracles;
    let mut d = f.log_domain;
    for _ in 0..rounds {
        d = d.saturating_sub(per_query_arity);
        path_nodes += d;
    }
    let merkle_compressions = f.queries * path_nodes;
    let nonfree_merkle = merkle_compressions * p.hash_compression;

    // Leaf hashing: bytes of field elements per opened leaf.
    let leaf_bytes = f.leaf_elements * p.field_bits.div_ceil(8);
    let leaf_compressions_each = leaf_bytes.div_ceil(p.hash_rate_bytes).max(1);
    let leaf_openings = f.queries * (f.oracles + rounds);
    let nonfree_leaf_hash = leaf_openings * leaf_compressions_each * p.hash_compression;

    // Folding arithmetic: ~3 extension multiplications and a few additions per
    // query per round for arity-2 interpolation; scale with arity.
    let muls_per_fold = 3 * f.fold_arity.max(2) / 2;
    let nonfree_fold_arith =
        f.queries * rounds * muls_per_fold * p.ext_mul() + f.queries * rounds * 4 * p.field_add;

    // Fiat-Shamir transcript.
    let nonfree_transcript = 64 * p.hash_compression;

    let nonfree_total =
        nonfree_merkle + nonfree_leaf_hash + nonfree_fold_arith + nonfree_transcript;

    VerifierEstimate {
        name: name.to_string(),
        nonfree_merkle,
        nonfree_fold_arith,
        nonfree_leaf_hash,
        nonfree_transcript,
        nonfree_total,
        garbled_bytes: nonfree_total * 16,
        primitives: p,
        params: f,
        assumptions,
    }
}

/// Convert a non-free gate count to a human-readable garbled size.
pub fn fmt_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    let x = b as f64;
    if x >= KB * KB * KB {
        format!("{:.2} GB", x / (KB * KB * KB))
    } else if x >= KB * KB {
        format!("{:.2} MB", x / (KB * KB))
    } else if x >= KB {
        format!("{:.2} KB", x / KB)
    } else {
        format!("{b} B")
    }
}

pub fn fmt_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}
