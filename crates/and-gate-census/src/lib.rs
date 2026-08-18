//! # and-gate-census
//!
//! Measures the non-free (AND) gate count of the primitives that make up a
//! SNARK verifier, under the free-XOR + half-gates garbling model that
//! BitVM3-core uses.
//!
//! ## Why this number and not another
//!
//! In BitVM3-core the operator garbles the verifier circuit once and every
//! challenger downloads it. Under free-XOR, XOR/XNOR/NOT gates cost zero
//! ciphertexts and each AND-variant gate costs two 16-byte ciphertexts. So:
//!
//!     garbled circuit size = 32 bytes x (non-free gate count)
//!
//! The BitVM3 paper quotes 2.7e9 non-free gates for the BN254 Groth16 verifier
//! and 41.2 GB of garbled circuit. We reproduce the 2.7e9 exactly (see
//! `results/anchor.json`), which calibrates everything else here.
//!
//! ## The hypothesis under test
//!
//! Prime-field verifiers are AND-expensive because modular arithmetic has
//! carry chains. Binary-field verifiers should be far cheaper because field
//! addition is XOR (free), constant multiplication is a GF(2)-linear map
//! (free), and squaring is Frobenius (free). If that gap is large, a
//! binary-field proof system is the natural backend for a post-quantum
//! BitVM3, and the remaining cost concentrates in the hash, which can then be
//! attacked separately.
//!
//! This crate measures the gap instead of asserting it.

pub mod bits;
pub mod gadgets;
pub mod harness;
pub mod models;
