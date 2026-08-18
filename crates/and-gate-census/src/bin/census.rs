//! Runs the full census and emits JSON + a markdown table.
//!
//!   cargo run --release --bin census -- --json results/census.json --md results/census.md

use and_gate_census::{
    bits,
    gadgets::{binfield, blake3 as b3, keccak, lowmc, primefield, sha256},
    harness::{measure, BitVecInput, Measurement},
    models::{fmt_bytes, fmt_count, model_fri_verifier, FriParams, PrimitiveCosts},
};
use garbled_snark_verifier::WireId;

fn split2(w: &[WireId], k: usize) -> (&[WireId], &[WireId]) {
    (&w[..k], &w[k..2 * k])
}

fn rand_bits(seed: u64, n: usize) -> Vec<bool> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x & 1 == 1
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_path = arg_after(&args, "--json");
    let md_path = arg_after(&args, "--md");

    let mut ms: Vec<Measurement> = Vec::new();

    // -----------------------------------------------------------------
    // Binary fields
    // -----------------------------------------------------------------
    for &k in &[32usize, 64, 128] {
        let a = rand_bits(0xA5A5 + k as u64, k);
        let b = rand_bits(0x5A5A + k as u64, k);
        let expected = binfield::ref_mul(&a, &b, k);
        let mut input = a.clone();
        input.extend_from_slice(&b);

        ms.push(measure(
            &format!("gf2_{k}_mul_karatsuba"),
            "binary_field",
            "GF(2^k) multiplication, Karatsuba. Same non-free count as a Wiedemann binary tower.",
            input.clone(),
            &expected,
            Some(k as u64),
            "bit of field element",
            move |c, w| {
                let (x, y) = split2(w, k);
                binfield::mul_karatsuba(c, x, y, k)
            },
        ));

        if k <= 64 {
            ms.push(measure(
                &format!("gf2_{k}_mul_schoolbook"),
                "binary_field",
                "GF(2^k) multiplication, schoolbook. Shown to quantify what Karatsuba buys.",
                input.clone(),
                &expected,
                Some(k as u64),
                "bit of field element",
                move |c, w| {
                    let (x, y) = split2(w, k);
                    binfield::mul_schoolbook(c, x, y, k)
                },
            ));
        }
    }

    // Squaring: expected FREE.
    {
        let k = 128usize;
        let a = rand_bits(0xBEEF, k);
        let expected = binfield::ref_square(&a, k);
        ms.push(measure(
            "gf2_128_square",
            "binary_field",
            "Frobenius is GF(2)-linear. Expect exactly 0 non-free gates.",
            a.clone(),
            &expected,
            Some(k as u64),
            "bit of field element",
            move |c, w| binfield::square(c, w, k),
        ));
    }

    // Constant multiplication: expected FREE.
    {
        let k = 128usize;
        let a = rand_bits(0xC0FFEE, k);
        let konst = rand_bits(0xDEAD, k);
        let expected = binfield::ref_mul(&a, &konst, k);
        let konst2 = konst.clone();
        ms.push(measure(
            "gf2_128_mul_const",
            "binary_field",
            "Multiplication by a fixed constant is GF(2)-linear. Expect 0 non-free gates. \
             This is why FRI folding coefficients and NTT twiddles are free in a binary field.",
            a.clone(),
            &expected,
            Some(k as u64),
            "bit of field element",
            move |c, w| binfield::mul_const(c, w, &konst2, k),
        ));
    }

    // Inversion.
    {
        let k = 32usize;
        let a = rand_bits(0x1234, k);
        let expected = binfield::ref_inv(&a, k);
        ms.push(measure(
            "gf2_32_inv_naive_chain",
            "binary_field",
            "Square-and-multiply over 2^k-2. All squarings free, so cost = (k-1) multiplications. \
             Itoh-Tsujii reduces this to ~log2(k)+hw(k-1)-1 multiplications without changing \
             the per-multiplication price.",
            a.clone(),
            &expected,
            Some(k as u64),
            "bit of field element",
            move |c, w| binfield::inv_naive(c, w, k),
        ));
    }

    // -----------------------------------------------------------------
    // Prime fields
    // -----------------------------------------------------------------
    {
        let p = primefield::M31_P;
        let av = 0x2AAA_AAAAu128 % p;
        let bv = 0x1555_5555u128 % p;

        let mut input = primefield::u128_to_bits(av, 31);
        input.extend(primefield::u128_to_bits(bv, 31));

        let exp_add = primefield::u128_to_bits(primefield::ref_m31_add(av, bv), 31);
        ms.push(measure(
            "m31_add",
            "prime_field",
            "M31 = 2^31-1 modular addition. Carry chain plus a conditional subtract.",
            input.clone(),
            &exp_add,
            Some(31),
            "bit of field element",
            |c, w| {
                let (x, y) = split2(w, 31);
                primefield::m31_add(c, x, y)
            },
        ));

        let exp_mul = primefield::u128_to_bits(primefield::ref_m31_mul(av, bv), 31);
        ms.push(measure(
            "m31_mul",
            "prime_field",
            "M31 modular multiplication with the Mersenne fold. Compare against gf2_32_mul.",
            input.clone(),
            &exp_mul,
            Some(31),
            "bit of field element",
            |c, w| {
                let (x, y) = split2(w, 31);
                primefield::m31_mul(c, x, y)
            },
        ));
    }

    {
        let p = primefield::GOLDILOCKS_P;
        let av = 0x0123_4567_89AB_CDEFu128 % p;
        let bv = 0x0FED_CBA9_8765_4321u128 % p;

        let mut input = primefield::u128_to_bits(av, 64);
        input.extend(primefield::u128_to_bits(bv, 64));

        let exp_add = primefield::u128_to_bits(primefield::ref_goldilocks_add(av, bv), 64);
        ms.push(measure(
            "goldilocks_add",
            "prime_field",
            "Goldilocks = 2^64-2^32+1 modular addition.",
            input.clone(),
            &exp_add,
            Some(64),
            "bit of field element",
            |c, w| {
                let (x, y) = split2(w, 64);
                primefield::goldilocks_add(c, x, y)
            },
        ));

        let exp_mul = primefield::u128_to_bits(primefield::ref_goldilocks_mul(av, bv), 64);
        ms.push(measure(
            "goldilocks_mul",
            "prime_field",
            "Goldilocks modular multiplication with the standard fast reduction. \
             Compare against gf2_64_mul.",
            input.clone(),
            &exp_mul,
            Some(64),
            "bit of field element",
            |c, w| {
                let (x, y) = split2(w, 64);
                primefield::goldilocks_mul(c, x, y)
            },
        ));
    }

    // -----------------------------------------------------------------
    // Hashes
    // -----------------------------------------------------------------
    {
        use sha2::{Digest, Sha256};
        let msg: Vec<u8> = (0u8..32).collect();
        let digest = Sha256::digest(&msg);
        let expected = BitVecInput::from_bytes_be(&digest);
        let input = BitVecInput::from_bytes_be(&msg);
        let n = msg.len();
        ms.push(measure(
            "sha256_compression",
            "hash",
            "One SHA-256 compression (single-block message). Validated against RustCrypto sha2. \
             Cost is dominated by 32-bit addition carries, not by Ch/Maj.",
            input,
            &expected,
            Some(64),
            "byte of rate",
            move |c, w| sha256::hash_one_block(c, w, n),
        ));
    }

    {
        let msg: Vec<u8> = (0u8..64).collect();
        let digest = blake3::hash(&msg);
        let expected = keccak::bytes_to_bits_le(digest.as_bytes());
        let words = b3::bytes_to_word_bits_le(&msg);
        let input: Vec<bool> = words.into_iter().flatten().collect();
        let n = msg.len();
        ms.push(measure(
            "blake3_compression",
            "hash",
            "One BLAKE3 compression (single-chunk root hash). Validated against the blake3 crate. \
             Pure ARX: every non-free gate is an addition carry.",
            input,
            &expected,
            Some(64),
            "byte of rate",
            move |c, w| {
                let words = b3::group_words(w);
                b3::hash_one_block(c, &words, n)
            },
        ));
    }

    {
        use tiny_keccak::{Hasher, Keccak};
        let msg: Vec<u8> = (0u8..32).collect();
        let mut hasher = Keccak::v256();
        hasher.update(&msg);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        let expected = keccak::bytes_to_bits_le(&out);
        let input = keccak::bytes_to_bits_le(&msg);
        let n = msg.len();
        ms.push(measure(
            "keccak_f1600",
            "hash",
            "One Keccak-f[1600] permutation via Keccak-256 of a short message. Validated against \
             tiny-keccak. Theta/rho/pi/iota are all free; only chi costs, at exactly 1600 \
             non-free gates per round for 24 rounds.",
            input,
            &expected,
            Some(136),
            "byte of rate",
            move |c, w| keccak::keccak256_one_block(c, w, n),
        ));
    }

    // -----------------------------------------------------------------
    // Low-multiplicative-complexity baseline
    // -----------------------------------------------------------------
    for (n, m, r) in [(128usize, 10usize, 20usize), (128, 1, 182), (256, 10, 38)] {
        let p = lowmc::Params { n, m, r };
        let k = lowmc::gen_constants(&p, 0x9E3779B9);
        let block = rand_bits(0x1357 + n as u64 + r as u64, n);
        let expected = lowmc::ref_encrypt(&p, &k, &block);
        let p2 = p.clone();
        let name = format!("lowmc_{n}_m{m}_r{r}");
        ms.push(measure(
            &name,
            "low_and_primitive",
            "LowMC. Linear layer is a full binary matrix multiply and costs zero. Non-free count \
             is exactly 3*m*r. See the cryptanalytic caveat in gadgets/lowmc.rs before quoting \
             this as a recommendation.",
            block.clone(),
            &expected,
            Some((n / 8) as u64),
            "byte of block",
            move |c, w| lowmc::encrypt(c, &p2, &k, w),
        ));
    }

    // -----------------------------------------------------------------
    // Report
    // -----------------------------------------------------------------
    let get = |name: &str| -> u64 {
        ms.iter()
            .find(|m| m.name == name)
            .map(|m| m.nonfree)
            .unwrap_or(0)
    };

    let estimates = vec![
        model_fri_verifier(
            "binary_field_FRI__keccak",
            PrimitiveCosts {
                hash_compression: get("keccak_f1600"),
                hash_rate_bytes: 136,
                field_mul: get("gf2_128_mul_karatsuba"),
                field_add: 0,
                field_bits: 128,
                ext_degree: 1,
            },
            FriParams {
                queries: 100,
                log_domain: 24,
                fold_arity: 2,
                log_final: 6,
                oracles: 3,
                leaf_elements: 8,
            },
            vec![
                "Binary field GF(2^128) used directly as the challenge field; no extension needed."
                    .into(),
                "100 queries at rate 1/2 targets roughly 100-bit soundness.".into(),
                "Merkle leaves hold 8 field elements.".into(),
            ],
        ),
        model_fri_verifier(
            "prime_field_FRI__m31_keccak",
            PrimitiveCosts {
                hash_compression: get("keccak_f1600"),
                hash_rate_bytes: 136,
                field_mul: get("m31_mul"),
                field_add: get("m31_add"),
                field_bits: 31,
                ext_degree: 4,
            },
            FriParams {
                queries: 100,
                log_domain: 24,
                fold_arity: 2,
                log_final: 6,
                oracles: 3,
                leaf_elements: 8,
            },
            vec![
                "M31 needs a degree-4 extension for challenge soundness; extension multiplication \
                 modelled as ~4^1.585 base multiplications."
                    .into(),
                "Same query count, domain and leaf shape as the binary-field row so the only \
                 variable is the field."
                    .into(),
            ],
        ),
        model_fri_verifier(
            "binary_field_FRI__blake3",
            PrimitiveCosts {
                hash_compression: get("blake3_compression"),
                hash_rate_bytes: 64,
                field_mul: get("gf2_128_mul_karatsuba"),
                field_add: 0,
                field_bits: 128,
                ext_degree: 1,
            },
            FriParams {
                queries: 100,
                log_domain: 24,
                fold_arity: 2,
                log_final: 6,
                oracles: 3,
                leaf_elements: 8,
            },
            vec![
                "Same as the keccak row but with BLAKE3 as the Merkle hash. BLAKE3 costs 163 \
                 non-free gates per byte of rate versus Keccak's 282, and BitVM already has a \
                 BLAKE3 implementation in Bitcoin Script."
                    .into(),
            ],
        ),
        // Poseidon2 is the default Merkle hash in Plonky3 and Stwo. Its cost is
        // computed analytically from the MEASURED m31_mul, not implemented, so it
        // is flagged as a model. Width 16, 8 full rounds with 16 S-boxes each and
        // 56 partial rounds with 1 S-box each; x^5 costs 3 multiplications.
        model_fri_verifier(
            "prime_field_FRI__m31_poseidon2",
            PrimitiveCosts {
                hash_compression: (8 * 16 + 56) * 3 * get("m31_mul"),
                hash_rate_bytes: 8 * 4,
                field_mul: get("m31_mul"),
                field_add: get("m31_add"),
                field_bits: 31,
                ext_degree: 4,
            },
            FriParams {
                queries: 100,
                log_domain: 24,
                fold_arity: 2,
                log_final: 6,
                oracles: 3,
                leaf_elements: 8,
            },
            vec![
                "THE CAUTIONARY ROW. This is what you get if you garble an off-the-shelf \
                 Plonky3/Stwo verifier without changing anything: Poseidon2 is designed to be \
                 cheap inside a prime-field SNARK, which makes it maximally expensive as a \
                 Boolean circuit."
                    .into(),
                "Poseidon2 width 16 over M31: 8 full rounds x 16 S-boxes + 56 partial rounds x 1 \
                 S-box, x^5 = 3 multiplications each, priced at the measured m31_mul."
                    .into(),
                "Hash cost is modelled, not measured. Everything it is built from is measured."
                    .into(),
            ],
        ),
        model_fri_verifier(
            "binary_field_FRI__lowmc_hash",
            PrimitiveCosts {
                hash_compression: get("lowmc_128_m10_r20"),
                hash_rate_bytes: 16,
                field_mul: get("gf2_128_mul_karatsuba"),
                field_add: 0,
                field_bits: 128,
                ext_degree: 1,
            },
            FriParams {
                queries: 100,
                log_domain: 24,
                fold_arity: 2,
                log_final: 6,
                oracles: 3,
                leaf_elements: 8,
            },
            vec![
                "SPECULATIVE. Substitutes a LowMC-based compression for Keccak to show the ceiling \
                 of what a garbling-friendly hash could buy. Not a security recommendation."
                    .into(),
                "Rate assumed 16 B/compression, far worse than Keccak's 136 B, which partly \
                 cancels the per-compression saving. This is the honest version of the tradeoff."
                    .into(),
            ],
        ),
    ];

    // stdout summary
    println!("\n=== MEASURED PRIMITIVES (non-free gates) ===\n");
    println!(
        "{:<28} {:>14} {:>14} {:>12} {:>9}",
        "gadget", "non-free", "free", "per unit", "verified"
    );
    for m in &ms {
        println!(
            "{:<28} {:>14} {:>14} {:>12} {:>9}",
            m.name,
            fmt_count(m.nonfree),
            fmt_count(m.free),
            m.nonfree_per_unit()
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            if m.verified { "OK" } else { "FAIL" }
        );
    }

    println!("\n=== MODELLED VERIFIERS ===\n");
    for e in &estimates {
        println!(
            "{:<34} {:>12} non-free   {:>12} garbled",
            e.name,
            fmt_count(e.nonfree_total),
            fmt_bytes(e.garbled_bytes)
        );
    }

    let all_ok = ms.iter().all(|m| m.verified);
    println!(
        "\nAll gadgets verified against native references: {}",
        if all_ok { "YES" } else { "NO -- see warnings above" }
    );

    let anchor_nonfree: u64 = 2_715_041_234;
    println!(
        "\nAnchor (measured separately, see results/anchor.json):\n  \
         BN254 Groth16 verifier = {} non-free gates = {}",
        fmt_count(anchor_nonfree),
        fmt_bytes(anchor_nonfree * 16)
    );

    if let Some(p) = json_path {
        let doc = serde_json::json!({
            "anchor": {
                "name": "bn254_groth16_verifier",
                "nonfree": anchor_nonfree,
                "source": "garbled-snark-verifier examples/groth16_gc_gate_count, k=6, uncompressed",
            },
            "measurements": ms,
            "models": estimates,
        });
        std::fs::write(&p, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
        println!("\nwrote {p}");
    }

    if let Some(p) = md_path {
        std::fs::write(&p, render_md(&ms, &estimates, anchor_nonfree)).unwrap();
        println!("wrote {p}");
    }

    let _ = bits::FALSE;
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn render_md(
    ms: &[Measurement],
    es: &[and_gate_census::models::VerifierEstimate],
    anchor: u64,
) -> String {
    let mut s = String::new();
    s.push_str("# AND-gate census\n\n");
    s.push_str(
        "Non-free (AND-variant) gate counts under free-XOR + half-gates, the model BitVM3-core \
         uses. Garbled size is 32 bytes per non-free gate.\n\n",
    );
    s.push_str(&format!(
        "**Anchor:** BN254 Groth16 verifier = {} non-free gates = {}. Reproduced from \
         `garbled-snark-verifier`, matching the 2.7e9 figure in the BitVM3 paper.\n\n",
        fmt_count(anchor),
        fmt_bytes(anchor * 16)
    ));

    s.push_str("## Measured primitives\n\n");
    s.push_str("| gadget | family | non-free | free | non-free per unit | unit | verified |\n");
    s.push_str("|---|---|---:|---:|---:|---|:--:|\n");
    for m in ms {
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            m.name,
            m.family,
            fmt_count(m.nonfree),
            fmt_count(m.free),
            m.nonfree_per_unit()
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            m.unit_label,
            if m.verified { "yes" } else { "**NO**" }
        ));
    }

    s.push_str("\n## Modelled verifiers\n\n");
    s.push_str("These are models, not measurements. Parameters are listed under each row.\n\n");
    s.push_str("| model | merkle | leaf hash | fold arith | total non-free | garbled |\n");
    s.push_str("|---|---:|---:|---:|---:|---:|\n");
    for e in es {
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            e.name,
            fmt_count(e.nonfree_merkle),
            fmt_count(e.nonfree_leaf_hash),
            fmt_count(e.nonfree_fold_arith),
            fmt_count(e.nonfree_total),
            fmt_bytes(e.garbled_bytes)
        ));
    }
    s.push('\n');
    for e in es {
        s.push_str(&format!("**`{}` assumptions**\n\n", e.name));
        for a in &e.assumptions {
            s.push_str(&format!("- {a}\n"));
        }
        s.push_str(&format!(
            "- queries={}, log_domain={}, fold_arity={}, log_final={}, oracles={}, \
             leaf_elements={}\n\n",
            e.params.queries,
            e.params.log_domain,
            e.params.fold_arity,
            e.params.log_final,
            e.params.oracles,
            e.params.leaf_elements
        ));
    }
    s
}
