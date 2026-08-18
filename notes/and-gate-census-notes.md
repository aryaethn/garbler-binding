# Handoff: AND-gate census for BitVM3 garbling backends

Written for a local Claude Code agent picking this up with full rustc. Everything
below has been built and run; the numbers are measured, not projected.

---

## 1. What this is

Research target #1 from `bitvm-research-directions.md`: a reproducible harness
that measures the **non-free (AND) gate count** of the primitives a SNARK
verifier is built from, under the free-XOR + half-gates model that BitVM3-core
uses.

This number is the entire off-chain budget. Under free-XOR, XOR/XNOR/NOT cost
zero ciphertexts and each AND-variant gate costs two 16-byte ciphertexts, so:

```
garbled circuit size = 32 bytes x (non-free gate count)
```

The BitVM3 paper quotes 2.7e9 non-free gates / 41.2 GB for the BN254 Groth16
verifier, and its Table 9 compares backends using numbers "reported in the
respective papers ... on varying commodity hardware." The point of this crate is
to replace that with one harness where every number is produced the same way and
every gadget is checked against a native reference.

## 2. Status: done and verified

- **Anchor reproduced exactly.** `results/anchor.json`: 2,715,041,234 non-free
  gates for the BN254 Groth16 verifier, from upstream's own unmodified example.
  Matches the paper's 2.7e9.
- **18 gadgets implemented and measured**, every one validated bit-for-bit
  against a native reference (`sha2`, `blake3`, `tiny-keccak`, or a
  reference implementation in the same file). The census prints
  `All gadgets verified against native references: YES` or names the failure.
- **Two independent calibration checks pass**, which is why I trust the rest:
  - SHA-256 compression measures 22,700 non-free gates, against the
    long-standing literature figure of ~22-23k.
  - Keccak-f[1600] measures exactly 38,400 = 24 rounds x 1600, which is
    forced by the structure (only chi costs, one AND per state bit per round).
  - Bonus: GF(2^k) Karatsuba lands on exactly 3^5=243, 3^6=729, 3^7=2187 for
    k=32/64/128, as the recursion demands.

## 3. The headline result, which is not what I expected

**Binary fields win enormously at the arithmetic level and it barely matters,
because the hash dominates everything.**

Field arithmetic, measured:

| operation | non-free gates | per bit of field element |
|---|---:|---:|
| `gf2_32_mul_karatsuba` | 243 | 7.6 |
| `m31_mul` | 2,510 | 81.1 |
| `gf2_64_mul_karatsuba` | 729 | 11.4 |
| `goldilocks_mul` | 10,980 | 171.6 |
| `gf2_128_square` | **0** | 0 |
| `gf2_128_mul_const` | **0** | 0 |
| `m31_add` | 95 | 3.1 |
| binary field add | **0** | 0 |

So the thesis is confirmed at the primitive level: binary field multiplication
is **10x to 15x** cheaper than the comparable prime field, and squaring,
constant multiplication and addition are literally free because they are
GF(2)-linear maps.

Then you compose it into a FRI verifier and the advantage almost vanishes:

| modelled verifier | non-free | garbled | vs Groth16 |
|---|---:|---:|---:|
| `prime_field_FRI__m31_poseidon2` | 49.32B | 735 GB | **18x worse** |
| **BN254 Groth16 (measured anchor)** | **2.72B** | **40.5 GB** | 1.0x |
| `prime_field_FRI__m31_keccak` | 1.48B | 22.1 GB | 1.8x better |
| `binary_field_FRI__keccak` | 1.37B | 20.5 GB | 2.0x better |
| `binary_field_FRI__blake3` | 403M | 6.0 GB | **6.7x better** |
| `binary_field_FRI__lowmc_hash` | 41.9M | 639 MB | **65x better** |

Read the two middle rows against each other: holding the hash fixed at Keccak
and changing *only the field* from M31 to GF(2^128) buys **7.6%**. Holding the
field fixed at GF(2^128) and changing *only the hash* from Keccak to BLAKE3 buys
**3.4x**, and to a LowMC-style low-AND compression **33x**.

**Conclusion that should drive the next phase: in a garbled verifier, the field
is a rounding error and the hash is the entire design.**

Two corollaries worth their own paragraph:

1. **Poseidon2 is a trap.** If you garble an off-the-shelf Plonky3 or Stwo
   verifier without touching it, you get 735 GB, eighteen times *worse* than the
   Groth16 baseline you were trying to beat. Poseidon is engineered to be cheap
   inside a prime-field SNARK, which is exactly what makes it maximally
   expensive as a Boolean circuit. Any "just use a STARK" proposal that does not
   explicitly change the Merkle hash is worse than doing nothing. This also
   explains why the BitVM3 paper's Table 9 lists Yao+STARK at ~10 GB rather than
   the ~1 GB an optimist would guess: the STARK they cite must already be using
   a bit-oriented hash.

2. **BLAKE3 is free money.** It costs 163 non-free gates per byte of rate versus
   Keccak's 282 and SHA-256's 355, and BitVM already maintains a BLAKE3
   implementation in Bitcoin Script (`bitvm/src/hash/`) and uses it in the
   chunker. A garbled verifier should use BLAKE3 for its Merkle tree. That is a
   deployable recommendation available today with zero new cryptography.

## 4. Where the model is soft

Everything in `gadgets/` is measured. Everything in `models.rs` is a formula
over those measurements, and its parameters are printed alongside every result.
Known weaknesses, in the order I would fix them:

- **No Merkle cap.** Real FRI verifiers truncate the top few levels of every
  Merkle path into a directly-committed "cap". With a cap of 2^6, each path
  loses 6 nodes out of ~24, so the Merkle term is overstated by roughly 25%.
  This does not change any conclusion but it makes the absolute numbers
  pessimistic.
- **Oracles are not batched.** I charge 3 separate trees at full depth. Most
  implementations batch trace columns into one tree, which would cut the
  first-phase Merkle cost by close to 3x.
- **Fold arithmetic is a hand-count** of ~3 extension multiplications per query
  per round. It contributes under 1% of the total in every configuration, so
  even a 10x error here is invisible. This is itself part of the finding.
- **Poseidon2 is modelled, not implemented.** Its cost is derived analytically
  from the measured `m31_mul` (8 full rounds x 16 S-boxes + 56 partial rounds,
  x^5 = 3 muls each). Implementing it would firm this up, and given it is the
  most dramatic row, it is worth doing.
- **Constant folding is not applied.** Where a gadget adds a compile-time
  constant (SHA-256 round constants, LowMC round keys) the executor still emits
  AND gates against constant wires. This overstates SHA-256 by a few percent.
- **Free gates are not free in wall-clock time.** LowMC-128 with m=1, r=182
  needs only 546 non-free gates but 1.49M free ones. Ciphertext size is what
  BitVM3 pays for in bandwidth and storage; garbling *time* still scales with
  total gates. Any hash chosen for low AND count needs a second column in the
  table for total gate count. `results/census.json` has it.

## 5. What I would do next, in order

1. **Implement Poseidon2 as a real circuit** and replace the modelled row. It is
   the most load-bearing estimate in the table and the easiest to firm up.
   `gadgets/primefield.rs` already has everything it needs.
2. **Add the Merkle cap and oracle batching to `models.rs`** as explicit
   parameters, then re-run. Expect the hash-dominated conclusion to survive and
   the absolute numbers to drop 2-3x.
3. **Implement a real Binius64 or Flock verifier circuit** rather than the
   generic FRI model. This is the big one and it is where the model stops being
   a model. The gadget library here (GF(2^k) Karatsuba, free squaring, free
   constant multiplication) is the foundation it needs.
4. **Survey low-AND hash candidates properly.** LowMC is in here as a *lower
   bound*, not a recommendation, and it has a genuinely difficult cryptanalytic
   history: several parameter sets have been broken by algebraic attacks. The
   real question this crate has surfaced is: what is the cheapest hash, in AND
   gates per byte, that the cryptographic community would actually accept in a
   Bitcoin bridge? Candidates to price: Rain, fixed-key AES constructions
   (AES-128 is ~5,120 ANDs per block = 320/byte, no better than Keccak, so
   probably not), and sponges built directly over binary tower fields.
5. **Cross-check against the BitVM3 paper's Table 9** row by row, and if the
   numbers disagree, that disagreement is itself a result worth writing up.

## 6. Build and run

```bash
./scripts/setup.sh        # vendors garbled-snark-verifier + applies the SP1 patch
cd and-gate-census
cargo run --release --bin census -- --json ../results/census.json --md ../results/census.md
```

If rustup tries to download toolchain 1.90 (the upstream repo pins it via
`rust-toolchain.toml`), `export RUSTUP_TOOLCHAIN=stable` first. Any recent
stable satisfies the crate's actual `rust-version = "1.90"` requirement.

Reproduce the anchor from upstream's unmodified example:

```bash
cd vendor/garbled-snark-verifier
cargo run --release --no-default-features --features test-utils \
    --example groth16_gc_gate_count -- --json
```

Runtime on 2 cores: ~2 min to build, ~4 min for the anchor, seconds for the
census.

## 7. Layout

```
BitVM/
  HANDOFF.md                      <- this file
  bitvm-research-directions.md    <- the wider research map this came from
  scripts/setup.sh
  results/
    anchor.json                   <- measured BN254 Groth16 ground truth
    census.json                   <- full machine-readable output
    census.md                     <- rendered tables
  and-gate-census/
    src/
      lib.rs
      bits.rs                     <- free vs non-free primitives, adders, mux
      harness.rs                  <- measure(): build, execute, verify, census
      models.rs                   <- composition formulas (the arguable part)
      gadgets/
        binfield.rs               <- GF(2^k): Karatsuba, free square, free const-mul, inversion
        primefield.rs             <- M31, Goldilocks: mul, add, reduction
        sha256.rs
        blake3.rs
        keccak.rs
        lowmc.rs                  <- low-AND lower bound (read the caveat)
      bin/census.rs
  vendor/garbled-snark-verifier/  <- patched clone, see scripts/setup.sh
```

## 8. One caution on framing

If you write this up, do not lead with "binary fields make BitVM cheaper." The
measurement says that is true and nearly irrelevant. Lead with the hash. The
interesting, defensible claim coming out of this is:

> The cost of a garbled SNARK verifier is set almost entirely by the
> multiplicative complexity of its Merkle hash. Field choice moves the total by
> under 10%; hash choice moves it by more than three orders of magnitude, and
> the hash that today's STARK stacks default to is the worst possible choice for
> this setting.

Binary fields still matter, but as an *enabler*: they are what let you use a
bit-oriented hash without paying a conversion tax, and they are what makes the
whole construction post-quantum. They are not the source of the savings.
