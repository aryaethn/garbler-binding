# AND-gate census

Non-free (AND-variant) gate counts under free-XOR + half-gates, the model BitVM3-core uses. Garbled size is 32 bytes per non-free gate.

**Anchor:** BN254 Groth16 verifier = 2.72B non-free gates = 40.46 GB. Reproduced from `garbled-snark-verifier`, matching the 2.7e9 figure in the BitVM3 paper.

## Measured primitives

| gadget | family | non-free | free | non-free per unit | unit | verified |
|---|---|---:|---:|---:|---|:--:|
| `gf2_32_mul_karatsuba` | binary_field | 243 | 1.33K | 7.6 | bit of field element | yes |
| `gf2_32_mul_schoolbook` | binary_field | 1.02K | 1.08K | 32.0 | bit of field element | yes |
| `gf2_64_mul_karatsuba` | binary_field | 729 | 4.12K | 11.4 | bit of field element | yes |
| `gf2_64_mul_schoolbook` | binary_field | 4.10K | 4.22K | 64.0 | bit of field element | yes |
| `gf2_128_mul_karatsuba` | binary_field | 2.19K | 12.61K | 17.1 | bit of field element | yes |
| `gf2_128_square` | binary_field | 0 | 508 | 0.0 | bit of field element | yes |
| `gf2_128_mul_const` | binary_field | 0 | 7.93K | 0.0 | bit of field element | yes |
| `gf2_32_inv_naive_chain` | binary_field | 7.53K | 45.14K | 235.4 | bit of field element | yes |
| `m31_add` | prime_field | 95 | 346 | 3.1 | bit of field element | yes |
| `m31_mul` | prime_field | 2.51K | 4.59K | 81.1 | bit of field element | yes |
| `goldilocks_add` | prime_field | 194 | 709 | 3.0 | bit of field element | yes |
| `goldilocks_mul` | prime_field | 10.98K | 21.03K | 171.6 | bit of field element | yes |
| `sha256_compression` | hash | 22.70K | 98.98K | 354.6 | byte of rate | yes |
| `blake3_compression` | hash | 10.42K | 49.34K | 162.8 | byte of rate | yes |
| `keccak_f1600` | hash | 38.40K | 115.29K | 282.4 | byte of rate | yes |
| `lowmc_128_m10_r20` | low_and_primitive | 600 | 165.11K | 37.5 | byte of block | yes |
| `lowmc_128_m1_r182` | low_and_primitive | 546 | 1.49M | 34.1 | byte of block | yes |
| `lowmc_256_m10_r38` | low_and_primitive | 1.14K | 1.25M | 35.6 | byte of block | yes |

## Modelled verifiers

These are models, not measurements. Parameters are listed under each row.

| model | merkle | leaf hash | fold arith | total non-free | garbled |
|---|---:|---:|---:|---:|---:|
| `binary_field_FRI__keccak` | 1.28B | 80.64M | 11.81M | 1.37B | 20.47 GB |
| `prime_field_FRI__m31_keccak` | 1.28B | 80.64M | 122.82M | 1.48B | 22.12 GB |
| `binary_field_FRI__blake3` | 346.85M | 43.75M | 11.81M | 403.08M | 6.01 GB |
| `prime_field_FRI__m31_poseidon2` | 46.19B | 2.91B | 122.82M | 49.32B | 734.89 GB |
| `binary_field_FRI__lowmc_hash` | 19.98M | 10.08M | 11.81M | 41.91M | 639.47 MB |

**`binary_field_FRI__keccak` assumptions**

- Binary field GF(2^128) used directly as the challenge field; no extension needed.
- 100 queries at rate 1/2 targets roughly 100-bit soundness.
- Merkle leaves hold 8 field elements.
- queries=100, log_domain=24, fold_arity=2, log_final=6, oracles=3, leaf_elements=8

**`prime_field_FRI__m31_keccak` assumptions**

- M31 needs a degree-4 extension for challenge soundness; extension multiplication modelled as ~4^1.585 base multiplications.
- Same query count, domain and leaf shape as the binary-field row so the only variable is the field.
- queries=100, log_domain=24, fold_arity=2, log_final=6, oracles=3, leaf_elements=8

**`binary_field_FRI__blake3` assumptions**

- Same as the keccak row but with BLAKE3 as the Merkle hash. BLAKE3 costs 163 non-free gates per byte of rate versus Keccak's 282, and BitVM already has a BLAKE3 implementation in Bitcoin Script.
- queries=100, log_domain=24, fold_arity=2, log_final=6, oracles=3, leaf_elements=8

**`prime_field_FRI__m31_poseidon2` assumptions**

- THE CAUTIONARY ROW. This is what you get if you garble an off-the-shelf Plonky3/Stwo verifier without changing anything: Poseidon2 is designed to be cheap inside a prime-field SNARK, which makes it maximally expensive as a Boolean circuit.
- Poseidon2 width 16 over M31: 8 full rounds x 16 S-boxes + 56 partial rounds x 1 S-box, x^5 = 3 multiplications each, priced at the measured m31_mul.
- Hash cost is modelled, not measured. Everything it is built from is measured.
- queries=100, log_domain=24, fold_arity=2, log_final=6, oracles=3, leaf_elements=8

**`binary_field_FRI__lowmc_hash` assumptions**

- SPECULATIVE. Substitutes a LowMC-based compression for Keccak to show the ceiling of what a garbling-friendly hash could buy. Not a security recommendation.
- Rate assumed 16 B/compression, far worse than Keccak's 136 B, which partly cancels the per-compression saving. This is the honest version of the tradeoff.
- queries=100, log_domain=24, fold_arity=2, log_final=6, oracles=3, leaf_elements=8

