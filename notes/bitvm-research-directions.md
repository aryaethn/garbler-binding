# BitVM Contribution Map: Garbling Layer, Protocol Layer, and the Binius/Flock Thesis

Research notes, August 2026. Grounded in the three BitVM papers, the BitVM/BitVM repo at HEAD (commit `7d1ca36`), and current literature.

---

## 0. Executive summary

Three things worth knowing before picking a direction:

1. **The garbling layer is the most active and most dangerous part of the stack.** The original BitVM3 note (bitvm.org, July 2025) proposed a novel RSA-based *arithmetic* garbling scheme. Fairgate Labs broke it within weeks: a circuit with two AND gates and three inputs is enough for an evaluator to forge wire labels, destroying authenticity ([eprint 2025/1291](https://eprint.iacr.org/2025/1291)). The published BitVM3 paper you have (eprint 2026/933) retreats to standard Yao half-gates with free-XOR, which is provably secure but costs 41.2 GB per circuit, and reframes the contribution as a *modular* proof system (BitVM3-core) into which any garbling backend can be plugged. That modularity is an invitation.

2. **The arithmetic garbling line has already won on size, and the remaining problems are correctness and Bitcoin-compatibility.** Argo and BABE get from ~40 GB down to ~22-25 MB by exploiting the field structure of Groth16 rather than flattening to Boolean. Duty-Free Bits (Alpen, [eprint 2026/476](https://eprint.iacr.org/2026/476)) fixed the projectivity mismatch that made arithmetic garbling incompatible with Bitcoin's bitwise Lamport encodings. Mosaic and Fairgate's "constant-size proofs of garbling correctness" are attacking setup verification. If you enter the garbling layer, you are entering a crowded, fast-moving race with Alpen, Fairgate, Stanford/Byzantine, and TU Wien in it.

3. **The protocol layer has one problem nobody has solved, and the BitVM3 authors say so explicitly:** the signer committee. It is the last honest-party assumption, it must stay online to onboard operators and register deposits, and no covenant soft fork is going to rescue it soon (nothing is activated; CTV's own activation client targets minimum activation around May 2027; BIP-110 signaling is at ~2%).

And on your Binius question: **there is a real thesis there, it is unclaimed, and it has one hard blocking constraint.** See Part 3.

---

## Part 1: The garbling layer

### 1.1 What actually drives cost

In BitVM3-core, the operator garbles the SNARK verifier circuit once at setup. Cost decomposes into four independent quantities, and different papers attack different ones:

| Quantity | What it is | Current value (Yao + Groth16) |
|---|---|---|
| **Circuit size** | non-free gates in the verifier circuit | 2.7e9 non-free gates |
| **Garbled circuit size** | ciphertexts the operator must publish and every challenger must download | 41.2 GB (2.7e9 half-gates x 16 B) |
| **Encoding size** | input labels bound to the on-chain commitment (the "projectivity" cost) | dominated by bit-decomposition in arithmetic schemes |
| **Setup verification** | proving to challengers that the garbling was honest | cut-and-choose (181, 7): ~288 GB, ~3.5 h |

The BitVM3 paper's own headline is the *on-chain* number ($9 total, $0.20 Disprove), which is excellent. Every remaining problem is off-chain.

Under free-XOR + half-gates, **XOR gates cost zero and AND gates cost two ciphertexts.** So circuit cost is exactly the AND-gate count, i.e. the multiplicative complexity of the verifier over GF(2). Hold onto that; it is the whole basis of the Binius argument in Part 3.

### 1.2 Timeline of the field

- **Dec 2023**: BitVM1. NAND circuit committed in a Taptree, O(log C) bisection, designated verifier.
- **2024**: BitVM2. Groth16 verifier in Script, chunked, permissionless challenging in 3 transactions. Deployed as Clementine (Citrea) and BOB.
- **Jul 2025**: BitVM3 note proposes RSA-based arithmetic garbling. Enormous claimed savings.
- **Aug 2025**: Fairgate breaks it ([2025/1291](https://eprint.iacr.org/2025/1291)). The break is not an edge case; two AND gates suffice.
- **Late 2025 - 2026**: the arithmetic garbling line matures with provable security. Glock (Alpen, [2025/1485](https://eprint.iacr.org/2025/1485)), Argo MAC (Eagen & Lai, [2026/049](https://eprint.iacr.org/2026/049)), BABE (Garg, Kolonelos, Sergeevich, Sridhar, Tse, [2026/065](https://eprint.iacr.org/2026/065)), OHMG (Futoransky, Barbara, Fernandez, Larotonda, [2025/2338](https://eprint.iacr.org/2025/2338)).
- **Mar 2026**: Duty-Free Bits ([2026/476](https://eprint.iacr.org/2026/476)) makes arithmetic garbling projective with additive rather than multiplicative (~254x) overhead. Reported: BABE Embryo encoding 22.16 MiB -> 500 KiB; Argo MAC encoding 6.8 MiB -> 355 KiB.
- **2026**: setup verification becomes the frontier. Mosaic ([2026/812](https://eprint.iacr.org/2026/812)) amortizes cut-and-choose so one set of on-chain signatures covers many copies. Fairgate presents "From Cut-and-Choose to Constant-Size Proofs of Garbling Correctness" at Stanford's Workshop on Cryptography for Bitcoin (SBC 2026), with a STARK-recursive prover at ~25k gates/sec. Also circulating: Antichain Winternitz ([2026/1568](https://eprint.iacr.org/2026/1568)), TRAPGC-DV ([2026/1430](https://eprint.iacr.org/2026/1430)).
- **Jul-Aug 2026**: BitVM3 paper published. GOAT/ZKM push Ziren toward BitVM3 mainnet (Veridise audit complete, second Consensys review). Citrea says it is "actively working on improving Clementine's design with BitVM3."

### 1.3 Where the gaps are

**Gap A: nobody has published a rigorous AND-gate accounting across candidate verifier circuits.** The BitVM3 paper's Table 9 reports Yao + Groth16 at ~40 GB and Yao + STARK at ~10 GB, a 4x gap, cited from other papers on varying hardware. That is a suspiciously coarse number for a quantity that determines the entire off-chain budget. A careful, reproducible gate-count harness across {Groth16/BN254, Groth16/BLS12-381, a Plonky3 STARK, a Binius64 verifier, a Flock verifier} would be genuinely useful to the whole field and is a two-to-four week project. It is also the necessary precondition for the Binius thesis. Low novelty, high utility, very high leverage as a first contribution that gets you known.

**Gap B: the 41 GB (or 22 MB) data availability problem is treated as an assumption, not a mechanism.** BitVM3 says the operator "shares the garbled circuit GC, the decoding information d, pk_GS, and the Assert transaction body with the challengers or makes them publicly available e.g., via a bulletin board" (Section 4.1) and mentions torrents. There is no incentive analysis, no penalty for withholding, no proof that an honest challenger who arrives late can still obtain the circuit. Given that soundness depends on at least one honest challenger *who has the circuit*, this is a soundness-relevant gap dressed up as an engineering detail. A paper on "data availability for BitVM garbled circuits" with an actual mechanism (erasure coding + sampling + on-chain slashing for withholding) is unclaimed as far as I can find.

**Gap C: setup verification cost is still the elephant.** Cut-and-choose at (181, 7) costs ~288 GB of storage and 3.5 hours across 16 cores, and requires a public randomness beacon or a coin-tossing committee. Mosaic and Fairgate are both on this. Entering here means competing directly with two funded teams. Do it only if you have a specific idea, not as an exploration.

**Gap D: garbling backends are compared but not benchmarked under a common harness.** Table 9 is compiled "using numbers reported in the respective papers; computing time is on varying commodity hardware, e.g., Apple Silicon M4, AMD Ryzen 7 7840U." That is an honest disclaimer and also an open invitation. An apples-to-apples benchmark suite for Bitcoin-compatible garbling schemes (Yao half-gates, Glock, Argo MAC, BABE, with and without Duty-Free Bits projectivization) would be cited by everyone. This is the ecosystem-service version of Gap A.

---

## Part 2: The protocol layer

### 2.1 The committee problem (the authors' own "most pressing direction")

Quoting BitVM3 Section 10 nearly verbatim: the reliance on the signing committee is "the most significant limitation of our construction, shared with all BitVM-family designs." Safety rests on existential honesty (one signer deletes their key), but **liveness requires the committee to be available whenever a new operator is onboarded or a new deposit is registered.** A committee that goes offline freezes new bridge activity even though existing deposits stay safe.

They name three mitigation classes and endorse none:

1. Rotating committees with well-defined handoff procedures.
2. A rationally incentivized committee whose members are bonded against unavailability.
3. A cryptographic construction that eliminates the setup committee altogether.

**Assessment of each as a contribution target:**

- **(1) Rotating committees.** Tractable, valuable, and mostly a protocol-design and analysis exercise rather than a new primitive. The hard part is the handoff: the new committee must re-authorize the existing transaction graph without the old committee's keys, which without covenants means the old committee pre-signs the handoff, which means the old committee must be alive at handoff time, which is the problem you were trying to solve. There is a real chicken-and-egg here and a clean solution would be publishable. Medium effort, medium-high novelty.

- **(2) Bonded committees.** This is economics and mechanism design more than cryptography. Cheaper to do, easier to get wrong, harder to publish at a crypto venue but very attractive to the deployed bridges (Citrea, BOB, Alpen), who have this problem *today* in production.

- **(3) Eliminating the committee.** This is what covenants would do. `CheckCovenant` is currently emulated by n-of-n pre-signing precisely because Bitcoin has no covenant opcode. Status as of August 2026: **nothing activated.** OP_CTV (BIP-119) has a published activation client with a start date of March 30, 2026 and minimum activation around May 2027 at a 90% miner threshold; OP_CAT (BIP-347) reached "Complete" spec status March 1, 2026 with no activation parameters; BIP-110 opened mandatory signaling around block 961,632 (~Aug 9, 2026) and is sitting near 2% miner support. So a covenant-based committee elimination is a paper you can write now that becomes deployable in 2027 at the earliest. That is actually a good position to be in: **specify the post-CTV BitVM3 bridge precisely, and show exactly how much of the committee falls away under each covenant proposal.** Nobody has done a rigorous "BitVM under CTV vs CAT vs CSFS vs TXHASH" comparison, and the covenant debate would benefit enormously from a concrete high-value application analysis. High visibility, moderate effort, and it positions you in two communities at once.

### 2.2 Operator collateral and capital efficiency

Clementine has been live on Bitcoin mainnet for six months and has processed roughly 150 BTC. Its design already improves on naive BitVM2 by having collateral back "an entire round of multiple user withdrawals" rather than one peg-out each. The BitVM3 paper acknowledges this is orthogonal to their contribution and that "the two could be composed in a future deployment" (Section 9, discussion of Clementine).

**That composition is an unclaimed, well-defined, and immediately useful piece of work.** Clementine's payoff rounds let operator collateral be reused across deposits and let a single successful challenge slash multiple misbehaviors; BitVM3-core makes the verification itself nearly free. Nobody has written down the combined protocol and proven it secure. It is a concrete, bounded, publishable result with two production teams waiting for it.

### 2.3 Data availability, again, at the protocol layer

Distinct from Gap B above. In the BitVM3 rollup variant, the PegOut transaction is embedded in the burn transaction on the rollup (via OP_RETURN) and an operator extracts and completes it. The user's connector output is what prevents concurrency races between operators. Worth checking whether the concurrency argument survives operator collusion and mempool-level censoring; the paper asserts uniqueness rules out races but the argument is one sentence (Section 6.3).

### 2.4 The light client

BitVM3's variable-difficulty light client is, per the authors, the first on-chain Bitcoin light client secure under variable difficulty with permissionless challenging. The construction binds epoch timestamp commitments to consensus time via `OP_CLTV` at `T_i - 2 hours`, with a burn path if the operator misses the liveness deadline `i*2016 + k + m_l`.

Two things to poke at:

- The 2-hour allowance is justified by the fact that Bitcoin blocks may be slightly ahead of network time. The security argument leans on Concentrated Chain Quality and Concentrated Code Quality results from Garay-Kiayias-Leonardos. Theorem 7.3 requires `m > (2/delta - 1)x`. It is worth checking whether the parameter choices are tight and what happens under realistic hashrate volatility (e.g. the post-halving hashrate swings, or a large miner going offline) rather than asymptotic assumptions.
- The implementation in the repo (`header-chain/`, `final-spv/`) is a **RISC Zero** guest proving SHA-256d header chains with an MMR (`mmr_guest.rs`, `mmr_native.rs`) and difficulty recalculation (`calculate_new_difficulty`, `BLOCKS_PER_EPOCH = 2016`). This is where Flock enters. See Part 3.

---

## Part 3: The Binius / Flock thesis

### 3.1 What these things are

**Binius** (Diamond & Posen, Irreducible) is a SNARK over towers of binary fields. The pitch: represent data in its natural bit width instead of embedding single bits into 254-bit prime field elements, so a bit costs a bit. **Binius64** (released Sept 2025) is the CPU-optimized descendant that abandons the tower-VM framing for native 64-bit words with direct constraints for XOR, AND, shifts, and 64-bit multiply. Current proof sizes: 187.75 KiB (ECDSA) and 322.11 KiB (XMSS), with a succinct verifier still on the roadmap.

**Flock** (Bünz, Rothblum, Wang, [eprint 2026/1329](https://eprint.iacr.org/2026/1329) / [arXiv 2607.27491](https://arxiv.org/abs/2607.27491), June 2026) is a hash-based SNARK for **batches of identical Boolean circuits**, built on binary fields with the ring-switching technique from Binius, plus new lincheck and zerocheck optimizations. It deliberately gives up generality (no arbitrary VM, no permutation/memory-checking machinery) to get extreme throughput on the one workload that dominates real SNARK cost: hashing.

Reported numbers, single core on an M4 Max: 82.1k BLAKE3 compressions/sec, 42.1k SHA-256 compressions/sec, 30.7k Keccak permutations/sec, under 250x overhead versus native execution. Over 660k BLAKE3 compressions/sec on ten cores. 9x faster than Binius64 on SHA-256 and roughly 500x faster than the fastest elliptic-curve SNARK tested. Its stated target application is post-quantum hash-based signatures (Lamport, XMSS).

Read that last sentence again in a BitVM context. **BitVM's entire state mechanism is Lamport and Winternitz commitments.**

### 3.2 Three distinct insertion points

These are separable. You can pursue any one without the others.

---

#### Insertion point A: Flock as the light-client prover (low risk, near-term, deployable)

The BitVM header-chain circuit is a RISC Zero guest computing SHA-256d over Bitcoin block headers plus MMR updates plus difficulty recalculation. A 2016-block epoch is roughly 6k SHA-256 compressions for the headers alone (each 80-byte header is 2 compressions for the outer hash plus 1 for the inner), plus the MMR path hashes. **This is precisely, exactly, Flock's target workload: a large batch of identical Boolean circuits with a hash-chain structure.** Flock explicitly supports "hash-chains and Merkle path openings."

At 42k SHA-256 compressions/sec/core, an entire difficulty epoch's header verification proves in well under a second of single-core time. The current RISC Zero path is orders of magnitude slower because it pays general-purpose zkVM overhead on a workload that has none of the generality.

**What this gets you:** operator proving cost for the light client drops to nearly nothing. It does not by itself fix the on-chain path (see 3.3), because you still need a small proof for Assert, so in the near term this is a *composition* result: Flock proves the header chain, and a small-proof outer SNARK proves the Flock verifier. But even standalone, it is a straightforward, measurable, PR-able engineering contribution to `header-chain/` and `final-spv/`, and it is the cheapest way to establish credibility in this codebase.

**Risk:** low. **Novelty:** low-to-medium (engineering, not research). **Time:** weeks. **Blocking dependency:** Flock's implementation is described as an "aggressively optimized proof-of-concept," so availability and API stability need checking.

---

#### Insertion point B: a binary-field verifier inside the garbled circuit (high risk, high reward, unclaimed)

This is the real research thesis, and the argument is clean.

Under free-XOR, **garbled circuit size equals the AND-gate count of the circuit**, i.e. its multiplicative complexity over GF(2). Now compare what you are garbling:

- **Groth16 over BN254**: arithmetic in a 254-bit *prime* field. Every addition is a modular add with a carry chain; every multiplication is a 254-bit multiply plus Montgomery reduction. Carries are AND gates. Result: 2.7 billion non-free gates, 41.2 GB, ~6 minutes to garble.
- **A binary-field proof system**: field addition **is** XOR, which is **free** under free-XOR. Field multiplication is carryless, and in a tower construction it is subquadratic with no carry propagation at all. The remaining AND gates live almost entirely in the hash function used for the Merkle/FRI commitments.

The BitVM3 paper's own Table 9 already shows the direction of the effect: Yao + STARK is ~10 GB versus Yao + Groth16 at ~40 GB, a 4x reduction, and it is the **only post-quantum row in the table.** But that STARK is presumably over a prime field (Mersenne-31 or Goldilocks), so it still pays carry-chain costs on every field operation. A binary-field system should do materially better, and the remaining cost concentrates in one place you can then attack independently.

**The follow-on idea that makes this more than an incremental improvement:** once the AND gates are concentrated in the hash, choose the hash for *low multiplicative complexity over GF(2)* rather than for CPU speed. There is a whole MPC-friendly primitives literature (LowMC, Rain, and the low-AND-depth cipher family) built for exactly this cost model, and it has never been combined with a binary-field SNARK for a Bitcoin garbling application. "Binary-field SNARK + minimal-AND hash, garbled" is, as far as I can find, an unoccupied point in the design space. Flock's zerocheck is optimized specifically for bit-vector AND operations, which is a suggestive alignment.

**Risk:** high. You are betting that binary fields beat the *arithmetic* garbling line (Argo/BABE at ~22-25 MB), not just the Boolean Yao baseline (41 GB). Arithmetic garbling exploits Groth16's prime-field structure homomorphically and gets three orders of magnitude, which is a lot to make up. The honest framing is that these are **incomparable** rather than competing: arithmetic garbling gets you small, binary fields get you **post-quantum and small**. Which brings us to the argument that makes this fundable.

**The post-quantum framing is the strongest version of this pitch.** Every deployed and proposed BitVM design (BitVM2, BitVM3, Argo, BABE, Glock) rests on Groth16 over a pairing-friendly curve. All of them are marked "post-quantum: no" in Table 9. Meanwhile Bitcoin is in the middle of an active post-quantum migration debate (BIP-360 P2QRH, BIP-361 legacy signature sunset), and Ethereum has already moved to drop Poseidon on post-quantum grounds. **A trust-minimized Bitcoin bridge whose security survives a cryptographically relevant quantum computer does not currently exist.** Building one requires a hash-based proof system, which means binary fields are the natural choice, which means the AND-gate argument above is not an optimization but the enabling technique. That is a coherent, timely, defensible paper.

**Risk:** high. **Novelty:** high. **Time:** months. **First step:** Gap A from Part 1, the gate-count harness. You can falsify or confirm the core hypothesis in a few weeks of work before committing.

---

#### Insertion point C: binary fields in Bitcoin Script (BitVM2 layer)

Weaker than it looks, but worth understanding so you do not waste time on it.

The intuition is right: BitVM2's ~1 GB Groth16 Script is dominated by BN254 pairing, which means 254-bit modular multiplication emulated on a stack machine with no multiply opcode. Binary-field arithmetic would replace that with XOR and carryless multiply.

**The problem is that Bitcoin disabled OP_AND (0x84), OP_OR (0x85), and OP_XOR (0x86), along with OP_CAT.** So you cannot do binary field arithmetic natively either. The repo already works around this: `bitvm/src/u4/` exists precisely because nibble-wise lookup tables are the cheapest way to emulate bitwise operations, and that machinery is what makes the BLAKE3 implementation in `bitvm/src/hash/` feasible.

So the honest question is: is a binary-field verifier, emulated via u4 lookup tables, cheaper in Script than BN254 pairing? Probably yes, possibly by a lot, because BLAKE3 in Script is already a solved and reasonably efficient problem and a hash-based verifier is mostly BLAKE3. But you immediately hit the same wall as everywhere else: BitVM2's on-chain cost is O(P + C), and hash-based proofs are 50 to 300 KiB. The chunker would have to commit to intermediate states via Winternitz across a much larger proof.

Related and worth reading before spending time here: the [OP_STARK_VERIFY proposal on Delving Bitcoin](https://delvingbitcoin.org/t/proposal-op-stark-verify-native-stark-proof-verification-in-bitcoin-script/2056) and the objections it drew (consensus risk, DoS vectors, ossification around one STARK flavor, credible neutrality). Those objections are informative about what the Bitcoin community will and will not accept, and they apply to any "enshrine a proof system" idea.

**Verdict:** interesting, but dominated by Insertion point B for the same effort. Pursue only if you specifically want to work in Script.

---

### 3.3 The blocking constraint (read this before committing to anything)

**BitVM3's on-chain cost is linear in proof size, and the constant is brutal.**

From the paper's Section 8.1: the Groth16 proof of 128 bytes is split into N = 128 digits of 8 bits each, and each digit requires a 65-byte Schnorr adaptor signature in the witness. Total witness 9159 B, transaction weight 9707 WU, ~2.4 kvB, ~4853 sats, about $4 at 2 sat/vB. Table 1 states on-chain cost O(P) explicitly.

Working the ratio out:

- **~72 bytes of witness per byte of proof.**
- **~38 sats per byte of proof**, i.e. roughly **$0.03 per proof byte** at the paper's own fee assumption.

Consequences:

| Proof size | Approx. witness | Approx. vsize | Approx. cost | Standard? |
|---|---|---|---|---|
| 128 B (Groth16) | 9.2 kB | 2.4 kvB | ~$4 | yes |
| 1 kB | 72 kB | 18 kvB | ~$31 | yes |
| 5 kB | 358 kB | 90 kvB | ~$148 | marginal (100 kvB limit) |
| 50 kB (STARK, compressed) | 3.6 MB | 895 kvB | ~$1,475 | **no** |
| 188 KiB (Binius64 ECDSA) | 13.8 MB | 3.4 MvB | ~$5,680 | **no, exceeds block size** |

So the practical ceiling on proof size for BitVM3-core as specified is roughly **2 to 5 kB**, and no binary-field or hash-based proof system is anywhere near that. Table 9's own "Yao-Style + STARK" row lists a 50-100 kB proof, which is why that row, despite being the only post-quantum option, is not the one they instantiate.

**This is the actual research problem, and it is the most valuable thing in this document.**

Two ways out:

**(i) Compress the proof.** Recursive wrapping into a small-proof SNARK reintroduces a pairing-based verifier into the garbled circuit, defeating the post-quantum argument and the AND-gate argument simultaneously. Hash-based recursion (WHIR-style, or FRI-Binius with aggressive folding) gets you to tens of kilobytes, not kilobytes. This route is a dead end for the PQ framing unless there is a genuine breakthrough in binary-field proof size.

**(ii) Decouple on-chain cost from proof size entirely.** This is the interesting one, and I think it is the right attack.

The reason the proof goes on-chain at all is the extractability property of the garbled-encoding extractable signature scheme (Section 3.3): the on-chain signature `sigma_GS(pi)` deterministically reveals the garbled encoding `En(e, pi)`, so that **any** challenger, including one who was not talking to the operator, can recover the input labels and evaluate. Extractability is what buys permissionless challenging. That is a genuinely good design, and it is also why on-chain cost is O(P).

But note what BitVM3 *already* assumes: the operator publishes a 41.2 GB garbled circuit off-chain, via a bulletin board or torrent, and challengers must have it to challenge. **The protocol already depends on off-chain data availability of a 41 GB object.** Adding "the operator also publishes the proof and its input labels off-chain" adds no new *class* of assumption, only a new object that is nine orders of magnitude smaller than one already assumed available.

So the sketch is:

1. Assert carries a **constant-size Winternitz commitment** to `H(pi || En(e, pi))`, roughly 32 bytes of committed data instead of P bytes, regardless of proof system.
2. The operator publishes `pi` and the labels off-chain before posting Assert, same channel as the garbled circuit.
3. A challenger who has the data evaluates and, on a false output label, posts the same ~93 vB Disprove as today.
4. A challenger who claims **non-availability** posts a bonded **DA challenge**, which forces on-chain reveal of the full label set within a window, falling back to today's O(P) Assert.
5. Equivocation on the Winternitz commitment (serving different proofs to different challengers) is punishable on-chain in constant size, exactly the `PunishEquiv` mechanism the paper already uses in Section 3.4 for the light client's Lamport keys.

An honest, rational operator always publishes, so path (5) never fires and the expensive path in (4) never fires. The DA challenger's bond bounds griefing. This is structurally the same optimistic-with-escalation pattern BitVM2 already uses for Claim -> Challenge -> Assert, applied one level down.

**If this works, proof size stops mattering, and every hash-based, post-quantum, binary-field proof system becomes viable for BitVM.** That single change is what unlocks Insertion point B.

**What has to be proven:** that soundness survives. The delicate part is that BitVM3-core's soundness theorem (Theorem 7.2) routes through extractability of GS to guarantee that an honest challenger *can always* recover the encoding. Replacing that with a DA assumption plus an escalation path weakens the theorem from unconditional-given-one-honest-challenger to conditional-on-the-escalation-path-being-affordable. Whether that is acceptable is exactly the question a paper here would answer. It might not be. But it is a well-posed question with a clear answer, which is what you want in a research problem.

**Also worth checking first:** BitVM3s (Linus, 2025, reference [31] in the paper) is described as having "reduced dispute footprints from megabytes to tens of kilobytes at the cost of ~80 GB of hint storage," and Duty-Free Bits reduces Argo-style off-chain data to under 1 MB. Read both before assuming the decoupling idea is unclaimed. My searches did not turn up anything doing exactly this, but eprint was not directly fetchable during this research and I could not read those two papers in full.

---

## Part 4: Ranked contribution targets

Ordered by expected value, accounting for effort, novelty, competition, and how much it helps you build standing in this community.

| # | Target | Layer | Effort | Novelty | Competition | Notes |
|---|---|---|---|---|---|---|
| 1 | AND-gate counting harness across candidate verifier circuits | garbling | 2-4 wk | low | none | Precondition for everything else. Immediately useful to the whole field. Falsifies or confirms the Binius thesis cheaply. |
| 2 | Flock/Binius prover for the BitVM header chain | protocol/eng | 3-6 wk | low-med | none | Concrete PR to `header-chain/`. Cheapest path to credibility in this codebase. |
| 3 | Decoupling on-chain cost from proof size (Section 3.3 above) | protocol | 3-6 mo | **high** | unknown | The keystone result. Unlocks PQ BitVM. Needs a real soundness proof. |
| 4 | Post-quantum BitVM3 via binary-field garbled verifier | garbling | 4-8 mo | **high** | none visible | Depends on #1 and ideally #3. The paper worth writing. |
| 5 | BitVM3-core composed with Clementine's payoff rounds | protocol | 2-3 mo | medium | low | Authors explicitly flag it as unclaimed and orthogonal. Two production teams want it. |
| 6 | BitVM under each covenant proposal (CTV / CAT / CSFS / TXHASH) | protocol | 2-3 mo | medium | low | Serves two communities. Timely: CTV min activation ~May 2027. |
| 7 | Data availability mechanism for garbled circuits | garbling/protocol | 2-4 mo | med-high | low | Soundness-relevant gap currently treated as an assumption. Pairs naturally with #3. |
| 8 | Rotating / bonded signer committees | protocol | 3-5 mo | med-high | low | The authors' own "most pressing." Watch the handoff chicken-and-egg. |
| 9 | Common benchmark harness for Bitcoin garbling schemes | garbling | 1-2 mo | low | low | Ecosystem service. Everyone cites the benchmark. |
| 10 | Setup verification / cut-and-choose replacement | garbling | 4+ mo | high | **high** | Alpen (Mosaic) and Fairgate both actively shipping here. Only enter with a specific idea. |

If you want a single recommendation: **do #1 and #2 in parallel over the next month.** #1 tells you whether the Binius thesis is real before you bet months on it, and #2 gets your name on commits in the BitVM repo while you find out.

---

## Part 5: Reading list, in order

**Foundational, already done:**
- BitVM1, BitVM2, BitVM3 (your three PDFs)

**Garbling layer, in dependency order:**
1. Fairgate, "A note on the security of the BitVM3 garbling scheme" ([2025/1291](https://eprint.iacr.org/2025/1291)) — read this before anything else; it is why the published BitVM3 looks the way it does
2. Glock ([2025/1485](https://eprint.iacr.org/2025/1485)) and Argo MAC ([2026/049](https://eprint.iacr.org/2026/049))
3. BABE ([2026/065](https://eprint.iacr.org/2026/065))
4. Duty-Free Bits ([2026/476](https://eprint.iacr.org/2026/476)) + the [Alpen writeup](https://www.alpen.org/blog/duty-free-bits-bitcoin)
5. Mosaic ([2026/812](https://eprint.iacr.org/2026/812)) + the [Alpen writeup](https://www.alpen.org/blog/introducing-mosaic-glocks-final-piece)
6. BitGC: Garbled Circuits with 1 Bit per Gate (EUROCRYPT 2025)

**Binary fields:**
7. Diamond & Posen, "Succinct Arguments over Towers of Binary Fields" ([2023/1784](https://eprint.iacr.org/2023/1784.pdf))
8. [Announcing Binius64](https://www.irreducible.com/posts/announcing-binius64), Irreducible
9. Flock ([arXiv 2607.27491](https://arxiv.org/abs/2607.27491)) + the [Succinct blog post](https://blog.succinct.xyz/introducing-flock/)
10. BinarySpartan ([2026/1656](https://eprint.iacr.org/2026/1656.pdf)), Setty
11. Vitalik's [Binius explainer](https://vitalik.eth.limo/general/2024/04/29/binius.html) for intuition

**Protocol layer:**
12. Clementine ([2025/776](https://eprint.iacr.org/2025/776)) and [6 Months of Clementine](https://www.blog.citrea.xyz/6-months-of-clementine-first-trust-minimized-bitcoin-bridge/)
13. Cardinal ([2025/2196](https://eprint.iacr.org/2025/2196.pdf))
14. [OP_STARK_VERIFY thread](https://delvingbitcoin.org/t/proposal-op-stark-verify-native-stark-proof-verification-in-bitcoin-script/2056) on Delving Bitcoin

**Ongoing:**
15. [Fairgate's "Computing on Bitcoin" newsletter](https://www.fairgate.io/newsletter) — weekly, currently at #102 (Aug 14, 2026), the best single tracker of this space

---

## Caveats on this document

- IACR eprint blocked direct fetching during this research. Claims attributed to Argo, BABE, Duty-Free Bits, Mosaic, BitVM3s, and the Fairgate security note come from secondary sources (project blogs, newsletters, search summaries) and **should be verified against the primary PDFs** before you build on them. The BitVM1/2/3 claims are read directly from the papers you provided and are reliable.
- The cost table in Section 3.3 is my arithmetic extrapolated from the BitVM3 paper's own N=128 figures, assuming the 65-byte-adaptor-signature-per-8-bit-digit encoding scales linearly. It does scale linearly by construction, but the standardness and block-size limits mean the large rows are hypothetical rather than measured.
- The decoupling sketch in Section 3.3(ii) is a hypothesis, not a result. It has not been security-analyzed and there may be an obvious attack I have not seen. Treat it as a direction to attack, not a design to implement.
