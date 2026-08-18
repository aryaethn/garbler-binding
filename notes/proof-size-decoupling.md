# Decoupling on-chain cost from proof size in BitVM3-core

Draft mechanism, August 2026. Notation follows BitVM3 (eprint 2026/933) throughout:
`CheckSig`, `CheckMultiSig`, `AbsTimelock`, `RelTimelock`, `Hashlock`,
`CheckCovenant`, `CheckGS`, `LampVerify`, `PunishEquiv`, `⟨·⟩` for a Taproot
output, `*` for anything irrelevant to the protocol.

Status: this is a proposal to attack, not a result. Section 6 states the one
property everything reduces to, and Section 7 gives a variant that avoids
needing it.

---

## 1. The problem, stated precisely

BitVM3-core's on-chain cost is `O(P)` where `P = |π|` (Table 1). The constant
comes from Section 8.1: the proof is split into `N = |π|` digits of 8 bits, and
the witness carries one 65-byte Schnorr adaptor signature per digit under a
single key with `OP_CODESEPARATOR` between successive `OP_CHECKSIGVERIFY`
operations.

Reading the paper's own figures back out:

```
|s|   = 33 + 3(N-1) + 1          leaf script
S_w   = varint(N+2) + 66N + varint(|s|) + |s| + 34
W     = 4B + S_w,  B = 137
```

which gives, at 2 sat/vB and the paper's own dollar calibration:

| proof size | Assert vsize | cost | standard? |
|---|---:|---:|:--:|
| 128 B (Groth16) | 2,362 vB | $3.89 | yes |
| 1 kB | 17,818 vB | $29.37 | yes |
| 5 kB | 88,474 vB | $145.85 | marginal (100 kvB limit) |
| 50 kB | 883,354 vB | $1,456 | **no** |
| 100 kB | 1,766,554 vB | $2,912 | **no, exceeds block weight** |

So the practical ceiling on proof size is about 5 kB. Every hash-based,
post-quantum-secure proof system is 10x to 60x past it. This is why Table 9's
`Yao-Style + STARK` row, the only post-quantum row in the paper, is not the one
instantiated.

**Reason to care, beyond BitVM3.** Companion measurement (`results/census.json`)
puts our best realistic Boolean-garbled hash-based verifier at 6.0 GB off-chain
against Argo/BABE's ~22-25 MB, a 246x gap. Arithmetic garbling wins on size and
always will, because it exploits elliptic-curve and pairing structure. That same
structure is what a quantum adversary breaks: every arithmetic-garbling row in
Table 9 is marked post-quantum "no", and Yao-style Boolean garbling, which needs
only a PRF, is the only "yes". Small and post-quantum are currently mutually
exclusive. The post-quantum branch is gated on the wall above, so this document
is the gate.

## 2. What the current design buys with that cost

The `O(P)` witness is not waste. It purchases *extractability* of the
garbled-encoding extractable signature scheme GS (Section 3.3):

> a valid signature on a message `x` deterministically reveals the
> garbled-circuit encoding `En(e, x)`

Because `σ_GS` is on-chain, **any** party, including one who never spoke to the
operator, can recover `L_π = En(e, π)` and evaluate `GC` locally. That is what
makes challenging permissionless, and permissionless challenging is BitVM2's
headline improvement over BitVM1 that BitVM3 inherits. Any redesign has to
preserve it or say plainly what it gives up.

The encoding information `e` must stay secret to the prover. If `e` were public,
any evaluator would hold both labels on every wire and could forge any output,
destroying authenticity. So challengers genuinely cannot compute `L_π`
themselves, and the labels must come from `P`.

## 3. The observation the design rests on

BitVM3-core **already** assumes off-chain availability of a 41.2 GB object.
Section 4.1: the prover "shares the garbled circuit `GC`, the decoding
information `d`, `pk_GS`, and the Assert transaction body with the challengers
or makes them publicly available e.g., via a bulletin board", with torrents
mentioned in the evaluation.

Soundness therefore already depends on an honest challenger *who has the garbled
circuit*. Adding "and who also has `(π, L_π)`", an object nine orders of
magnitude smaller, introduces no new class of assumption. What it introduces is
a new *failure mode*: a prover who withholds. The mechanism below handles that
with escalation rather than by putting the data on-chain unconditionally.

## 4. Construction: BitVM3-core-D

Two transactions replace `Assert`, and one is added.

### 4.1 Setup changes

Unchanged from BitVM3-core, plus:

- `P` samples a Winternitz/one-time key pair `(pk_δ, sk_δ)` used to bind a
  single 256-bit digest.
- The signer committee pre-signs **both** `Withdraw_lite` and `Withdraw_full`
  under `SIGHASH_ALL`, binding each to its respective Assert. This is the same
  covenant emulation as Section 3.5; the only change is that there are two
  authorized exit transactions instead of one, selected by which Assert path was
  taken.
- `Δ` is the existing dispute window. `Δ_E` is a new, shorter escalation window
  with `Δ_E < Δ`.

### 4.2 `Assert_lite`

`P` publishes `(π, L_π)` on the same channel as `GC`, then posts:

| | `Assert_lite` Transaction |
|---|---|
| Inputs | (0) `(*, *, CheckGS_{pk_δ})` |
| Outputs | (0) `(d BTC, ⟨Hashlock(H(L*)), RelTimelock(Δ) ∧ CheckSig_{pk_O}, PunishEquiv_δ⟩)` |
| | (1) `(0 BTC, ⟨CheckSig_{pk_O} ∧ RelTimelock(Δ_E), EscalateScript⟩)` |
| Witness | (0) `*, σ_δ` |

where `σ_δ` is a GS signature on the digest

```
δ  =  H( φ ‖ π ‖ L_π )
```

carried by `N' = 32` adaptor-signature digits rather than `N = |π|`.

Output (1) is a zero-value **escalation connector**. `Withdraw_lite` consumes
both outputs, so if anyone spends output (1) via `EscalateScript`, the happy
path dies. Same connector-output technique as Section 4.3 of BitVM2.

**Size: 706 vB, 1,412 sat, about $1.16, independent of `|π|`.** Against $3.89
today for a 128-byte Groth16 proof, and against $2,912-and-unminable for a
100 kB proof.

### 4.3 `Disprove` (unchanged)

| | `Disprove` Transaction |
|---|---|
| Inputs | (0) `(Assert_lite, 0, Hashlock(H(L*)))` |
| Outputs | (0) `(* BTC, True)` |
| Witness | (0) `L*` |

Still roughly 93 vB, under $0.20. A challenger who received `(π, L_π)` and whose
local evaluation decodes to `False` takes this path and never touches the
escalation machinery.

### 4.4 `Escalate`

Posted by any challenger who did **not** obtain data sufficient to evaluate.
Requires a bond `c ≥ fee(Assert_full)`, crowdfundable via
`SIGHASH_SINGLE|ANYONECANPAY` exactly as in BitVM2 Section 5.4.

| | `Escalate` Transaction |
|---|---|
| Inputs | (0) `(Assert_lite, 1, EscalateScript)` |
| | (1) `(*, *, *)` funding the bond `c` |
| Outputs | (0) `(c BTC, ⟨CheckCovenant⟩)` connector enabling `Assert_full` |
| Witness | (0) `Covenant`, (1) `*` |

### 4.5 `Assert_full`

`P`'s only route to the reserve once escalated. Identical to BitVM3-core's
original `Assert` except that it is bound to the same one-time key `pk_δ`, and
it is chunked when `|π|` demands it.

| | `Assert_full` Transaction (chunk `j` of `k`) |
|---|---|
| Inputs | (0) `(Escalate, 0, CheckCovenant)` for `j=1`, else `(Assert_full_{j-1}, 0, CheckCovenant)` |
| Outputs | (0) `(d + c BTC, ⟨Hashlock(H(L*)), RelTimelock(Δ) ∧ CheckSig_{pk_O}, PunishEquiv_δ⟩)` |
| Witness | (0) `*, σ_GS, σ_δ` |

The witness carries the full `N = |π|` adaptor signatures, restoring
extractability, plus a signature `σ_δ` under the **same** one-time key `pk_δ` on
the digest. Because `pk_δ` is one-time, two signatures on distinct digests
constitute an equivocation witness spendable by anyone through `PunishEquiv_δ`.
This is the mechanism the paper already uses in Section 3.4 and Table 8 to bind
`σ^C_{H,i}` and `σ^A_{H,i}` across `Assert_{i,j}`; nothing new is invented here.
`P` is therefore pinned to the `(φ, π, L_π)` committed in `Assert_lite`.

Chunking is BitVM2's construction, unchanged. At 100 kvB per chunk: 1 chunk up
to 5 kB of proof, 9 chunks at 50 kB, 18 chunks at 100 kB.

### 4.6 Exits

| | `Withdraw_lite` |
|---|---|
| Inputs | (0) `(Deposit, 0, CheckCovenant)` |
| | (1) `(Assert_lite, 0, RelTimelock(Δ) ∧ CheckSig_{pk_O})` |
| | (2) `(Assert_lite, 1, RelTimelock(Δ_E) ∧ CheckSig_{pk_O})` |
| Outputs | (0) `(u BTC, CheckSig_{pk_O})` |
| Witness | (0) `Covenant`, (1) `σ_O`, (2) `σ_O` |

Input (2) is the point: if `Escalate` consumed `Assert_lite` output (1), this
transaction is permanently invalid. `Withdraw_full` is identical with
`(Assert_full_k, 0, ...)` in place of inputs (1) and (2), and returns the bond
`c` to `P`.

## 5. Honest-challenger decision rule

The rule is the protocol. A verifier `V` holding `GC`, `d`, and the digest `δ`
read off `Assert_lite`:

1. Did `V` receive `(π', L')` with `H(φ ‖ π' ‖ L') = δ`? If not, **`Escalate`**.
2. Compute `De(d, Ev(GC, L'))`.
   - `False` → **`Disprove`** with the recovered `L*`. Cheap path, $0.20.
   - `True` → **do nothing**. `P` withdraws after `Δ`.
   - **neither** (garbage label) → **`Escalate`**.

Case 2c is the one worth naming. The escalation path is not only about data
*availability*, it is also about label *well-formedness*. Calling it a "DA
challenge" would be a misnomer and would hide the real work it does.

## 6. The hole, and the property everything reduces to

Here is what breaks if you are not careful, and it is the reason this document
exists rather than a patch.

Moving `σ_GS` off-chain removes the guarantee that `L_π` is a well-formed
encoding. `V` checking `H(φ ‖ π' ‖ L') = δ` learns only that `P` committed to
*some* pair. It does **not** learn `L' = En(e, π')`, because `V` does not hold
`e`.

Half the worry is unfounded. Suppose `P` supplies `L' = En(e, x)` for some input
`x ≠ π'` and evaluation decodes to `True`. Then `Vrfy(φ, x) = True`, so `x` is
itself a valid proof, and by knowledge soundness of the SNARK, `φ` is true and
`P` knows a witness. Cheating this way is not cheating.

The remaining worry is real. Can `P`, **who holds `e`**, produce a label vector
`L'` that is not the encoding of any input yet still satisfies
`De(d, Ev(GC, L')) = True`? Standard garbling security does not rule this out.
Correctness, authenticity and privacy (Section 3.2) are all stated against
adversaries who do **not** hold `e`; here the adversary is the garbler.

**Why cut-and-choose does not already solve this.** It is tempting to answer
"cut-and-choose handles malicious garblers, so we are covered." It does not
cover this. Mosaic states the malicious-prover threat it defends against
precisely: "A malicious `P` could produce an incorrect garbled circuit that
always evaluates to true, preventing `V` from recovering `s*` even for an
invalid witness," and cut-and-choose answers it by opening a random subset and
checking the *tables*. That gives **circuit correctness**: `GC` is a correct
garbling of `F` with respect to `e` and `d`.

Label well-formedness is a separate guarantee, and in every existing design it
comes from somewhere else entirely: the on-chain reveal. Mosaic again, plainly:
"The data `P` must publish on chain to authorize her transaction can be arranged
to simultaneously serve as the garbled circuit input labels. There is therefore
an exact correspondence between the witness `P` commits to on chain and the
input on which `V` evaluates the garbled circuit."

So the division of labour in the current literature is:

| guarantee | supplied by |
|---|---|
| `GC` is a correct garbling of `F` | cut-and-choose (Mosaic, Glock) |
| `L` is a well-formed encoding under `e` | the on-chain reveal (GS extractability) |

BitVM3-core-D keeps the first and removes the second. Garbler-binding is exactly
the property that would replace it. Cut-and-choose is necessary here but not
sufficient, and the two are composable rather than redundant.

**The objection to be ready for, and the answer.** Chen's SoK (2025/1253,
Section 7.1) rejects both authenticated garbling and dual-execution for BitVM
with an argument that lands very close to this design:

> "The operator can simply generate a garbled circuit that is faulty and always
> outputs 1... This would prevent the challenger from being able to challenge
> the proof even when the proof is invalid, as the output would differ and the
> computation will abort. [...] **security with abort does not protect against a
> garbler who intentionally wants to fail all garbled circuits.**"

A reviewer will point at case 2c of Section 5, the inconclusive evaluation, and
say this is the same failure. It is the same *behaviour* and a different
*outcome*, and the difference is structural rather than rhetorical. In the 2PC
settings the SoK is discussing, an abort is neutral: the protocol stops and
nobody is worse off, which is precisely why a garbler who wants to fail can do
so for free. Here, abort is a loss. A prover who makes evaluation inconclusive
triggers escalation, escalation spends the connector on `Assert_lite` output
(1), `Withdraw_lite` becomes permanently invalid, and the prover's only
remaining route to the reserve is `Assert_full`, which restores extractability
and gets them disproven. Failing to respond forfeits the reserve outright.

So the SoK's objection is correct and does not apply, because BitVM supplies
something 2PC does not: a pre-signed transaction graph in which refusing to
proceed is itself punishable. Say this explicitly and early, because the
objection is the first one a reader from the MPC side will raise.

So BitVM3-core-D, in the form above, reduces to a property the literature does
not supply:

> **Definition (Garbler-Binding).** A garbling scheme `G = (Gb, En, Ev, De)` is
> *garbler-binding* for a circuit `F` if for every PPT adversary `A` given
> `(GC, e, d) ← Gb(1^κ, F)`, the probability that `A` outputs `L` with
> `De(d, Ev(GC, L)) = True` and no `x` satisfying both `F(x) = True` and
> `L = En(e, x)` is negligible.

Intuition for why Yao half-gates might satisfy it: with a circular
correlation-robust hash, evaluating on labels outside the encoding space
produces outputs that look random, so landing on the `True` output label
requires either honest evaluation or inverting `H`. Knowing `e` does not
obviously help invert `H`. That is an argument, not a proof, and the reduction
has to be done properly against the concrete half-gates construction.

**This is the single highest-value thing to attack in this document.** Either it
holds, and BitVM3-core-D is a clean result, or it fails, and the counterexample
is itself worth writing up because it says something about what garbling schemes
do and do not guarantee against their own garbler.

> **STATUS UPDATE (attack completed).** Section 6 has been attacked and does not
> survive. See `garbler-binding-attack.md` for the full write-up. Summary: the
> property fails four independent ways, and the cheapest repair doubles the
> label length to `k = 256`, taking the garbled circuit from 40.5 GB to 81 GB in
> exchange for benefits that Variant B already obtains economically.
> **Variant A is withdrawn. Section 7 is the construction.**
>
> Two findings from that attack must be carried into Variant B regardless:
> (i) `De` must be the authenticity-style variant with committed output labels,
> since ZRE15's native `De(d,Y) = d ⊕ lsb(Y)` never returns ⊥; and
> (ii) BitVM3-core publishes `H(L*)` but not `H(Z^True)`, so off-chain success
> is unverifiable. Both are cheap, and neither is in the paper.

## 7. Variant B: the version that needs no new assumption

If garbler-binding turns out to be false, hard, or merely unproven, weaken the
decision rule in Section 5 to:

> `Disprove` on `False`. **`Escalate` on anything other than `False`, including
> `True`.**

Now soundness never rests on the off-chain labels. Any honest verifier who
cannot produce a `Disprove` escalates, and escalation restores full GS
extractability on-chain, at which point the original BitVM3-core soundness
theorem (Theorem 7.2) applies verbatim to `Assert_full`.

The cost of Variant B is that an honest prover is escalated on **every**
peg-out, since honest evaluation decodes to `True`. That sounds fatal but is
not, if you invert who pays: make `Escalate` require the bond `c`, and refund
`c` to `P` through `Withdraw_full`. A challenger who escalates against an honest
prover simply loses `c`. So in equilibrium nobody escalates against an honest
prover, and the honest path is `Assert_lite` at $1.16.

Variant B's real cost is a worst-case, not an average-case:

| | Variant A (needs garbler-binding) | Variant B (no new assumption) |
|---|---|---|
| honest path, any `\|π\|` | $1.16 | $1.16 |
| fraud, data available | $1.16 + $0.20 | $1.16 + $0.20 |
| fraud, data withheld | escalation | escalation |
| worst case `\|π\|` = 128 B | $3.89 | $3.89 |
| worst case `\|π\|` = 100 kB | $2,912, 18 chunks | $2,912, 18 chunks |

and the worst case is paid **only by a prover who is about to lose their
deposit**. Size the deposit `d ≥ fee(Assert_full) + c` and the escalation is
self-financing. For a 100 kB proof that is a ~$3k bond, against BitVM2's
$16,000 worst-case dispute that operators already tolerate.

**Variant B is the one to write down first.** It is a strict improvement over
BitVM3-core with no new cryptographic assumption: constant honest-case on-chain
cost, unchanged worst case, and hash-based proof systems become deployable for
the first time. Variant A is the optimization you reach for afterwards, and its
whole value is removing the escalation round-trip.

## 8. What changes in the security analysis

Relative to Section 7 of the paper:

**Completeness (cf. Theorem 7.1).** Honest `P` publishes `(π, L_π)` and posts
`Assert_lite`. If nobody escalates, `P` spends output (0) via `RelTimelock(Δ)`.
If someone escalates, `P` posts `Assert_full`; by correctness of the garbling
scheme evaluation decodes to `True`, by authenticity no challenger obtains `L*`,
and `P` spends after `Δ`, recovering `c`. Requires `Δ_E < Δ` so the escalation
window closes before the dispute window, and requires the committee to have
pre-signed `Withdraw_full`.

**Soundness (cf. Theorem 7.2).** Malicious `P` posts `Assert_lite` binding `δ`
under one-time key `pk_δ`. Let `V` be honest and capitalized with `c`.

- `V` holds matching data, evaluation decodes `False` → `Disprove`. Done.
- `V` holds no matching data, or evaluation is inconclusive → `Escalate`. `P`
  must post `Assert_full` bound to the same `δ` or forfeit, because
  `Withdraw_lite` is dead. On `Assert_full`, GS extractability holds and
  Theorem 7.2 applies unchanged.
- `P` serves different `(π, L)` to different challengers → at most one matches
  the single on-chain `δ`; every other challenger detects the mismatch by
  hashing and escalates. No equivocation branch is needed for this case.
- `P` signs two distinct digests under `pk_δ` across `Assert_lite` and
  `Assert_full` → `PunishEquiv_δ` is spendable by anyone.
- Variant A additionally requires garbler-binding for the `True` case. Variant B
  does not.

**The assumption that actually changes.** BitVM3-core requires "at least one
verifier is honest". BitVM3-core-D requires **at least one verifier who is
honest and capitalized with `c`**. That is a real weakening and must be stated
as such, not buried. Mitigations, in the order I would present them: `c` is
refunded when the challenge is justified; crowdfunding amortizes `c` across many
challengers exactly as in BitVM2 Section 5.4; and users exiting the bridge are
naturally motivated challengers with capital already at stake.

## 9. Open problems, ranked

1. **Is Yao half-gates garbler-binding?** Section 6. Everything about Variant A
   hangs on it. Prove it against the concrete construction, or find the
   counterexample.
2. **Sampled escalation.** Escalation currently reveals all `N` labels. Since
   escalation is about availability and well-formedness, a challenger-selected
   random subset verified against a Merkle root inside `δ` should suffice, which
   would cut the worst case from `O(P)` to `O(√P)` or `O(log P)`. The obstacle
   is the classic data-availability sampling problem: a prover withholding 1% of
   labels passes sampling but still blocks evaluation. The standard answer is
   erasure coding, and adapting it to garbled input labels is not obviously
   sound. Worth a section, probably worth a paper.
3. **Compose with Mosaic.** Cut-and-choose keeps 7 of 181 garbled instances
   (Section 4.2). Mosaic already makes the on-chain footprint independent of the
   number of retained copies `ℓ` via polynomial label correlation; this document
   makes it independent of `|π|`. The two axes are orthogonal (see Section 10.3)
   and the composition looks direct, since the single share-per-input-wire that
   Mosaic reveals on-chain is exactly the object deferred here. Confirm that `δ`
   binds correctly across instances without reintroducing a factor of `ℓ`.
4. **Fee-rate risk.** The escalation path's cost is denominated in future
   blockspace. A prover who commits fraud during a fee spike may face an
   escalation that exceeds their bond. Deposit sizing needs a fee-rate model,
   not a point estimate.
5. **Does this compose with arithmetic garbling?** Argo and BABE have small
   proofs, so `O(P)` does not bind for them and they gain little. But if any
   future arithmetic scheme wants a large proof, the same mechanism applies.

## 10. Reconciliation with prior art

Papers read: Duty-Free Bits (2026/476), Mosaic (2026/812), Fairgate's note on
the BitVM3 garbling scheme (2025/1291). Result: **nobody does this, and two
independent 2026 papers treat the constraint it removes as an axiom.**

### 10.1 The constraint is universal and unquestioned

Duty-Free Bits, Section 1.2:

> "A crucial constraint of this setting is that E's garbled circuit input must
> be authenticated on-chain via Lamport signatures. In a Lamport signature on a
> field element `x ∈ F_p`, E reveals, for each bit `x_j` of `x`, one of two
> λ-bit preimages `L_{j,0}` or `L_{j,1}`. This coincides exactly with a
> projective input encoding: the revealed preimages serve simultaneously as the
> Lamport signature on-chain and as the garbled input labels off-chain.
> **Projectivity is therefore not merely convenient, it is mandated by the
> on-chain authentication mechanism.**"

Mosaic, Section 1:

> "To evaluate the garbled circuit and recover the secret, the verifier needs
> the prover's input labels, **which the prover must post on chain.** Since
> Bitcoin charges permanently for block space, minimizing this on-chain
> footprint is a primary design concern."

Both papers then do heroic work *around* the constraint. Neither questions it.
That is the lane.

### 10.2 Second-order consequence: projectivity becomes optional

This is bigger than the fee saving and I did not see it before reading
Duty-Free Bits.

The entire projectivity problem exists **only because** the labels must be
revealed bit-by-bit on-chain. IT-GSs are not projective: they encode the
evaluator's input as field elements via an affine map, not as a per-bit
selection. BABE and Argo both had to bit-decompose, paying an `lg p` blow-up
(BABE's scalar-multiplication encoding goes from under 95 KiB to 22.16 MiB, a
~240x increase that Duty-Free Bits' own introduction calls out as "due
primarily to their application requiring projectivity"). Duty-Free Bits then
reduces that penalty to additive, landing at ~500 KiB for BABE's Embryo and
~355 KiB for Argo MAC.

If the on-chain commitment no longer touches the labels, **the requirement that
motivates all of this disappears**, and an IT-GS can be used in its native
non-projective form: under 95 KiB rather than 500 KiB, a further ~5x, obtained
by deleting machinery rather than adding it.

I want to be careful about how strongly to claim this. Duty-Free Bits has
already made projectivization cheap, so removing the requirement is now an
incremental win on that axis rather than a 240x one. But "we make an entire
line of technical work unnecessary for this application" is a strong framing if
it survives scrutiny, and it is worth checking properly against Section 5.2 of
their paper before asserting it.

### 10.3 Mosaic is orthogonal and composes

Mosaic reduces the on-chain footprint so it is "independent of the number of
garbled copies `ℓ`", via polynomial label correlation (from Eagen's Glock):
labels across all `N` cut-and-choose copies are evaluations of a degree-`t`
polynomial, the `t` shares opened during cut-and-choose fall one short of the
reconstruction threshold, and the on-chain adaptor signature reveals the
missing share as a byproduct, letting the evaluator interpolate the rest.

So Mosaic makes on-chain cost independent of `ℓ`; BitVM3-core-D makes it
independent of `|π|`. Different axes of the same product. They should compose
directly: Mosaic's single-share-per-input-wire reveal is exactly the object
that Section 4 defers off-chain. Open problem 3 in Section 9 should be
rewritten as "compose with Mosaic" rather than "check against Mosaic".

One Mosaic argument to be ready for. They dismiss authenticated garbling on
timing grounds: its MAC checks fire "during (or after) evaluation... by the
time authenticated garbling could flag incorrect garbling, it is too late for V
to decline participation." A reviewer may reach for the same objection here,
since escalation also fires late. The answer is that the objection is about the
*participation* decision (before funds are locked, where cut-and-choose is the
right tool), whereas escalation lives inside the dispute window (after funds
are locked, where late detection is the entire design). Say so explicitly.

### 10.4 BitVM3s: not what I feared, and probably broken

`https://bitvm.org/bitvm3.pdf` now serves the published paper, not the July 2025
manuscript, so I could not read BitVM3s directly. But the Fairgate note pins
down what it was: `[Lin25]` "BitVM3: Efficient Computation on Bitcoin",
`https://bitvm.org/bitvm3-rsa.pdf`, the **RSA-based** garbling scheme. Its "tens
of kilobytes" dispute footprint came from arithmetic garbling in `Z_N`, not from
any decoupling of on-chain cost from proof size, and its ~80 GB of hint storage
is the tell. Different mechanism, different axis.

It is also broken. Fairgate's counterexample is a two-AND-gate, three-input
circuit; the attack needs only fan-out greater than one on a single wire, and
their Remark 4 says "most non-trivial circuits will suffer from many similar
exponent collisions. Trying to transform the topology to avoid this type of
attack is not possible." Liam Eagen found a related attack independently.

Worth noting for the write-up: Table 9 of the published BitVM3 paper still
carries a `BitVM3s + Groth16` row. Whether a comparison table should include a
scheme with a published break is a fair question to raise, politely.

### 10.5 Why the Fairgate break does not falsify garbler-binding, and why that
### is not reassuring

Their attack is an **evaluator**-side authenticity break: an evaluator holding
`a_0, b_0, c_0` and the public adaptors recovers `b_1` by exploiting that the
public exponents are coprime, so extended Euclid yields `x` from `x^a` and
`x^b`. It needs the multiplicative structure of `Z_N`, which Yao half-gates with
a CCR hash simply does not have. So it does not transfer to the setting of
Section 6.

But the shape of the failure should lower your prior. In both cases the claim is
"a party cannot produce labels it should not be able to produce", the intuition
was that some structure made it hard, and the structure turned out to be
exploitable in a circuit with two AND gates. Do not ship garbler-binding as a
conjecture with a paragraph of intuition. Either reduce it to circular
correlation robustness against the concrete half-gates construction, or lead
with Variant B, which needs none of it.

Encouraging data point: Duty-Free Bits proves its scheme secure "assuming a
circular-correlation robust hash function (CCRH)", which is exactly the
assumption family a garbler-binding proof would target. The tools are sitting
right there.

### 10.6 Still to read

- **BitVM3s / the RSA manuscript**: `https://bitvm.org/bitvm3-rsa.pdf`, or the
  Internet Archive copy at `https://tinyurl.com/bitvm3-rsa`. Low priority now,
  but worth confirming 10.4.
- **Glock** (2025/1485), since Mosaic credits it with introducing both the
  polynomial label correlation and the switch from Lamport to Schnorr adaptor
  signatures as the on-chain authentication mechanism. The adaptor-signature GS
  that BitVM3-core uses traces to here, so this is where to check whether
  anything about the reveal can be made sublinear.
- **Chen, "systematization of knowledge organizing the design space"**, cited as
  [12] in Mosaic. A SoK already exists in this space. That matters for the
  fallback plan discussed separately: the SoK lane is partly occupied, so any
  systematization would need to be the *measured* one, not the organizing one.
- **Argo MAC** (2026/049) and **BABE** (2026/065), to confirm the 10.2 claim
  about non-projective encoding sizes from the primary sources rather than from
  Duty-Free Bits' summary of them.

---

## 11. Glock and the SoK

Read after the first revision. Both change what the contribution should be
called, and one of them supplies the best argument for it.

### 11.1 Glock names the coincidence as a happy accident

Eagen, Glock (2025/1485), Section 1.3:

> "**In an auspicious harmony**, the mechanism GCs use to authenticate inputs
> and outputs composes perfectly with the mechanism that BitVM already uses to
> efficiently authenticate on bitcoin: Lamport or more generally 'projective'
> signatures."

He then makes the identification literal. A projective signature satisfies
`Sign(sk, w ∈ F_2^n) = (Sign(sk_i, w_i))_{i∈[n]}`, and he sets

```
ℓ_i^(b) = Sign(sk_i, b)        o_i^(b) = Sign(sk'_i, b)
```

so that `[w]_ℓ = Sign(sk, w)`. **The input labels are not merely revealed
on-chain; they are defined to be the signature shares.**

That reframes this whole document. BitVM3-core inherits the fusion through
adaptor signatures. Duty-Free Bits exists to make arithmetic garbling fit it.
Mosaic exists to keep its cost independent of the number of cut-and-choose
copies. Three papers, all managing consequences of one identification.

The contribution here is best described as **unfusing them**: let the labels go
back to being ordinary garbling labels, and bind them with a separate,
constant-size on-chain commitment. That is a cleaner statement than "make the
Assert smaller," and it explains why the cost is what it is. Fusing buys
extractability for free; unfusing means paying for it another way, which is
exactly what Section 6 is about. The design and its cost are the same fact.

### 11.2 Glock already states the property Section 6 needs

Section 1.3, on the security goal:

> "If the protocol is secure, then E should learn `[m]_o` **if and only if** G
> authenticated some `w` under `ℓ` such that `C(w) = m`."

The `⟸` direction is standard. The `⟹` direction, that learning the output
label implies the garbler authenticated a real input, **is garbler-binding**. So
the property is not novel to this document; it is already the stated security
goal of the Glock abstraction, just discharged in every existing construction by
the on-chain reveal rather than proven about the garbling scheme. That is good
news for framing: this is not a new assumption pulled from nowhere, it is an
existing requirement being asked to stand on its own.

### 11.3 "Why not just widen the wires?" has a quantitative answer

The obvious objection to this whole document is that the on-chain cost is
already sublinear in the naive sense: Glock notes his scheme "naturally
generalizes to larger alphabets **at no additional on-chain cost**", and BitVM3
uses exactly this, spending one 65-byte adaptor signature per 8-bit digit rather
than per bit.

So why not 16-bit or 32-bit wires and be done? Because the tradeoff has a knee.
For alphabet size `q` and an `n`-bit input:

| | on-chain signatures | off-chain labels |
|---|---:|---:|
| `q = 2` | `n` | `2n` |
| `q = 256` (BitVM3) | `n/8` | `32n` |
| `q = 2^16` | `n/16` | `4096n` |
| `q = 2^32` | `n/32` | `2^27 n` |

Going from 8-bit to 16-bit wires halves the on-chain cost and multiplies the
off-chain encoding by 128. For a 128-byte Groth16 proof that is roughly 512 KB
of label material at `q=256` and roughly 67 MB at `q=2^16`. BitVM3 is already
sitting at the knee. Widening further is not a path, which is why the on-chain
cost has to be attacked structurally rather than parametrically.

### 11.4 The field has already declared this cost optimal once, and was wrong

Chen's SoK, Section 1:

> "Jeremy Rubin showed in Delbrag that by using Yao's garbled circuits, one can
> reduce the on-chain cost of BitVM to be independent of the computation, but
> roughly 60 bytes per input bit (using RIPEMD-160). The on-chain cost becomes
> very manageable, and **this result is likely optimal and cannot be further
> improved.**"

Sixty bytes per input *bit*. BitVM3-core spends 65 bytes per input *byte*. The
"likely optimal" figure was beaten roughly eightfold within months, by Glock's
larger-alphabet adaptor signatures. No lower bound was ever argued; the claim
was an intuition about a design paradigm, and the paradigm moved.

This is the single best sentence to cite when proposing to break the bound
again, and it should be cited generously rather than scored off. The SoK is
careful, it says "likely", and its point stands *within* the fuse-the-labels
paradigm. The claim here is that the paradigm is the assumption.

### 11.5 Corroboration and useful numbers

- **Third independent confirmation of the census anchor.** The SoK, Section 1.1:
  "An estimate of the Boolean circuit for Groth16 verifier on BN-254, Citrea, is
  `2.7 × 10^9` AND gates. Using the most efficient PFGC [ZRE15] in Minicrypt,
  each GC is about 40 GB." That matches our measured 2,715,041,234 non-free
  gates and 40.46 GiB exactly, from a third source.
- **Cut-and-choose multiplier, stated concretely.** "If we use C&C and manage to
  require only 4 copies, each GC requires 160 GB to be transferred and stored."
- **Real mainnet cost data, better than the $16,000 estimate.** Babylon's June
  2025 Bitcoin mainnet experiment, via the SoK: happy path **$52.49**, correct
  but challenged **$4,162.55**, incorrect and challenged **$15,742.55**. Cite
  the measurement, not the estimate.
- **Privacy-free garbling is the right primitive.** The SoK is explicit that all
  GCs in this setting are privacy-free (PFGC): "the evaluator knows all the
  input bits." Useful for Section 6, since it means privacy is not among the
  properties at risk; only authenticity is.
- **Succinct and reusable PFGC exist on paper.** HMAC-based PFGC gives
  communication `O(|in|)` rather than `O(|C|)`; AB-LFE gives reusable PFGC with
  garbler compute `O(|in|)` too. Both are "at most nearly practical" per the
  SoK, but note the direction: those reduce off-chain cost to a function of
  *input size*, which makes the on-chain input reveal an even larger share of
  the total. The case for attacking it gets stronger, not weaker.

### 11.6 Fiamma: closest prior art, and what it actually was

Chen's SoK cites [Fia24] for the claim that "if these data can be published
elsewhere for data availability, the cost can be significantly reduced." That is
the nearest thing to this document's core move, and it predates everything else
here by a year, so it needed checking.

The citation resolves to a five-post thread by Fiamma (the account has since
rebranded to `@onRide_`; the same org is backed by L2 Iterative, Chen's
affiliation), 27 August 2024. What they reported:

> "Today, we executed three transactions for a complete BitVM2 slashing process
> on the Signet (Bitcoin testnet) to verify a Groth16 ZK proof. The total
> transaction cost was $4.66 (7,508 sats) with a size of 1.5k virtual bytes."

| transaction | vB | sat | $ |
|---|---:|---:|---:|
| Challenge | 250.00 | 1,250.00 | 0.78 |
| Assert | 331.25 | 1,656.25 | 1.03 |
| Dispute | 920.25 | 4,601.25 | 2.86 |
| **Total** | **1,501.50** | **7,507.50** | **4.66** |

at 5 sat/vB and BTC at $62,095. Their description of the middle transaction:

> "Assert tx: The staker deposits funds into a Taproot address created by all 977
> fragmented scripts of the Groth16 Verifier."

**Read those numbers against stock BitVM2 and something is missing.** In BitVM2,
Assert's *witness* carries the operator's Winternitz commitments to every
intermediate state `z_0 ... z_k`; that is the multi-megabyte object, and it is
what drives the $16,000 worst case. An Assert of 331 vB does not contain it.
Likewise a Dispute of 920 vB cannot contain the re-execution of a Groth16
sub-program: 977 fragments of a roughly 1 GB verifier are about 1 MB each, so
revealing one leaf should cost hundreds of kvB, not 920 vB. Note also that
committing to 977 scripts is cheap *by construction*, since a Taproot address is
a 32-byte Merkle root regardless of how many leaves hang off it; that part was
never the expensive part.

So either the demo ran on a drastically reduced circuit, or the commitments and
the disputed script were not on-chain. The SoK reads it as the latter, and the
SoK's author shares an affiliation with the org that published it, so that
reading deserves weight.

**Why this is probably still a different result.** Even granting the strongest
reading, the object Fiamma moved off-chain is BitVM2's Winternitz commitments to
intermediate states. Those are what a challenger *reads* in order to locate the
faulty chunk. The object moved off-chain here is the garbled input encoding,
which is what a challenger *needs in order to evaluate at all*. The soundness
arguments are not analogous: a missing intermediate state leaves the challenger
able to force the operator to reveal it through the existing bisection game,
whereas a missing label set leaves the challenger unable to produce any fraud
proof, which is exactly why Sections 5 through 7 exist. Different object,
different failure mode, different fix.

**Verdict, after reading the spec.** "BitVM2 Specification: Verify ZKP on Bitcoin
with Fraud Proof", Fiamma, August 2024. Fiamma is prior art for the *motivation*
and not for the *mechanism*, and the difference is exactly the thing this
document is about.

Their key metrics confirm the scale: script size 2.38 GB, 977 subscripts,
average 2.44 MB each, Winternitz signatures, BLAKE3. So a real Dispute revealing
one leaf is hundreds of kvB, not the 920 vB they measured. The spec explains
why, in the protocol description:

> "S provides ZKP verification services on the Fiamma chain and **stores inputs,
> outputs, and all intermediate values on the PoS chain, along with the
> Winternitz signature for these values.**"

and, under future work:

> "On-chain Cost for Challenge Process: **Since there is no need to store data
> and commitments on Bitcoin**, efforts should continue to minimize the size of
> all subscripts to reduce challenge costs."

**Their answer to withholding is an external proof-of-stake chain.** The data
lives on the Fiamma PoS chain; the proof state reaches "soft finality" once
secured by that network and "hard finality" after a confirmation threshold;
"intersubjective nodes" monitor the PoS chain and are "required to stake assets
on Fiamma or Bitcoin to prevent outages or malicious behavior". There is no
Bitcoin-enforced fallback if the data is withheld. The spec is candid about what
that costs, listing under "To be Improved and Completed":

> "Security: The protocol is secure provided that **neither S nor C act
> maliciously at the same time**."

That is a two-party non-collusion assumption plus an external consensus system
with its own validator set, in place of BitVM2's existential honesty.

Two further points that matter when citing this:

- The $4.66 figure should not be quoted as the cost of a BitVM2 dispute. The
  same section lists "Winternitz Signature: We will complete the integration of
  the Winternitz signature in the next phase." The demo exercised the
  transaction flow, not a full-fidelity dispute.
- The object is still different. Fiamma defers BitVM2's intermediate-state
  commitments, which a challenger *reads* to locate a faulty chunk. This
  document defers the garbled input encoding, which a challenger *needs in order
  to evaluate at all*.

**So the contribution stands, and the contrast sharpens it.** Someone did try
moving this data off Bitcoin, a year before anyone else, and needed an external
staked chain and a non-collusion assumption to make it safe. The claim here is
that you can get the same on-chain saving using only Bitcoin's own consensus,
the pre-signed transaction graph that BitVM already builds, and one honest
capitalized challenger, because refusing to reveal is itself punishable. Cite
Fiamma generously in the introduction; the delta is the escalation path, not the
idea of deferring data.

Related, and worth reading in the same sitting: **ESSPI** (BitVMX,
`bitvmx.org/files/esspi-ecdsa-input-bitvmx.pdf`). It attacks the same on-chain
input-authentication cost from the opposite direction, replacing Winternitz with
Schnorr/ECDSA signatures over a published payload and using a secondary BitVMX
instance to prove the two agree. Reported improvement: from "1:200" data
expansion, about 25 witness bytes per signed bit, to "optimal 1:1". Crucially,
**all input data stays on-chain**; the cost is `O(|input|)` with a far better
constant rather than decoupled.

That matters here in two ways. It weakens the crudest version of the Section 1
argument, since 1:1 publication of a 100 kB proof is roughly 25 kvB and about
$41, which is standard and affordable. And it strengthens the Section 11.1
framing, because ESSPI gets to 1:1 precisely by *not* requiring the on-chain
bytes to double as garbled labels. Fusion is what costs.

It also suggests a **Variant C** worth writing down: publish `π` on-chain
ESSPI-style at 1:1, keep only `L_π` off-chain under the digest `δ`, and retain
the escalation path for the labels alone. That removes any data-availability
question about the proof itself, leaves only the labels deferred, and costs
about $41 rather than $1.16 for a 100 kB proof. Strictly worse on fees, strictly
better on DA assumptions. Whether that trade is worth it depends on how the
garbler-binding question in Section 6 lands.
