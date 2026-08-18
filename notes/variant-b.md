# BitVM3-core-D, Variant B: construction and security argument

Companion to `proof-size-decoupling.md` and `garbler-binding-attack.md`.
Variant A was withdrawn after the attack; this is the construction that stands.

**Claim.** BitVM3-core-D achieves on-chain cost independent of proof size, under
**zero new cryptographic assumptions** relative to BitVM3-core, at the price of
one strengthened operational assumption: the honest verifier must hold capital
`c`.

Notation follows BitVM3 (eprint 2026/933). Theorem numbering mirrors theirs:
B.1 against their Theorem 7.1 (completeness), B.2 against 7.2 (soundness).

---

## 0. What the attack bought us

Writing the proof after the attack rather than before changed the construction
twice, both times by *removing* machinery. Worth stating up front, because the
result is simpler than the draft in `proof-size-decoupling.md` Section 4.

**Simplification 1: the modified decoding is unnecessary.** Attacks 1 and 2 said
Variant A needed an authenticity-style `De` and a published `H(Z^True)`. Variant
B needs neither, because it has no "True" branch. The honest verifier's rule is a
*dichotomy*, not a trichotomy:

```
Y ← Ev(GC, L')
if H(Y) = H(L*):  Disprove with Y
else:             Escalate
```

The hashlock on `H(L*)` that BitVM3-core already places on the Assert output
*is* the authenticity check. A verifier never has to recognise success, only
failure, and failure is self-certifying: holding a preimage of `H(L*)` is
exactly what `Disprove` requires. Nothing about `Ev` on off-manifold labels is
ever assumed.

**Simplification 2: the digest `δ` is not load-bearing.** The draft bound `P` to
`δ = H(φ ‖ π ‖ L_π)` via a one-time key, with a `PunishEquiv` branch, so that
`Assert_full` could not switch proofs. Soundness does not need it. If `P` posts
`Assert_lite`, gets escalated, and then reveals a *different* `π₂` in
`Assert_full`, extractability still yields `En(e, π₂)`, correctness still gives
`De(d, Ev(GC, En(e,π₂))) = Vrfy(φ, π₂)`, and if that is False the honest verifier
still disproves. `P` gains nothing by switching. Likewise, showing different
off-chain data to different verifiers gains nothing: every recipient either
disproves or escalates.

So `δ` becomes an optional anti-DoS filter rather than a binding commitment. It
lets a verifier reject junk before spending the compute to evaluate a 40 GB
circuit. Keep it if you want that; it costs 32 adaptor-signature digits. Drop it
and `Assert_lite` is a plain two-output Taproot spend.

| `Assert_lite` variant | size | cost @2 sat/vB | independent of `\|π\|` |
|---|---:|---:|:--:|
| with `δ` (32 digits, anti-DoS) | 706 vB | $1.16 | yes |
| without `δ` (minimal) | ~154 vB | ~$0.25 | yes |

Against $3.89 today for a 128-byte Groth16 proof and $2,912-and-unminable for
100 kB.

---

## 1. Construction

### 1.1 Setup

Identical to BitVM3-core Section 4.1. No modifications. Specifically: `P` runs
`Gb(1^κ, F)` for `F` the SNARK verifier circuit, derives `(pk_GS, sk_GS)` from
`e`, and publishes `GC`, `d`, `pk_GS` and the transaction bodies via the
bulletin board. Setup correctness is established as in Section 4.2, by
cut-and-choose or a setup proof; unchanged and still required.

New parameters:

- `Δ` — the existing dispute window.
- `Δ_E` — escalation window, with `Δ_E < Δ`.
- `c` — escalation bond.
- `k` — number of `Assert_full` chunks, `k = ⌈|π| · 17.9 / 100000⌉` at the
  100 kvB standardness limit.

The committee pre-signs **both** `Withdraw_lite` and `Withdraw_full` under
`SIGHASH_ALL`. This is the only setup-phase change: two authorized exits instead
of one.

### 1.2 Transactions

`P` publishes `(π, L_π)` on the same channel as `GC`, then posts:

| | `Assert_lite` |
|---|---|
| Inputs | (0) `(*, *, CheckSig_{pk_O})` |
| Outputs | (0) `(d BTC, ⟨Hashlock(H(L*)), RelTimelock(Δ) ∧ CheckSig_{pk_O}⟩)` |
| | (1) `(0 BTC, ⟨EscalateScript, RelTimelock(Δ_E) ∧ CheckSig_{pk_O}⟩)` |
| Witness | (0) `σ_O` |

| | `Disprove` |
|---|---|
| Inputs | (0) `(Assert_lite, 0, Hashlock(H(L*)))` |
| Outputs | (0) `(* BTC, True)` |
| Witness | (0) `L*` |

| | `Escalate` |
|---|---|
| Inputs | (0) `(Assert_lite, 1, EscalateScript)` |
| | (1) `(*, *, *)` funding the bond `c` |
| Outputs | (0) `(c BTC, ⟨CheckCovenant⟩)` |
| Witness | (0) `Covenant`, (1) `*` |

| | `Assert_full` (chunk `j` of `k`) |
|---|---|
| Inputs | (0) `(Escalate, 0, CheckCovenant)` if `j=1`, else `(Assert_full_{j-1}, 0, CheckCovenant)` |
| Outputs | (0) `(d + c BTC, ⟨Hashlock(H(L*)), RelTimelock(Δ) ∧ CheckSig_{pk_O}⟩)` |
| Witness | (0) `*, σ_GS` |

`Withdraw_lite` consumes `(Deposit, 0)`, `(Assert_lite, 0)` after `Δ`, and
`(Assert_lite, 1)` after `Δ_E`. The third input is the mechanism: if `Escalate`
consumed output (1), `Withdraw_lite` is permanently invalid.
`Withdraw_full` consumes `(Deposit, 0)` and `(Assert_full_k, 0)` after `Δ`, and
returns `c` to `P`.

### 1.3 Honest-verifier rule

A verifier `V` holding `GC`, `d`, and `H(L*)`:

1. If `V` received `(π', L')` from `P`: compute `Y ← Ev(GC, L')`.
   If `H(Y) = H(L*)`, post `Disprove` with witness `Y`.
2. In every other case — no data, junk data, or `H(Y) ≠ H(L*)` — post
   `Escalate`, bonding `c`.

---

## 2. Completeness

**Theorem B.1.** *BitVM3-core-D is complete in the random oracle model, assuming
the prover follows setup and proving honestly and holds `w` with `(φ,w) ∈ R`,
the ledger is safe and live, the garbling scheme is correct and authentic, `H` is
preimage-resistant, the SNARK is complete, and the digital signature scheme is
EUF-CMA secure. An honest prover recovers the reserve within `Δ` of posting
`Assert_lite`, at net cost `fee(Assert_lite)` when unescalated and
`fee(Assert_lite) + fee(Assert_full) − c` when escalated.*

*Proof.* `P` holds `w`, so by SNARK completeness `Vrfy(R, crs, φ, π) = True` for
`π ← Prove(R, crs, φ, w)`. `P` publishes `L_π = En(e, π)` and posts
`Assert_lite`.

**Case 1: no `Escalate` within `Δ_E`.** By correctness of `G`,
`De(d, Ev(GC, En(e,π))) = Vrfy(R, crs, φ, π) = True`, so
`Ev(GC, L_π) = Z^True ≠ L*`. For any verifier to post `Disprove` it must exhibit
a preimage of `H(L*)`. Its view is `(GC, d, H(L*), L_π)`, which is exactly the
view granted in the authenticity experiment of ZRE15 Section 2 — `(F, X)` alone,
without `e`, `d`'s underlying labels, or `R` — augmented with the published hash.
By authenticity of `G`, no PPT verifier produces `Ỹ ≠ Ev(GC, L_π)` decoding to a
non-⊥ value except negligibly; by preimage resistance of `H`, none inverts
`H(L*)` directly. Note this is not a new assumption: BitVM3-core already places
`H(L*)` in an on-chain hashlock and relies on the same property. Hence no
`Disprove`, and after `Δ` the operator spends `Assert_lite` output (0) via the
timelock. `Withdraw_lite`'s three inputs are all available, and the committee
pre-signature authorizes it.

**Case 2: some verifier posts `Escalate`.** `Withdraw_lite` is dead. `P` posts
`Assert_full` chunks `1..k`, whose witnesses carry the full `N = |π|` adaptor
signatures under `pk_GS`. By extractability, every verifier recovers
`L_π = En(e,π)`; by correctness, evaluation decodes to True; by authenticity,
none obtains `L*`. After `Δ`, `P` spends `Assert_full_k` output (0) and
`Withdraw_full` returns `d + c`. Net cost is `fee(Assert_full) − c ≤ 0` whenever
`c ≥ fee(Assert_full)`.

**Timing.** Case 2 requires `Δ − Δ_E` to accommodate confirmation of `k` chained
chunks. With `k = 18` for a 100 kB proof and a 6-block depth per chunk, that is
108 blocks, roughly 18 hours, comfortably inside a one-week `Δ`. This is a
parameter constraint, not an assumption, and it must be stated in the protocol
description. □

---

## 3. Soundness

**Theorem B.2.** *BitVM3-core-D is sound in the random oracle model, assuming
the prover follows setup honestly but may deviate arbitrarily during proving,
**at least one verifier is honest and holds capital `c`**, the ledger is safe and
live, the garbling scheme is correct and authentic, the garbled-encoding
extractable signature scheme is extractable, `H` is collision- and
preimage-resistant, and the SNARK is knowledge-sound. Then whenever the prover
spends the reserve, an extractor outputs `w` with `(φ, w) ∈ R`.*

*Proof.* Let `V*` be the honest capitalized verifier and suppose `P` reaches the
reserve. `V*`'s rule is exhaustive; take the two cases.

**Case A: `V*` evaluated and obtained `Y` with `H(Y) = H(L*)`.** Then `V*` posts
`Disprove` with witness `Y`, spending `Assert_lite` output (0). `Withdraw_lite`
requires that output, so it is dead; `Withdraw_full` requires `Assert_full`,
which requires `Escalate`, which requires `Assert_lite` output (1), and no path
reaches the reserve. Ledger liveness places `Disprove` on-chain within `Δ`.
Contradiction.

Note carefully what this case does **not** require. `V*` need not know that `L'`
is a well-formed encoding, and the argument never invokes correctness or
authenticity on off-manifold input. `V*` holds an actual preimage of `H(L*)`,
and that is self-certifying: by collision resistance of `H`, `Y = L*`, and
producing `L*` is all `Disprove` needs. This is precisely the step where Variant
A required garbler-binding and Variant B does not.

**Case B: otherwise.** `V*` posts `Escalate` within `Δ_E`, spending
`Assert_lite` output (1). `Withdraw_lite` is permanently invalid.

*B1: `P` does not post `Assert_full` within `Δ − Δ_E`.* Neither exit is
available and `P` forfeits. Contradiction.

*B2: `P` posts `Assert_full` with witness `σ_GS`.* By extractability of GS,
every verifier — including any who never interacted with `P` — recovers a
garbled encoding `L_{π'} = En(e, π')` for the `π'` signed. Setup honesty gives
that `GC` correctly implements the SNARK verifier. By correctness of `G`,

```
De(d, Ev(GC, En(e, π'))) = Vrfy(R, crs, φ, π').
```

If this is `False`, `V*` obtains `L*` and posts `Disprove` against
`Assert_full_k` output (0) before the timelock, blocking `Withdraw_full`.
Contradiction. Therefore `Vrfy(R, crs, φ, π') = True`, and by knowledge soundness
of the SNARK an extractor outputs `w` with `(φ, w) ∈ R`. □

**Corollary (no equivocation branch needed).** `P` may commit to `π₁` off-chain
and reveal `π₂ ≠ π₁` in `Assert_full`; case B2 applies to whichever proof is
actually signed on-chain, so `P` gains nothing. `P` may also serve different data
to different verifiers; each recipient lands in case A or case B, and both are
losing. Hence the `PunishEquiv_δ` branch sketched in
`proof-size-decoupling.md` Section 4 is unnecessary and should be deleted.

---

## 4. Operator safety and the griefing bound

**Theorem B.3.** *An honest prover's net loss to malicious escalation is at most
`fee(Assert_full) − c`, which is `≤ 0` for `c ≥ fee(Assert_full)`. Each
escalation costs the escalating verifier `c`, and at most one escalation is
possible per `Assert_lite`.*

*Proof.* `Assert_lite` output (1) is a single UTXO, so `Escalate` fires at most
once. By Theorem B.1 Case 2 an honest prover completes `Assert_full` and
`Withdraw_full` returns `d + c`. The escalating verifier's bond funds
`Escalate` output (0), which flows to the prover. □

So in equilibrium no rational verifier escalates against a prover it believes
honest, which is what recovers Variant A's fast path economically rather than
cryptographically. The residual costs to an honest prover are liquidity (the
bond is locked during the window) and latency (the escalation round-trip), not
value.

**Deposit sizing.** Set `d ≥ fee(Assert_full) + c` so that escalation against a
*cheating* prover is self-financing from the forfeited deposit. For `|π| = 100 kB`
that is roughly `$2,912 + c`, against the $15,742.55 worst case Babylon measured
for BitVM2 on mainnet in June 2025.

---

## 5. The assumption delta, stated plainly

| assumption | BitVM3-core | Variant B |
|---|:--:|:--:|
| at least one honest verifier | yes | yes |
| ...who also holds capital `c` | no | **yes** |
| off-chain availability of `GC` (41 GB) | yes | yes |
| off-chain availability of `(π, L_π)` | n/a | **no** (escalation covers withholding) |
| honest setup (cut-and-choose or setup proof) | yes | yes |
| garbling correctness | yes | yes |
| garbling authenticity | yes | yes |
| GS extractability | on every Assert | **only on `Assert_full`** |
| `H` collision- and preimage-resistant | yes | yes |
| SNARK knowledge soundness | yes | yes |
| one-time signature unforgeability | yes (light client) | yes (light client) |
| **anything new** | — | **none** |

The single delta is the capitalized honest verifier. Three mitigations, in the
order to present them:

1. The bond is refunded whenever the challenge was justified, so an honest
   verifier facing a genuinely cheating prover risks nothing.
2. `c` is crowdfundable via `SIGHASH_SINGLE|ANYONECANPAY`, exactly as BitVM2
   Section 5.4 does for its `Challenge` collateral. This is not a new technique
   being invented for this protocol.
3. Users exiting the bridge are natural challengers who already have capital at
   stake in the outcome.

It is worth being explicit that BitVM2 already requires a capitalized challenger
for its `Challenge` transaction, so the delta is against BitVM3-core
specifically, not against the family.

---

## 6. What this unlocks

On-chain cost becomes independent of proof size, so the ceiling identified in
`proof-size-decoupling.md` Section 1 disappears:

| proof system | proof size | Assert today | Assert, Variant B |
|---|---:|---:|---:|
| Groth16 / BN254 | 128 B | $3.89 | **$0.25** |
| Binius64 (ECDSA) | 188 KiB | unminable | **$0.25** |
| STARK, compressed | 50-100 kB | $1,456-$2,912, non-standard | **$0.25** |

The worst case survives at `$2,912` for a 100 kB proof, but it is paid only by a
prover who is forfeiting a deposit sized to cover it.

That removes the on-chain half of the dichotomy from the census work: **small and
post-quantum are no longer mutually exclusive on-chain.** The off-chain half
remains — our measured 6.0 GB for a Boolean-garbled hash-based verifier against
Argo/BABE's ~22-25 MB — and that is now the only thing standing between this and
a post-quantum trust-minimized Bitcoin bridge.

---

## 7. Open items, honestly

1. **Fee-rate risk.** `c` and `d` are denominated in future blockspace. A prover
   cheating during a fee spike may face an `Assert_full` exceeding the bond. This
   is a sharper version of a problem BitVM already has with pre-signed graphs
   (Glock Section 1.2: "This requires estimating many parameters of the system in
   advance, including the fee rate and time to finalize a transaction"), and it
   is worse here because `Assert_full` is large. Needs a fee model, anchor
   outputs, or CPFP, not a point estimate.
2. **Sampled escalation.** Escalation reveals all `N` labels. A challenger-selected
   random subset verified against a Merkle root should suffice for an
   availability-and-well-formedness check, cutting the worst case from `O(P)`.
   The obstacle is the standard data-availability sampling problem, and erasure
   coding over garbled input labels is not obviously sound. Open, and probably
   its own paper.
3. **Composition with Mosaic.** Mosaic makes on-chain cost independent of the
   cut-and-choose copy count `ℓ`; this makes it independent of `|π|`. Orthogonal,
   and the composition looks direct, but it has not been checked.
4. **Model.** The arguments above are game-based sketches. The paper works in a
   UC-style formulation via Cardinal's ChainVM framework (Appendix A), and the
   theorems need restating there before submission.
5. **The capitalized-verifier assumption** is the thing a reviewer will push on.
   Decide now whether to present it as a weakening or, better, to argue it is
   already implicit in any protocol where challenging costs a transaction fee.
