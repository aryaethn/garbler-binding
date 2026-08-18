# Attack on Section 6: garbler-binding does not hold

Companion to `proof-size-decoupling.md`.

**Verdict after Step 2 (see Section "Does the real circuit have the structure?"
at the end, which partially retracts the first version of this document):**
Attacks 1, 2, 3 and 5 stand. Attack 4 is real, has a working exploit, and
**does not apply to the deployed BN254 Groth16 verifier**, which was measured
and found to have no exploitable split. So Variant A is not broken by the
exploit; it is unproven, and its security now demonstrably depends on a
circuit-structural property that must be audited per circuit. The
recommendation is unchanged, for economic rather than cryptographic reasons.

Sources used, read directly: Zahur-Rosulek-Evans, "Two Halves Make a Whole"
(eprint 2014/756), Figure 2 and Section 4; Guo-Katz-Wang-Yu (eprint 2019/074)
for the CCR setting; BitVM3 (eprint 2026/933) Sections 4.1 and 7.

---

## 0. The construction we are attacking

ZRE15 Figure 2, verbatim in structure:

```
Gb:   R  ←$ {0,1}^{k-1}1                          global offset, lsb(R) = 1
      W_i^0 ←$ {0,1}^k   for input wires
      W_i^1 = W_i^0 ⊕ R                           free-XOR
      XOR gate:  W_i^0 = W_a^0 ⊕ W_b^0            no ciphertexts
      AND gate:  (W_i^0, T_Gi, T_Ei) ← GbAnd(...)
      output:    d_i = lsb(W_i^0)

En:   X_i = e_i ⊕ x_i R

Ev:   XOR:  W_i = W_a ⊕ W_b
      AND:  s_a = lsb W_a ;  s_b = lsb W_b
            W_Gi = H(W_a, j)  ⊕ s_a · T_Gi
            W_Ei = H(W_b, j') ⊕ s_b · (T_Ei ⊕ W_a)
            W_i  = W_Gi ⊕ W_Ei

De:   y_i = d_i ⊕ lsb(Y_i)
```

BitVM3-core instantiates this with `k = 128` (16-byte labels; that is where the
"2 ciphertexts x 16 B per non-free gate" accounting in the paper and in our
census comes from).

Two facts from ZRE15 that the attack turns on, both stated by the authors:

> "The scheme shown in Figure 2 **does not provide authenticity**, simply because
> authenticity is not required in many use cases including semi-honest Yao's
> circuits."

> "**Authenticity (aut):** Given input `(F, X)` **alone**, no adversary should be
> able to produce `Ỹ ≠ Ev(F, X)` such that `De(d, Ỹ) ≠ ⊥`, except with
> negligible probability."

Note what the authenticity experiment hands the adversary: `(F, X)` **alone**.
Not `e`, not `d`, not `R`. The garbler holds all three. Authenticity is, by
construction, silent about the garbler. That is not an oversight to be patched;
it is the definition doing its job for a different threat model.

---

## Attack 1: `De` never returns ⊥, so there is nothing to break

The most embarrassing one first. In ZRE15 as written, `De(d, Y) = d ⊕ lsb(Y)`.
It is a single XOR against one bit of the label. **Every** 128-bit string decodes
to a valid output bit. There is no ⊥.

So a malicious prover does not need any cleverness:

1. Pick arbitrary garbage `L ←$ ({0,1}^k)^n`.
2. Evaluate locally. The output label is garbage, and `lsb` of garbage is
   uniform.
3. If it decodes to False, resample and repeat.

Expected two trials. Garbler-binding fails with a two-line attack and no
cryptanalysis whatsoever.

**Repair:** replace `De` with an authenticity-style decoding that commits to
both output labels, e.g. `d = (H(Z^0), H(Z^1))` with `De` returning ⊥ on a
mismatch. ZRE15 Section 4.3 gives the standard modification. Everything below
assumes this repair is in place.

---

## Attack 2: BitVM3-core publishes only half the decoding, so "True" is unobservable

This one is specific to BitVM3-core and it kills Variant A as I specified it,
independently of any cryptography.

From BitVM3 Section 4.1: "Let `L*` be the output label of the circuit that
decodes to False," and the Assert output carries "a hash lock on `H(L*)`."
Table 4 confirms it: `Disprove` has input `(Assert, 0, Hashlock(H(L*)))` and
witness `L*`.

**`H(Z^True)` is never published.** It does not need to be, in the original
design: the operator wins by the *absence* of a Disprove, so nobody ever has to
recognise success.

But Section 5 of the companion document asks the challenger to distinguish three
outcomes: False, True, and inconclusive. With only `H(L*)` in hand, a challenger
can recognise False and nothing else. "True" and "garbage" are the same
observation. So a cheating prover ships garbage labels off-chain, every honest
challenger sees not-`L*`, and under Variant A's rule "True → do nothing" they do
nothing.

**Repair:** publish `H(Z^True)` at setup as well. It is 32 bytes and free. But
it is *not* in the paper, and noticing that it becomes necessary the moment you
remove the on-chain reveal is exactly the kind of thing that has to be caught
before rather than after.

---

## Attack 3: the definition as written is false, for a boring reason

Even with Attacks 1 and 2 repaired, the definition in Section 6 of the companion
document quantifies over the wrong object. It asks that `L` **be** an encoding
`En(e, x)`. Counterexample:

Let input wires `i` and `j` both feed a common XOR gate, or more generally let
`S` be any set of input wires whose parity into every `H`-application in the
circuit is even. Set

```
L_m = W_m^0 ⊕ ρ   for m ∈ S,     L_m = W_m^{x_m}   otherwise
```

for any `ρ ∉ {0, R}`. Evaluation of the XOR gate gives
`(W_i^0 ⊕ ρ) ⊕ (W_j^0 ⊕ ρ) = W_i^0 ⊕ W_j^0`: the `ρ` cancels. No `H` is ever
called on a perturbed label, so the **entire evaluation is bit-identical to the
honest one**, and the output decodes correctly.

`L` is not `En(e, x)` for any `x`, yet everything works. The definition is too
strong and must be stated over outcomes:

> **Definition (Evaluation-Binding).** For every PPT `A` given
> `(GC, e, d) ← Gb(1^κ, F)`: `A` cannot output `L` with
> `De(d, Ev(GC, L)) = True` unless `F` is satisfiable.

This attack does not help a cheating prover by itself. It matters because it
shows the property has to be formulated carefully, and because the mechanism it
exposes, **free-XOR making large regions of the circuit GF(2)-affine in the
labels**, is what Attack 4 weaponises.

---

## Attack 4: the security ceiling is 2^(k/2), not 2^k

Now the real one.

Model `H` as a random oracle. For off-manifold `L`, the map
`L ↦ Ev(GC, L)` behaves like a random function into `{0,1}^k`, so hitting the
specific target `Z^True` should cost `2^k`. That is the intuition I offered in
the companion document, and it is wrong whenever the circuit has XOR structure
near the output, which free-XOR guarantees it will.

**The attack.** Suppose the output label can be written

```
Z = g(L_S) ⊕ h(L_T)
```

for disjoint input-wire sets `S`, `T`. This holds whenever the paths from `S` and
from `T` merge only through XOR gates after their last `H`-application, which is
exactly the affine structure Attack 3 exhibits. Then:

1. Enumerate `2^{k/2}` garbage assignments to `L_S`, tabulate `g(L_S)`.
2. Enumerate `2^{k/2}` garbage assignments to `L_T`, look up
   `Z^True ⊕ h(L_T)` in the table.
3. A collision is expected. It yields `L` with `Ev(GC, L) = Z^True`.

Standard birthday. With van Oorschot-Wiener parallel collision search this needs
negligible memory and parallelises perfectly.

**Concretely, for BitVM3-core's `k = 128`: 2^64.**

Cost estimate, being deliberately conservative. `H` is instantiated with fixed-key
AES-NI or BLAKE3; call it `10^9` evaluations per core-second. Then
`2^64 / 10^9 ≈ 1.8 x 10^10` core-seconds, about **585 core-years**, or roughly
**three weeks on 10,000 cloud cores at a hardware cost on the order of $100k**.

Clementine has processed roughly 150 BTC. A six-figure attack against an
eight-figure bridge is not a theoretical concern.

**How hard is the structural precondition to rule out?** Our census measured the
BN254 Groth16 verifier at 7,686,952,943 free (XOR/XNOR) gates against
2,715,041,234 non-free gates: **74% of the circuit is XOR**. Establishing that no
exploitable affine split exists anywhere in the output cone of a 10.4-billion-gate
circuit is not a proof obligation anyone should want to take on, and it would
have to be re-discharged for every circuit, every proof system, and every
compiler revision, forever.

---

## Proof of concept: it runs

`garbling-attack/` is a working implementation. It is a faithful reimplementation
of ZRE15 Figure 2 parameterized by label length `k`, because
`garbled-snark-verifier` fixes `k = 128` and puts the birthday attack out of
demonstration range. Before any attack runs, `validate()` checks the garbling
exhaustively over every input of every test circuit at `k ∈ {16, 32, 64, 128}`;
all pass. If the garbling were wrong the attacks would prove nothing.

```
cd garbling-attack && cargo run --release
```

Full output in `results/attack-poc.txt`. Summary:

**Attack 1**, ZRE15 native `De`:

```
k=32   FORGED in 1 trial(s)
k=64   FORGED in 1 trial(s)
k=128  FORGED in 3 trial(s)
```

Random garbage input labels, decoded with `y = d ⊕ lsb(Y)`. The committed-`De`
repair returns `None` on the same labels, as it should.

**Attack 3**, XOR cancellation on `((a XOR b) AND c) XOR d`:

```
k=32   identical=true  L_0 off-manifold=true  L_1 off-manifold=true  decoded=Some(true)
k=64   identical=true  ...
k=128  identical=true  ...
```

Evaluation is bit-identical to honest with both perturbed labels off-manifold.

**Attack 4**, birthday on `(a AND b) XOR (c AND d)`. `off-mf` is now an
exhaustive check that the forged vector equals `En(e,x)` for **none** of the
`2^n` inputs, not merely that two coordinates are off-manifold:

```
  k          H evals        2^(k/2)            2^k    found   off-mf   decodes
  24           20722        4.096e3        1.678e7     true     true Some(true)
  28          105924        1.638e4        2.684e8     true     true Some(true)
  32          280360        6.554e4        4.295e9     true     true Some(true)
  36         1170344        2.621e5       6.872e10     true     true Some(true)
  40         4349874        1.049e6       1.100e12     true     true Some(true)
  44        24420688        4.194e6       1.759e13     true     true Some(true)
```

Every row is a label vector that is the encoding of no input whatsoever, which
the honest evaluator accepts as a proof of `True` under authenticity-style
committed decoding. That is the break, executed, not argued.

Head to head against naive search for the same target at the same `k`:

```
  k         birthday H          naive H      speedup
  20              5702          1160196         203x
  24             20722         36204000        1747x
  28            105924        345161504        3259x
```

The speedup itself grows as `2^{k/2}`, which is the point. Measured scaling
exponent across `k = 24..44`:

```
  measured scaling exponent: 1.02   (birthday predicts 1.00)
```

So the attack is empirically `2^{k/2}`, not `2^k`, over a twenty-bit range of
label lengths. Extrapolating to the deployed parameter: **`k = 128` gives 2^64.**

A caveat stated plainly: this demonstrates the attack on a circuit *built* to
have the split structure. Whether the real Groth16 verifier circuit contains an
exploitable split anywhere in its output cone is a separate question, and it is
the next experiment. If it does not, Attacks 1, 2, 3 and 5 still stand and
Attack 4 becomes a design constraint rather than a live break.

## Attack 5: there is no small patch to Theorem 7.2

Worth stating separately, because it explains why none of this is repairable by
being more careful with the existing proof.

BitVM3's soundness proof begins:

> "A malicious prover that publishes Assert with witness `σ_π` reveals, **by
> extractability of GS**, the encoding `L_π = En(e, π)`. Since setup is honest,
> `GC` correctly implements the SNARK verifier, and **by correctness of the
> garbling scheme**, `De(d, Ev(GC, L_π)) = SNARK.Vrfy(R, crs, φ, π)`."

The second invocation depends on the first. *Correctness* of a garbling scheme
is a statement about valid encodings only: it says nothing whatsoever about
`Ev(GC, L)` for `L ∉ En(e, ·)`. Extractability is what establishes the
hypothesis that correctness needs.

Remove the on-chain reveal and you do not weaken the theorem, you delete its
first line and the second no longer type-checks. There is no partial credit
here.

---

## Does the real circuit have the structure? (Step 2)

The proof of concept above demonstrates Attack 4 on a circuit *built* to have
the split. `circuit-split-analysis/` asks whether the circuit BitVM3-core
actually garbles has it.

**Method.** A custom `CircuitMode` runs the real `garbled_groth16::verify`
circuit end to end. Every wire carries a 64-bit dependency sketch: input wire
`i` is seeded with bit `i mod 64`, every gate ORs its operands, so a wire's
sketch records which of the 64 residue classes of input wires it depends on. The
last 2^21 gates are recorded with their wire ids and sketches, which lets the
*linear frontier* of the output be reconstructed exactly offline: from the
output wire, step back through free gates only, stopping at non-free gates or
inputs, with even-parity atoms cancelling as the label algebra requires.

**Result**, one full pass over the real circuit:

```
input wires:            3302
gates executed:         10338696819
non-free gates:         2714835821
output sketch popcount: 64/64

--- linear frontier of the output ---
backward steps through free gates: 1
frontier atoms (odd parity):       1
unresolved wires:                  0

--- one level deeper: the top non-free gate ---
  operand A sketch popcount 64/64
  operand B sketch popcount 64/64
  A-exclusive classes: 0x0000000000000000
  B-exclusive classes: 0x0000000000000000

--- how deep before a separable gate appears? ---
non-free gates in recorded tail: 638658
of those, with separably controllable operands: 0
```

Three findings, with different strengths.

1. **Exact:** the output's linear frontier is a single atom. The output wire is
   produced directly by a non-free gate with no XOR above it, so the top-level
   XOR decomposition Attack 4 needs does not exist. This is not statistical; the
   backward walk terminated in one step with nothing unresolved.

2. **Evidence:** the top non-free gate's two operands each depend on inputs from
   all 64 residue classes with no mutually exclusive class, so they are not
   separably controllable at this resolution.

3. **Evidence:** across the 638,658 non-free gates in the last 2^21 gates of the
   circuit, **zero** have separably controllable operands.

**Conclusion: Attack 4 does not apply to the deployed circuit.** The Groth16
verifier ends in an equality check that aggregates the entire pairing result, so
every wire near the output depends on essentially every input, and there is
nothing to vary independently.

**Scope, stated honestly.** The recorded tail is 2^21 of 1.03e10 gates, the last
0.02%. Finding 1 is exact and unconditional; findings 2 and 3 are at 64-class
resolution, and two cones could be disjoint while both touching all 64 classes.
Exact cone analysis would need a 3302-bit bitset per live wire, roughly 66 MB
resident and an estimated 10 to 15 minutes per pass, which is affordable and
should be done before this is published. A separate gap: my non-free count of
2,714,835,821 differs from the census anchor's 2,715,041,234 by 205,413, most
likely gates whose output wire is `UNREACHABLE` and which the upstream counter
includes but mine does not. Unverified; worth confirming.

**What this does to the argument.** Attack 4 stops being a break on the deployed
system and becomes a **design requirement**: the circuit must not admit an
affine split reachable from the output. The deployed circuit satisfies it, and
nobody chose that. It is a property of the Groth16 verifier's final equality
check, not a decision anyone made, and it is not obviously preserved under a
change of proof system, a change of compiler, or a change of output convention.
A hash-based verifier ending in a XOR-tree accumulator, which is exactly what
the post-quantum direction points at, would be a natural place for it to fail.

So the honest framing for a write-up is not "we broke BitVM3" but:

> Free-XOR garbling gives no binding guarantee against the garbler. Whether a
> given deployment is safe depends on a structural property of its circuit that
> no existing design states, checks, or is aware of relying on. We give the
> property, an exploit for circuits that violate it, and a tool that decides it.

That is a better paper than the break would have been, and it is true.

---

## The verdict, and why it is not close

Repairing Variant A requires all four of:

| # | repair | cost |
|---|---|---|
| 1 | authenticity-style `De` with committed output labels | small |
| 2 | publish `H(Z^True)` at setup | 32 bytes |
| 3 | restate as evaluation-binding and prove it under CCR | months, uncertain |
| 4 | rule out affine splits in the output cone, per circuit, forever | a tool and a full circuit pass, every time |

Item 4 is the one that decides it, though not the way the first draft of this
document claimed. Step 2 shows the condition *can* be discharged for a given
circuit: it took a custom analysis mode and one full pass over 1.03e10 gates,
and the answer for the deployed Groth16 verifier came back clean. So the repair
is possible. It is also a permanent obligation, re-run for every circuit, every
proof system and every compiler revision, on a property no upstream design
states or knows it depends on. And if some future circuit fails the check, the
only remaining fix is `k = 256`, which **doubles the garbled circuit from
40.5 GB to 81 GB**, since size is `2 ciphertexts x (k/8) bytes` per non-free
gate.

Set that against what Variant A actually buys over Variant B. Both post the same
`Assert_lite` at $1.16 on the honest path. Both escalate only when a challenger
chooses to. The sole difference is that Variant A lets an honest challenger
*recognise* success and stand down on cryptographic grounds, whereas Variant B
achieves the same equilibrium economically, by making the escalation bond `c`
unprofitable to burn against an honest prover.

So the trade is: **+40 GB of off-chain data, plus an unproven assumption, plus a
per-circuit topology audit, in exchange for replacing an economic deterrent with
a cryptographic one.** In a design whose entire premise is that off-chain size is
the binding constraint, that is not a close call.

**Drop Variant A. Write Variant B.**

---

## What survives, and what to do with it

1. **Variant B is untouched by all five attacks.** Its soundness never rests on
   off-chain labels: any challenger who cannot produce a Disprove escalates, and
   escalation restores on-chain extractability, at which point Theorem 7.2
   applies verbatim to `Assert_full`. Attack 5 is the reason this works, not a
   problem for it.

2. **Attack 2 is a real finding about BitVM3-core as published**, independent of
   this whole line of work: the construction commits to `H(L*)` but not
   `H(Z^True)`, so success is unverifiable off-chain. That costs nothing today
   because extractability makes it moot, but it is a latent asymmetry worth a
   sentence to the authors.

3. **Attack 4 generalises beyond this document.** Any BitVM-family design that
   lets an evaluator act on labels not authenticated on-chain inherits the
   `2^{k/2}` ceiling. That includes anything built on Glock's "auspicious
   harmony" if the harmony is ever broken for efficiency. Worth writing up as a
   short note on its own: *free-XOR halves your security margin the moment the
   garbler can choose the labels.*

4. **The 128-bit label choice deserves scrutiny in its own right.** It is
   inherited from 2PC, where the garbler cannot choose evaluator inputs. BitVM
   is not that setting whenever labels move off-chain. Nobody appears to have
   asked whether `k = 128` is still the right parameter here.

## Immediate next step

Write the Variant B completeness and soundness argument against Theorems 7.1 and
7.2, with the escalation path carrying the soundness reduction and the bond
carrying the griefing bound. That document is now unblocked and, unlike Variant
A, has no open cryptographic dependency.
