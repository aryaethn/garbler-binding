# Free-XOR Garbling Is Not Binding Against the Garbler

Artifacts for the paper *Free-XOR Garbling Is Not Binding Against the Garbler:
What the On-Chain Label Reveal Buys in BitVM-Style Protocols*
([`paper/main.pdf`](paper/main.pdf)).

## The claim in one paragraph

BitVM-style protocols have a prover garble a SNARK verifier and have challengers
evaluate it. Soundness needs the prover to be unable to make an honest
evaluation accept without a valid witness. No standard garbling property gives
this. Correctness quantifies only over valid encodings; authenticity hands the
adversary the garbled circuit and one encoded input and withholds `e`, `d` and
the global offset `R`, all of which the garbler holds. Every design in this
family closes the gap the same way, by revealing the input labels on-chain,
which is exactly why on-chain cost is linear in proof size. This work isolates
the missing property, shows it is not free, and measures whether the deployed
circuit needs it.

## Results

| | |
|---|---|
| Native half-gates decoding | forges in 1, 1, 3 trials at `k` = 32, 64, 128 |
| BitVM3-core decoding commitment | one-sided; success is unobservable off-chain |
| Encoding-form binding | false; XOR cancellation gives a bit-identical evaluation |
| Birthday ceiling | `2^(k/2)`, measured scaling exponent **1.02** over `k` in [24,44] |
| Speedup vs naive search at `k=28` | **3,259x**, itself growing as `2^(k/2)` |
| Deployed BN254 Groth16 verifier | output linear frontier = **1 atom**; **0 of 638,658** tail gates separable |

The deployed system is **not** vulnerable. It is safe because Groth16 terminates
in an equality check aggregating the whole pairing result, a property nobody
chose, that is stated nowhere, and that is not obviously preserved under a
change of proof system.

## Layout

```
paper/                    LaTeX source and compiled PDF
crates/
  garbling-attack/        the exploit: k-parameterised half-gates + the attacks
  circuit-split-analysis/ the tool: does a circuit admit an affine split?
  and-gate-census/        supporting measurement harness (gate census, anchor)
results/                  committed output of every run reported in the paper
notes/                    working notes, including an unfinished follow-up
scripts/                  vendoring and reproduction
```

## Reproducing

The exploit is self-contained, one dependency, about ten seconds:

```bash
cd crates/garbling-attack && cargo run --release
```

Expected output is in [`results/attack-poc.txt`](results/attack-poc.txt).

The circuit analysis needs the BitVM Alliance implementation vendored, then one
pass over the real verifier circuit (about ten minutes on a laptop core):

```bash
./scripts/setup.sh
cd crates/circuit-split-analysis && cargo run --release
```

Expected output is in [`results/split-analysis.txt`](results/split-analysis.txt).

`scripts/setup.sh` clones `garbled-snark-verifier` and applies one patch: it
removes the unconditional SP1 build-dependencies, whose build script downloads
artifacts from S3 at compile time. Nothing else about the upstream crate is
changed, and the anchor measurement in `results/anchor.json` comes from
upstream's own unmodified example.

## Building the paper

```bash
cd paper && make
```

## Working notes

`notes/` contains the material this paper was extracted from. It is unpolished
and is included for provenance rather than as a claim.

- `attack-working-notes.md` — the attack as first written, including a verdict
  that Step 2 later partially retracted. Kept because the retraction is part of
  the record.
- `and-gate-census-notes.md` — the gate census, its calibration checks, and the
  finding that a garbled verifier's cost is set almost entirely by its Merkle
  hash rather than its field.
- `proof-size-decoupling.md`, `variant-b.md` — **an unfinished follow-up**: a
  construction that decouples on-chain cost from proof size using a bonded
  escalation path rather than an unconditional label reveal. Not claimed here.
  It has completeness, soundness and griefing arguments in game-based form, and
  needs restatement in the ChainVM model before it is a paper.
- `bitvm-research-directions.md` — the survey the whole line of work started from.

## Citing

```bibtex
@misc{garblerbinding2026,
  author = {Aria Naraghi},
  title  = {Free-{XOR} Garbling Is Not Binding Against the Garbler},
  year   = {2026},
  note   = {Preprint},
  url    = {https://github.com/<user>/garbler-binding}
}
```

## License

MIT for the code. The paper is under CC BY 4.0.
