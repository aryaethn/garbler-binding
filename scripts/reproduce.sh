#!/usr/bin/env bash
# Reproduces every number reported in the paper.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== 1/3  exploit (Tables 1 and 2, ~10s) ==="
( cd "$ROOT/crates/garbling-attack" && cargo run --release ) | tee "$ROOT/results/attack-poc.txt"

if [ ! -d "$ROOT/vendor/garbled-snark-verifier" ]; then
  echo; echo "vendor/ missing; run scripts/setup.sh for steps 2 and 3"; exit 0
fi

echo; echo "=== 2/3  circuit split analysis (Table 3, ~10 min) ==="
( cd "$ROOT/crates/circuit-split-analysis" && cargo run --release ) \
  | grep -v "^··\|^····\|^Start:\|^End:" | tee "$ROOT/results/split-analysis.txt"

echo; echo "=== 3/3  gate census (supporting, ~5 min) ==="
( cd "$ROOT/crates/and-gate-census" && \
  cargo run --release --bin census -- --json "$ROOT/results/census.json" \
                                      --md "$ROOT/results/census.md" )
