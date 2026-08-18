#!/usr/bin/env bash
# Vendors the BitVM Alliance garbled-snark-verifier and applies the one patch
# needed to build it without SP1.
#
# Upstream declares sp1-build and sp1-sdk as *unconditional* [build-dependencies].
# Cargo compiles build-dependencies regardless of feature flags, and sp1-prover's
# build script downloads a verifying-key map from S3 at compile time, which fails
# in sandboxes and CI. Nothing else about the crate is modified; the anchor
# measurement in results/anchor.json comes from upstream's own example, unchanged.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/vendor/garbled-snark-verifier"

if [ -d "$VENDOR" ]; then
  echo "already vendored at $VENDOR (delete to re-vendor)"
  exit 0
fi

mkdir -p "$ROOT/vendor"
git clone --depth 1 https://github.com/chainwayxyz/garbled-snark-verifier.git "$VENDOR"

python3 - "$VENDOR/Cargo.toml" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('[build-dependencies]\nsp1-build = "5.2"\nsp1-sdk = "5.2"\n', '')
open(p, 'w').write(s)
PY

cat > "$VENDOR/build.rs" <<'RS'
fn main() {
    println!("no soldering");
}
RS

echo
echo "vendored to $VENDOR"
echo
echo "if rustup tries to install toolchain 1.90 (upstream pins it), run:"
echo "  export RUSTUP_TOOLCHAIN=stable"
