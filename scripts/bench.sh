#!/usr/bin/env bash
# Benchmarks quorum-hsm against SoftHSM2 (speed and attacks) and writes
# docs/benchmarks/results.md. Needs: cargo, softhsm2 (sudo apt install softhsm2).
# Extra arguments go to quorum-bench, e.g. --iterations 500 or --softhsm <module.so>.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-pkcs11 -p quorum-bench
mkdir -p docs/benchmarks
target/release/quorum-bench --out docs/benchmarks/results.md "$@"
