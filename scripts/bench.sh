#!/usr/bin/env bash
# Benchmarks quorum-hsm against SoftHSM2 (speed and attacks), three times.
# Writes docs/benchmarks/results.md (report from run 1), docs/benchmarks/runs/
# (raw numbers) and docs/benchmarks/comparison.svg (the chart).
# Needs: cargo, python3, softhsm2 (sudo apt install softhsm2).
# Extra arguments go to quorum-bench, e.g. --iterations 500 or --softhsm <module.so>.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-pkcs11 -p quorum-bench
mkdir -p docs/benchmarks/runs
for i in 1 2 3; do
  echo "run $i of 3..." >&2
  out=()
  [ "$i" = 1 ] && out=(--out docs/benchmarks/results.md)
  target/release/quorum-bench --data "docs/benchmarks/runs/run$i.tsv" "${out[@]}" "$@" >/dev/null
done
tools/plot_benchmarks.py docs/benchmarks/runs/run*.tsv > docs/benchmarks/comparison.svg
echo "wrote docs/benchmarks/results.md, docs/benchmarks/runs/ and docs/benchmarks/comparison.svg" >&2
