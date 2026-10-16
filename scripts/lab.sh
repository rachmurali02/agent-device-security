#!/usr/bin/env bash
# Experiments: performance under load and extra attack vectors.
# Writes docs/experiments/results.md (the report), lab.tsv (raw numbers) and
# load.svg (the chart). Takes about 3 minutes.
# Extra arguments go to quorum-lab, e.g. --seconds 5 --max-clients 128.
# Needs: cargo, python3.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-bench -p quorum-emulator
mkdir -p docs/experiments
target/release/quorum-lab all --out docs/experiments/results.md \
  --data docs/experiments/lab.tsv "$@"
tools/plot_load.py docs/experiments/lab.tsv > docs/experiments/load.svg
echo "wrote docs/experiments/results.md, lab.tsv and load.svg" >&2
