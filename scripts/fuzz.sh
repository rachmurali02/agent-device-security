#!/usr/bin/env bash
# Runs every fuzz target for a while (default 60 seconds each).
# Needs a nightly compiler and cargo-fuzz:
#   rustup toolchain install nightly-2026-10-14
#   cargo +nightly-2026-10-14 install cargo-fuzz --locked
# Crashing inputs are saved under fuzz/artifacts/<target>/.
set -euo pipefail

cd "$(dirname "$0")/.."
SECONDS_EACH=${1:-60}
NIGHTLY=${NIGHTLY:-nightly-2026-10-14}
for t in wire_request state_load verifiers slot_file board hsm_commands; do
  echo "== $t ($SECONDS_EACH s)" >&2
  extra=()
  [ "$t" = hsm_commands ] && extra=(-max_len=2048)
  cargo +"$NIGHTLY" fuzz run -O "$t" -- -max_total_time="$SECONDS_EACH" "${extra[@]}" 2>&1 \
    | grep -E "^Done|SUMMARY|panicked" || true
done
