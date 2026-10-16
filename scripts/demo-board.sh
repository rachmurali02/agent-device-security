#!/usr/bin/env bash
# Board demo: the life of a brand-new HSM board, without needing the board.
#
# `quorum-emulator board` runs the real firmware logic (crate quorum-device)
# on a simulated flash chip, reached over a pseudo serial port: the same way
# the `quorum` tool talks to a real Pico 2 over USB. Swap the pseudo port for
# /dev/ttyACM0 and the same commands drive the real board (docs/HARDWARE.md).
# Needs: cargo.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-emulator -p quorum-cli

WORK=$(mktemp -d)
EMU=target/release/quorum-emulator
Q=target/release/quorum
export QUORUM_PIN=123456
BOARD_PID=

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
expect_denied() {
  if "$@"; then echo "UNEXPECTED: that should have been refused" >&2; exit 1; fi
}
# "Plugs in" the board: starts it on its flash file and finds its serial port.
plug_in() {
  rm -f "$WORK/port"
  $EMU board --flash "$WORK/flash.bin" --pty >"$WORK/port" 2>>"$WORK/board.log" &
  BOARD_PID=$!
  for _ in $(seq 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
  export QUORUM_HSM_SERIAL=$(cat "$WORK/port")
  echo "   board is on serial port $QUORUM_HSM_SERIAL"
}
unplug() { kill "$BOARD_PID"; wait "$BOARD_PID" 2>/dev/null || true; }
trap 'kill $BOARD_PID 2>/dev/null; rm -rf "$WORK"' EXIT

step "1. A brand-new board is plugged in: it is blank and refuses to do anything"
plug_in
expect_denied $Q keys

step "2. Provisioning: set the PIN and two admins (both must sign off)"
for who in alice bob; do $Q admin new --out "$WORK/$who" >/dev/null; done
$Q provision --pin "$QUORUM_PIN" --admin "$WORK/alice.pub" --admin "$WORK/bob.pub" \
  --threshold 2 --out "$WORK/hsm.id"

step "3. Provisioning again (say, to swap in the attacker's admins) is refused"
$Q admin new --out "$WORK/mallory" >/dev/null
expect_denied $Q provision --pin 0000 --admin "$WORK/mallory.pub" --threshold 1

step "4. Alice and Bob create an agent key with a \$30 budget"
$Q admin propose-create --label shopping-agent --allow payment --max-amount 20 --budget 30 --confirm-above 20 \
  --out "$WORK/p1"
$Q admin approve --proposal "$WORK/p1" --as "$WORK/alice" --yes --out "$WORK/p1.alice" >/dev/null
$Q admin approve --proposal "$WORK/p1" --as "$WORK/bob" --yes --out "$WORK/p1.bob" >/dev/null
$Q admin submit --proposal "$WORK/p1" --approval "$WORK/p1.alice" --approval "$WORK/p1.bob" \
  --cert-out "$WORK/agent"

step "5. The agent spends \$20"
$Q act --key 1 --kind payment --to shop.example --amount 20 --out "$WORK/pay1"
$Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/pay1"

step "6. The board is unplugged and plugged back in"
unplug
plug_in
$Q identity

step "7. The key, its rules and the \$20 already spent all survived: \$15 more is over budget"
expect_denied $Q act --key 1 --kind payment --to shop.example --amount 15 --out "$WORK/x"
$Q act --key 1 --kind payment --to shop.example --amount 10 --out "$WORK/pay2"
$Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/pay2"

step "8. The audit log on the board recorded all of it"
$Q audit pull --log "$WORK/audit.log"
$Q audit checkpoint --out "$WORK/checkpoint"
$Q audit verify --hsm-identity "$WORK/hsm.id" --log "$WORK/audit.log" --checkpoint "$WORK/checkpoint"

step "Done: the board went blank -> provisioned -> in use, and kept its state across a restart"
