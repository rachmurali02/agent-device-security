#!/usr/bin/env bash
# Milestone 2 demo: an AI shopping agent whose key is guarded by rules that
# live inside the HSM. Needs: cargo, pkcs11-tool (OpenSC).
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-emulator -p quorum-pkcs11 -p quorum-cli

WORK=$(mktemp -d)
EMU=target/release/quorum-emulator
Q=target/release/quorum
export QUORUM_HSM_SOCKET=$WORK/hsm.sock
export QUORUM_PIN=123456

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
# Runs a command that the HSM is supposed to refuse.
expect_denied() {
  if "$@"; then echo "UNEXPECTED: that should have been refused" >&2; exit 1; fi
}

step "Set up: a new HSM, switched on"
$EMU init --state "$WORK/hsm.state" --pin "$QUORUM_PIN"
$EMU serve --state "$WORK/hsm.state" --socket "$QUORUM_HSM_SOCKET" 2>"$WORK/hsm.log" &
EMU_PID=$!
trap 'kill $EMU_PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 50); do [ -S "$QUORUM_HSM_SOCKET" ] && break; sleep 0.1; done

step "The user sets up their phone as a confirmation device"
$Q confirmer new --out "$WORK/phone"

step "The user gives their shopping agent a key, with rules"
# Payments and messages only. At most \$50 per payment, \$60 in total.
# Anything over \$20 needs the user to approve it on their phone.
$Q agent-key create --label shopping-agent \
  --allow payment,send_message \
  --max-amount 50 --budget 60 --confirm-above 20 \
  --confirmer "$WORK/phone.pub" | tee "$WORK/key.txt"
PUB=$(awk '/^public key:/ {print $3}' "$WORK/key.txt")

step "1. Agent buys a \$15 coffee: within the rules, no approval needed"
$Q act --key 1 --kind payment --to coffee-shop.example --amount 15 --out "$WORK/coffee"

step "   The coffee shop checks the signed action (no HSM needed)"
$Q verify --public-key "$PUB" --signed "$WORK/coffee"

step "2. Agent tries to book a \$35 flight on its own: needs the user's OK"
expect_denied $Q act --key 1 --kind payment --to airline.example --amount 35 --out "$WORK/flight"

step "   Same flight, this time the user approves on their phone"
$Q act --key 1 --kind payment --to airline.example --amount 35 \
  --confirm-with "$WORK/phone" --yes --out "$WORK/flight"
$Q verify --public-key "$PUB" --signed "$WORK/flight"

step "3. Agent tries an \$80 payment: over the per-payment limit, even with approval"
expect_denied $Q act --key 1 --kind payment --to tv-store.example --amount 80 \
  --confirm-with "$WORK/phone" --yes --out "$WORK/tv"

step "4. Agent tries to delete the user's photos: not an allowed kind of action"
expect_denied $Q act --key 1 --kind delete_data --to photos --out "$WORK/delete"

step "5. Agent tries another \$15 payment: would go over the \$60 budget (\$50 used)"
expect_denied $Q act --key 1 --kind payment --to coffee-shop.example --amount 15 --out "$WORK/more"

step "6. An attacker on the computer tries to make the agent key sign raw bytes"
echo "QHSM-ACTION forged: pay \$9999 to attacker" > "$WORK/forged.txt"
expect_denied pkcs11-tool --module "$PWD/target/release/libquorum_pkcs11.so" \
  --login --pin "$QUORUM_PIN" --sign -m EDDSA --id 00000001 \
  -i "$WORK/forged.txt" -o "$WORK/forged.sig"

step "7. Someone edits a signed action after the fact: verification fails"
cp "$WORK/coffee.statement" "$WORK/edited.statement"
cp "$WORK/coffee.sig" "$WORK/edited.sig"
# Byte 40 is the action kind: turn the payment into something else.
printf '\x04' | dd of="$WORK/edited.statement" bs=1 seek=40 conv=notrunc status=none
expect_denied $Q verify --public-key "$PUB" --signed "$WORK/edited"

step "Where the key stands now"
$Q agent-key show --key 1

step "What the HSM saw (commands and results, never secrets)"
cat "$WORK/hsm.log"

printf '\n\033[1mDemo finished: every action was approved or refused exactly as the rules say.\033[0m\n'
