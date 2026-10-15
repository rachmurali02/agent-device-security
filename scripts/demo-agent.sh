#!/usr/bin/env bash
# Agent demo: an AI shopping agent whose key is guarded by rules inside the
# HSM. Creating the key, changing its rules and changing the admins all need
# sign-off from 2 of 3 admins; every payment answers a shop's one-time
# request; and everything lands in a tamper-evident audit log.
# Needs: cargo, pkcs11-tool (OpenSC).
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-emulator -p quorum-pkcs11 -p quorum-cli

WORK=$(mktemp -d)
EMU=target/release/quorum-emulator
Q=target/release/quorum
export QUORUM_HSM_SOCKET=$WORK/hsm.sock
export QUORUM_PIN=123456

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
# Runs a command that is supposed to be refused.
expect_denied() {
  if "$@"; then echo "UNEXPECTED: that should have been refused" >&2; exit 1; fi
}

step "Factory: three admins (Alice, Bob, Carol); any 2 must sign off on agent keys"
for who in alice bob carol; do $Q admin new --out "$WORK/$who" >/dev/null; done
$EMU init --state "$WORK/hsm.state" --pin "$QUORUM_PIN" \
  --admin "$WORK/alice.pub" --admin "$WORK/bob.pub" --admin "$WORK/carol.pub" --threshold 2
$EMU serve --state "$WORK/hsm.state" --socket "$QUORUM_HSM_SOCKET" 2>"$WORK/hsm.log" &
EMU_PID=$!
trap 'kill $EMU_PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 50); do [ -S "$QUORUM_HSM_SOCKET" ] && break; sleep 0.1; done

step "The shop saves the HSM's identity key: the one thing it needs to trust"
$Q identity --out "$WORK/hsm.id"

step "The user sets up their phone as a confirmation device"
$Q confirmer new --out "$WORK/phone"

RULES=(--label shopping-agent --allow payment,send_message
       --max-amount 50 --budget 60 --confirm-above 20
       --confirmer "$WORK/phone.pub" --require-request)

step "1. Someone with only the PIN and one admin tries to create an agent key"
$Q admin propose-create "${RULES[@]}" --out "$WORK/p1"
$Q admin approve --proposal "$WORK/p1" --as "$WORK/alice" --yes --out "$WORK/p1.alice"
expect_denied $Q admin submit --proposal "$WORK/p1" --approval "$WORK/p1.alice"

step "2. Proper sign-off: Alice and Bob each review the exact rules and approve"
$Q admin propose-create "${RULES[@]}" --out "$WORK/p2"
$Q admin approve --proposal "$WORK/p2" --as "$WORK/alice" --yes --out "$WORK/p2.alice"
$Q admin approve --proposal "$WORK/p2" --as "$WORK/bob"   --yes --out "$WORK/p2.bob"
$Q admin submit --proposal "$WORK/p2" --approval "$WORK/p2.alice" --approval "$WORK/p2.bob" \
  --cert-out "$WORK/agent"

step "3. Agent buys a \$15 coffee, answering the shop's one-time payment request"
$Q shop request --out "$WORK/coffee.req"
$Q act --key 1 --kind payment --to coffee-shop.example --amount 15 \
  --request "$WORK/coffee.req" --out "$WORK/coffee"

step "   The shop checks it: HSM identity -> birth certificate -> signed action -> its request"
$Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/coffee" \
  --request "$WORK/coffee.req"

step "4. Someone replays the same signed payment to the shop: refused"
expect_denied $Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" \
  --signed "$WORK/coffee" --request "$WORK/coffee.req"

step "5. Agent tries to pay without a shop's request: the HSM refuses (rule)"
expect_denied $Q act --key 1 --kind payment --to coffee-shop.example --amount 5 --out "$WORK/x"

step "6. A \$35 flight needs the user's OK on their phone"
$Q shop request --out "$WORK/flight.req"
expect_denied $Q act --key 1 --kind payment --to airline.example --amount 35 \
  --request "$WORK/flight.req" --out "$WORK/flight"
$Q act --key 1 --kind payment --to airline.example --amount 35 --request "$WORK/flight.req" \
  --confirm-with "$WORK/phone" --yes --out "$WORK/flight"
$Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/flight" \
  --request "$WORK/flight.req"

step "7. A payment arrives after the shop's request expired: the shop refuses"
$Q shop request --valid-for 1 --out "$WORK/snack.req"
$Q act --key 1 --kind payment --to snack-bar.example --amount 5 \
  --request "$WORK/snack.req" --out "$WORK/snack"
sleep 2
expect_denied $Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" \
  --signed "$WORK/snack" --request "$WORK/snack.req"

step "8. Rule checks: \$80 (over the limit), deleting photos (not allowed), \$15 (over budget)"
$Q shop request --out "$WORK/r8.req"
expect_denied $Q act --key 1 --kind payment --to tv-store.example --amount 80 \
  --request "$WORK/r8.req" --confirm-with "$WORK/phone" --yes --out "$WORK/x"
expect_denied $Q act --key 1 --kind delete_data --to photos --request "$WORK/r8.req" --out "$WORK/x"
expect_denied $Q act --key 1 --kind payment --to coffee-shop.example --amount 15 \
  --request "$WORK/r8.req" --out "$WORK/x"

step "9. An attacker with the PIN tries to sign raw bytes, then to delete the key"
MODULE=$PWD/target/release/libquorum_pkcs11.so
echo "pay \$9999 to attacker" > "$WORK/forged.txt"
expect_denied pkcs11-tool --module "$MODULE" --login --pin "$QUORUM_PIN" \
  --sign -m EDDSA --id 00000001 -i "$WORK/forged.txt" -o "$WORK/forged.sig"
expect_denied pkcs11-tool --module "$MODULE" --login --pin "$QUORUM_PIN" \
  --delete-object --type privkey --id 00000001

step "10. Someone edits a signed action afterwards: the check fails"
cp "$WORK/coffee.statement" "$WORK/edited.statement"; cp "$WORK/coffee.sig" "$WORK/edited.sig"
printf '\x04' | dd of="$WORK/edited.statement" bs=1 seek=40 conv=notrunc status=none
expect_denied $Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/edited"

step "11. An audit collector copies the HSM's log out (it holds at most 64 entries)"
$Q audit pull --log "$WORK/audit.log"

step "12. Changing the rules: \$10 per payment from now on, \$100 in total"
NEW_RULES=(--allow payment,send_message --max-amount 10 --budget 100 --confirm-above 20
           --confirmer "$WORK/phone.pub" --require-request)
$Q admin propose-update --key 1 "${NEW_RULES[@]}" --out "$WORK/p3"
$Q admin approve --proposal "$WORK/p3" --as "$WORK/alice" --yes --out "$WORK/p3.alice"
echo "   ...with only Alice's approval:"
expect_denied $Q admin submit --proposal "$WORK/p3" --approval "$WORK/p3.alice"
$Q admin propose-update --key 1 "${NEW_RULES[@]}" --out "$WORK/p4" >/dev/null
$Q admin approve --proposal "$WORK/p4" --as "$WORK/alice" --yes --out "$WORK/p4.alice" >/dev/null
$Q admin approve --proposal "$WORK/p4" --as "$WORK/carol" --yes --out "$WORK/p4.carol"
$Q admin submit --proposal "$WORK/p4" --approval "$WORK/p4.alice" --approval "$WORK/p4.carol" \
  --cert-out "$WORK/agent-v2"

step "13. A \$10 payment under the new rules: the shop needs the new certificate"
$Q shop request --out "$WORK/lunch.req"
$Q act --key 1 --kind payment --to cafe.example --amount 10 --request "$WORK/lunch.req" --out "$WORK/lunch"
echo "   ...a shop still holding the old certificate notices the rules changed:"
expect_denied $Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent" --signed "$WORK/lunch"
$Q verify --hsm-identity "$WORK/hsm.id" --cert "$WORK/agent-v2" --signed "$WORK/lunch" \
  --request "$WORK/lunch.req"

step "14. Bob leaves and Dave joins; the current admins (Alice and Bob) approve the handover"
$Q admin new --out "$WORK/dave" >/dev/null
$Q admin propose-admins --admin "$WORK/alice.pub" --admin "$WORK/carol.pub" --admin "$WORK/dave.pub" \
  --threshold 2 --out "$WORK/p5"
$Q admin approve --proposal "$WORK/p5" --as "$WORK/alice" --yes --out "$WORK/p5.alice" >/dev/null
$Q admin approve --proposal "$WORK/p5" --as "$WORK/bob" --yes --out "$WORK/p5.bob" >/dev/null
$Q admin submit --proposal "$WORK/p5" --approval "$WORK/p5.alice" --approval "$WORK/p5.bob"
echo "   ...Bob's approval no longer counts:"
$Q admin propose-delete --key 1 --out "$WORK/p6" >/dev/null
$Q admin approve --proposal "$WORK/p6" --as "$WORK/bob" --yes --out "$WORK/p6.bob" >/dev/null
$Q admin approve --proposal "$WORK/p6" --as "$WORK/dave" --yes --out "$WORK/p6.dave" >/dev/null
expect_denied $Q admin submit --proposal "$WORK/p6" --approval "$WORK/p6.bob" --approval "$WORK/p6.dave"

step "15. The audit log: copy it out, get a signed checkpoint, and check it"
$Q audit pull --log "$WORK/audit.log"
$Q audit checkpoint --out "$WORK/checkpoint"
$Q audit verify --hsm-identity "$WORK/hsm.id" --log "$WORK/audit.log" --checkpoint "$WORK/checkpoint"
echo "   What the log says (refusals included):"
$Q audit show --log "$WORK/audit.log" | grep -E "REFUSED|rules changed|admins replaced|wrong PIN" | sed 's/^/   /'

step "16. Someone hides the \$80 attempt by erasing its amount: detected"
SEQ=$($Q audit show --log "$WORK/audit.log" | grep -m1 'REFUSED (\$80' | sed 's/^#\([0-9]*\).*/\1/')
cp "$WORK/audit.log" "$WORK/edited.log"
printf '\0\0\0\0\0\0\0\0' | dd of="$WORK/edited.log" bs=1 seek=$(( (SEQ-1)*54 + 14 )) conv=notrunc status=none
expect_denied $Q audit verify --hsm-identity "$WORK/hsm.id" --log "$WORK/edited.log" --checkpoint "$WORK/checkpoint"

step "17. Someone deletes that entry instead: also detected"
{ head -c $(( (SEQ-1)*54 )) "$WORK/audit.log"; tail -c +$(( SEQ*54 + 1 )) "$WORK/audit.log"; } > "$WORK/cut.log"
expect_denied $Q audit verify --hsm-identity "$WORK/hsm.id" --log "$WORK/cut.log" --checkpoint "$WORK/checkpoint"

step "Where the key stands now"
$Q agent-key show --key 1

step "What the HSM saw (commands and results, never secrets)"
cat "$WORK/hsm.log"

printf '\n\033[1mDemo finished: every step was approved or refused exactly as the rules say.\033[0m\n'
