#!/usr/bin/env bash
# End-to-end demo: create an HSM, make a key, sign a message, and check the
# signature with OpenSSL. Needs: cargo, pkcs11-tool (OpenSC), openssl.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet -p quorum-emulator -p quorum-pkcs11

WORK=$(mktemp -d)
EMU=target/release/quorum-emulator
MODULE=$PWD/target/release/libquorum_pkcs11.so
export QUORUM_HSM_SOCKET=$WORK/hsm.sock
PIN=123456
P11="pkcs11-tool --module $MODULE"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "1. Create a brand-new HSM (like a factory would)"
$EMU init --state "$WORK/hsm.state" --pin $PIN

step "2. Turn it on"
$EMU serve --state "$WORK/hsm.state" --socket "$QUORUM_HSM_SOCKET" 2>"$WORK/hsm.log" &
EMU_PID=$!
trap 'kill $EMU_PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 50); do [ -S "$QUORUM_HSM_SOCKET" ] && break; sleep 0.1; done
$P11 --show-info

step "3. Ask the HSM to create a signing key (the private half never leaves it)"
$P11 --login --pin $PIN --keypairgen --key-type EC:edwards25519 --label agent-key --id 01

step "4. Ask the HSM to sign a message"
echo "agent action: send_email to=alice@example.com" > "$WORK/msg.txt"
$P11 --login --pin $PIN --sign -m EDDSA --id 01 -i "$WORK/msg.txt" -o "$WORK/msg.sig"

step "5. Check the signature with OpenSSL (separate software, no HSM involved)"
$P11 --read-object --type pubkey --id 01 -o "$WORK/pub.pem"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin -in "$WORK/msg.txt" -sigfile "$WORK/msg.sig"

step "6. Change the message (new recipient): the signature must now fail"
echo "agent action: send_email to=mallory@example.com" > "$WORK/msg.txt"
if openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin -in "$WORK/msg.txt" -sigfile "$WORK/msg.sig"; then
  echo "UNEXPECTED: tampered message verified" >&2; exit 1
fi

step "7. Try a wrong PIN: the HSM refuses and counts the attempt"
if $P11 --login --pin 000000 --list-objects 2>&1; then
  echo "UNEXPECTED: wrong PIN accepted" >&2; exit 1
fi
$P11 --list-token-slots | grep "token flags"

step "What the HSM saw (it logs commands, never secrets)"
cat "$WORK/hsm.log"

printf '\n\033[1mDemo finished: every check behaved as expected.\033[0m\n'
