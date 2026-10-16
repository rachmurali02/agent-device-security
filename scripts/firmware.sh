#!/usr/bin/env bash
# Builds the HSM firmware for both supported RP2350 boards and converts it
# for drag-and-drop:
#   target/firmware/quorum-firmware-pico2.{elf,uf2}  Raspberry Pi Pico 2 (4 MB flash)
#   target/firmware/quorum-firmware-xiao.{elf,uf2}   Seeed Studio XIAO RP2350 (2 MB flash)
# Flashing: see docs/HARDWARE.md.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p target/firmware
build() { # <name> <flash MB> [cargo args...]
  local name=$1 mb=$2; shift 2
  (cd firmware/rp2350 && cargo build --release --locked "$@")
  cp firmware/rp2350/target/thumbv8m.main-none-eabihf/release/quorum-firmware \
    "target/firmware/quorum-firmware-$name.elf"
  tools/elf2uf2.py "target/firmware/quorum-firmware-$name.elf" \
    "target/firmware/quorum-firmware-$name.uf2" "$mb"
}
build pico2 4
build xiao 2 --features xiao-rp2350
