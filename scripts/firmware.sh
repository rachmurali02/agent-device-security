#!/usr/bin/env bash
# Builds the Pico 2 (RP2350) firmware and converts it for drag-and-drop.
# Output: target/firmware/quorum-firmware.elf and .uf2
# Flashing: see docs/HARDWARE.md.
set -euo pipefail

cd "$(dirname "$0")/.."
(cd firmware/rp2350 && cargo build --release --locked)
mkdir -p target/firmware
cp firmware/rp2350/target/thumbv8m.main-none-eabihf/release/quorum-firmware \
  target/firmware/quorum-firmware.elf
tools/elf2uf2.py target/firmware/quorum-firmware.elf target/firmware/quorum-firmware.uf2
