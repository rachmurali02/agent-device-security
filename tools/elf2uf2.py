#!/usr/bin/env python3
"""Converts the firmware (an ELF file) into a UF2 file for the Pico 2.

UF2 is the format the RP2350's boot ROM accepts by drag-and-drop: hold the
BOOTSEL button while plugging the board in, it appears as a USB drive, and
copying a .uf2 file onto it flashes the firmware.

Only the Python standard library is used. Usage:
    tools/elf2uf2.py <firmware.elf> <firmware.uf2> [flash size in MB, default 4]
"""

import struct
import sys

FAMILY_RP2350_ARM_S = 0xE48BFF59  # RP2350, Arm cores, secure mode
FLASH_START = 0x10000000
STATE_AREA = 64 * 1024  # the last 64 KB hold the HSM's state, not the program
PAGE = 256

UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000
PT_LOAD = 1


def flash_pages(elf: bytes, flash_end: int) -> dict[int, bytearray]:
    """The 256-byte flash pages the program occupies, keyed by address."""
    if elf[:4] != b"\x7fELF" or elf[4] != 1 or elf[5] != 1:
        sys.exit("not a 32-bit little-endian ELF file")
    phoff, = struct.unpack_from("<I", elf, 0x1C)
    phentsize, phnum = struct.unpack_from("<HH", elf, 0x2A)
    pages: dict[int, bytearray] = {}
    for i in range(phnum):
        p_type, p_offset, _vaddr, p_paddr, p_filesz, _memsz, _flags, _align = (
            struct.unpack_from("<8I", elf, phoff + i * phentsize)
        )
        if p_type != PT_LOAD or p_filesz == 0:
            continue
        # The load address (p_paddr) is where the bytes live in flash; data
        # that runs from RAM is copied there at start-up.
        if not (FLASH_START <= p_paddr and p_paddr + p_filesz <= flash_end):
            sys.exit(f"segment at {p_paddr:#x} is outside the program's flash area")
        data = elf[p_offset : p_offset + p_filesz]
        for n, byte in enumerate(data):
            addr = p_paddr + n
            page = pages.setdefault(addr - addr % PAGE, bytearray(PAGE))
            page[addr % PAGE] = byte
    return pages


def uf2(pages: dict[int, bytearray]) -> bytes:
    out = bytearray()
    addrs = sorted(pages)
    for n, addr in enumerate(addrs):
        header = struct.pack(
            "<8I",
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_FLAG_FAMILY_ID_PRESENT,
            addr,
            PAGE,
            n,
            len(addrs),
            FAMILY_RP2350_ARM_S,
        )
        block = header + bytes(pages[addr]) + bytes(476 - PAGE) + struct.pack("<I", UF2_MAGIC_END)
        assert len(block) == 512
        out += block
    return bytes(out)


def main() -> None:
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    flash_mb = int(sys.argv[3]) if len(sys.argv) == 4 else 4
    flash_end = FLASH_START + flash_mb * 1024 * 1024 - STATE_AREA
    with open(sys.argv[1], "rb") as f:
        pages = flash_pages(f.read(), flash_end)
    if not pages:
        sys.exit("no loadable segments")
    if min(pages) != FLASH_START:
        sys.exit("the program does not start at the beginning of flash")
    with open(sys.argv[2], "wb") as f:
        f.write(uf2(pages))
    size = (max(pages) + PAGE - FLASH_START) // 1024
    print(f"wrote {sys.argv[2]}: {len(pages)} blocks, {size} KB of flash")


if __name__ == "__main__":
    main()
