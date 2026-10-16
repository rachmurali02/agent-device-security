/* Raspberry Pi Pico 2 (RP2350, 4 MB flash, 520 KB RAM).
 *
 * The last 64 KB of flash are kept out of the program: the HSM's state lives
 * there (two 8 KB slots at 0x3F0000; see src/main.rs, STATE_BASE). */
MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K - 64K
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

SECTIONS {
    /* The boot ROM looks in the first 4 KB of flash for the IMAGE_DEF block
     * that says "this is a valid program" (and, with secure boot, where the
     * signature is). */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

/* Program code starts after the boot block. */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* Entries that `picotool info` shows. */
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* After everything else, so that `picotool seal` can append the hash
     * and signature that secure boot checks. */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
