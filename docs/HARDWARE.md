# Running the HSM on a real chip (RP2350 boards)

The same HSM code that runs in the emulator also runs on a **Raspberry Pi
Pico 2** or a **Seeed Studio XIAO RP2350**: two small, cheap boards built
around the same **RP2350** chip. The board plugs into
USB and shows up as a serial port; the `quorum` tool talks to it exactly as
it talks to the emulator.

> **Status:** the firmware builds and is checked on every push, and all of
> its logic is tested on the computer with a simulated flash chip (including
> a power cut at every byte of every save). It has **not been run on a
> physical board yet**: that's the next step once the board arrives. Expect
> small fixes then.

## What to buy

| Item | Why | Notes |
|---|---|---|
| **Raspberry Pi Pico 2** *or* **Seeed Studio XIAO RP2350** | The board (RP2350 chip) | Either works; each has its own firmware file. Pico 2: 4 MB flash, micro-USB. XIAO: 2 MB flash (plenty: the firmware is ~128 KB), USB-C, smaller. Avoid the Pico 2 **W**: its LED is wired through the wireless chip, so the status LED won't work. |
| **USB cable that carries data** | Power and connection | Micro-USB for the Pico 2, USB-C for the XIAO. Many cheap cables are charge-only and the board won't show up. |
| *(optional)* **Raspberry Pi Debug Probe** | Step-by-step debugging over SWD | Not needed to use the HSM. Note that secure boot can switch debugging off for good. |

## How it fits together

```
 your computer                                 RP2350 board
 ─────────────                                 ────────────
 quorum / quorum-pkcs11                        firmware/rp2350   moves bytes only:
   │  QUORUM_HSM_SERIAL=/dev/ttyACM0             USB serial, flash, random numbers, LED
   │                                              │
   └── USB serial: [length][frame] ────────────► quorum-device    blank → provisioned → ready;
                                                  │                saves state in 2 flash slots
                                                 quorum-core      every security decision
```

| Piece | What it does | Tested on the computer? |
|---|---|---|
| `crates/core` | All security decisions (unchanged from the emulator) | Yes: unit tests, glitch tests, fuzzing |
| `crates/device` | Boot, provisioning, saving to flash, cutting the USB byte stream into requests | Yes: a simulated flash chip with power cuts, plus a fuzz target |
| `firmware/rp2350` | Connects the above to the chip: USB, flash, the hardware random number generator, the LED | Built and linted on every push; needs the board to run |

`quorum-emulator board` runs `crates/device` on a simulated flash chip
behind a pseudo serial port, so the whole board experience can be tried
without the board: `./scripts/demo-board.sh`.

## 1. Build the firmware

```bash
./scripts/firmware.sh
```

This writes one firmware per board into `target/firmware/` (about 128 KB
each):

| Board | File to use |
|---|---|
| Raspberry Pi Pico 2 | `quorum-firmware-pico2.uf2` |
| Seeed Studio XIAO RP2350 | `quorum-firmware-xiao.uf2` |

**Use the file for your board.** The HSM keeps its state in the last 64 KB
of flash, and the two boards have different amounts of flash. GitHub
Actions also builds both on every push: open a run, and download
**quorum-firmware** from its "Artifacts".

## 2. Put it on the board

1. Hold down the **BOOTSEL** button while plugging the board in (on the
   XIAO it's the button marked **B**).
2. A USB drive called **RP2350** appears.
3. Copy your board's `.uf2` file onto it. The board restarts into the HSM.

Or, with [picotool](https://github.com/raspberrypi/picotool) (version 2 or
later): `picotool load -x target/firmware/quorum-firmware-pico2.elf` (board
in BOOTSEL mode). From `firmware/rp2350`, `cargo run --release` does the
same (add `--features xiao-rp2350` for the XIAO).

**The LED** (the green one on the Pico 2, the small yellow user LED on the
XIAO) shows what the HSM is doing:

| LED | Meaning |
|---|---|
| Slow blink | **Blank**: waiting to be provisioned |
| Steady on | **Ready** |
| Fast blink | **Broken**: flash is damaged or a save failed; every request is refused |

(On the XIAO we assume the user LED lights up when its pin is low, as on
earlier XIAO boards. If "ready" shows as steady *off*, that assumption was
wrong: a one-line fix in `firmware/rp2350/src/main.rs`.)

## 3. Find its serial port

- **Linux:** `/dev/ttyACM0` (check with `ls /dev/ttyACM*`). If you get
  "permission denied", add yourself to the `dialout` group
  (`sudo usermod -aG dialout $USER`, then log out and in).
- **macOS:** `/dev/cu.usbmodem…` (check with `ls /dev/cu.usbmodem*`).

```bash
export QUORUM_HSM_SERIAL=/dev/ttyACM0
```

With this set, `quorum` (and the PKCS#11 adapter) talk to the board instead of
the emulator.

## 4. Provision it (once)

A new board is blank and refuses everything until it's provisioned:

```bash
Q=target/release/quorum
$Q admin new --out alice
$Q admin new --out bob
$Q provision --pin 123456 --admin alice.pub --admin bob.pub --threshold 2 --out hsm.id
```

The board picks its own serial number and identity key using its hardware
random number generator, saves its first state, and the LED goes steady.
`hsm.id` is the identity key to give to shops.

**Provisioning works once.** Afterwards `provision` is refused, so nobody can
swap in their own admins later. Damaged flash doesn't make the board blank
again either: it refuses everything instead, so damage can never be used to
reset the PIN tries, the budgets or the admins.

From here on, everything in the main README works the same way: admins create
agent keys, agents act, shops verify, the audit log is pulled. Try unplugging
the board and plugging it back in: keys, rules and money already spent are
all still there.

## 5. Starting over (wipes all keys)

To return a board to blank, erase its state area (the last 64 KB of flash)
with the board in BOOTSEL mode, using picotool 2:

```bash
picotool erase -r 0x103F0000 0x10400000   # Pico 2 (4 MB)
picotool erase -r 0x101F0000 0x10200000   # XIAO RP2350 (2 MB)
```

This destroys every key on it. Afterwards it's a new HSM with a new identity
key, so shops that trusted the old one won't trust it.

## 6. Secure boot (only run *your* firmware) ⚠️ cannot be undone

Without secure boot, anyone holding the board can put different firmware on
it, for example one that ignores the rules. **Secure boot** makes the RP2350
refuse to run any firmware that isn't signed with your key. Your key's
fingerprint is burned into the chip's **OTP** (one-time-programmable) memory.

> ⚠️ **Read this first.** OTP bits can be set but never cleared.
> - If you lose the private key, **the board can never be updated again**.
> - If the wrong values are burned, **the board can be ruined for good**.
> - Do this on a board you can afford to lose, after the unsigned firmware
>   works. None of the scripts in this repository burn OTP; these are
>   manual steps on purpose.

```bash
# 1. Make a signing key (keep private.pem offline and backed up)
openssl ecparam -name secp256k1 -genkey -out private.pem

# 2. Sign the firmware; picotool also writes otp.json (what to burn)
picotool seal --sign --hash target/firmware/quorum-firmware-pico2.elf \
  quorum-firmware-signed.elf private.pem otp.json

# 3. Check that the signed firmware works BEFORE turning secure boot on
#    (a chip without secure boot also runs signed firmware)
picotool load -x quorum-firmware-signed.elf

# 4. Read otp.json. It holds your key's fingerprint and the setting that
#    turns secure boot on. Then burn it (THIS IS PERMANENT):
picotool otp load otp.json
```

After this, unsigned firmware (or firmware signed with another key) doesn't
boot. Other OTP settings worth reading about in the RP2350 datasheet before
going further:

- **`CRIT1.DEBUG_DISABLE`**: switches off the debug port, so nobody can read
  the RAM or stop the chip with a debug probe.
- **`CRIT1.GLITCH_DETECTOR_ENABLE`** and **`GLITCH_DETECTOR_SENS`**: turn on
  the chip's own glitch sensors. They complement the HSM's double-checked
  decisions (milestone 4), which handle one glitch; the sensors help with the
  rest.
- **Anti-rollback** (`picotool seal --rollback`): stops someone putting an
  older, correctly signed firmware with a known bug back on the board.

## 7. Testing on the board: the results we're looking for

Work through these in order. Each row is a pass/fail check; write down what
you see (and the timings) so we can put them in the README.

| # | Do this | Pass if | What it proves |
|---|---|---|---|
| 1 | Flash the `.uf2` | The board reboots; the LED **blinks slowly** | The firmware boots on real silicon; flash state area starts blank |
| 2 | Plug it in, `ls /dev/ttyACM*` | A new serial port appears | USB works |
| 3 | `quorum keys` | `DENIED … this device is blank` | The board answers over USB with the real protocol |
| 4 | `quorum provision --pin 123456 --admin alice.pub --admin bob.pub --threshold 2 --out hsm.id` | Prints a serial and identity key; LED goes **steady** | Hardware random numbers, signing and the first flash save work |
| 5 | Run `provision` again | `DENIED … already set up` | Provisioning really happens only once |
| 6 | Create an agent key with a $30 budget (2 admins), spend $20 (same commands as `scripts/demo-board.sh`) | Approved; `quorum verify` says VALID | The whole design on the chip; signatures made on the chip check out on the computer |
| 7 | **Unplug and replug**, then try to spend $15, then $10 | $15 refused (over budget), $10 approved | Keys and counters survive power loss: flash saves work |
| 8 | Unplug the board **in the middle of** a payment, several times (a loop of payments makes this easy) | After replugging, the board is "ready" and its spending never goes *down* | Real power cuts during flash writes are safe |
| 9 | `quorum audit pull`, `checkpoint`, `verify` | VALID | The audit log works on the chip |
| 10 | Time a payment: `time quorum act …` | Note the number | Real-chip speed (expect milliseconds, not the emulator's 0.24 ms: signing on a 150 MHz chip and erasing flash are slower) |

Once these pass, the next steps are measuring speed properly on the board,
then milestone 6 (encrypted, rollback-proof state) and, on a board you can
spare, secure boot.

## What these boards do *not* protect yet

The RP2350 is a good chip for learning and for a real prototype, but this is
not yet a certified HSM. Most importantly:

- **The flash chip is a separate part on the board** (on both the Pico 2
  and the XIAO). Someone holding the
  board can read it with a clip-on programmer, and the state on it (keys,
  PIN, counters) is **not encrypted yet**.
- **Rollback.** For the same reason, someone could save a copy of the flash
  and put it back later, undoing spending to reset a budget. The hash
  protects against damage, not against putting back an old, genuine copy.
- **Power analysis.** Measuring the chip's power use while it signs can leak
  keys; the signing code has no countermeasures for that.

The planned fix for the first two (milestone 6) is to **encrypt and
authenticate the saved state with a key that lives in the RP2350's OTP**,
readable only by our signed firmware, and to **count saves in OTP** so an old
copy is recognised. Until then, treat a lost board as a lost key.
