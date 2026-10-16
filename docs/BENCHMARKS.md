# Benchmarks: is enforcing rules inside the HSM the right approach?

**Short answer:** yes, for our threat (someone controls the computer and knows
the PIN). It's the only option tested that blocks the attacks: **8 of 8**,
against 1 of 8 for the conventional setup. With two-slot storage and glitch
double-checks, an agent action that is safely saved to disk takes about
**0.24–0.29 milliseconds**. That's about 75 µs more than the conventional setup keeping
its counters only in memory, and less than the conventional setup saving
them to disk.

![Benchmark comparison chart of quorum-hsm and SoftHSM2](benchmarks/comparison.svg)

*Bars show the median of three runs; the thin line spans the fastest to
slowest run. The same numbers are in the tables below.*

## What we compared

| Option | What it is | Where the rules run |
|---|---|---|
| **quorum-hsm** (this project) | Our HSM, running in the emulator | **Inside the HSM** |
| **SoftHSM2** | The standard open-source software HSM, used the usual way | On the computer, *in front of* the HSM |
| **No HSM** | The same Ed25519 maths, called directly | Nowhere (the floor: the fastest possible) |

To keep the comparison fair:

- **Same signature scheme everywhere** (Ed25519) and the same 64-byte message.
- **Same code drives both HSMs.** The benchmark talks PKCS#11 through the
  [`cryptoki`](https://crates.io/crates/cryptoki) library, so swapping HSMs
  means swapping one file path, nothing else.
- **Same rules.** The SoftHSM2 setup checks exactly the same rules, using our
  own rule code, so the only difference is *where* the check runs.
- **No logging** in our emulator during timing (printing to the screen slowed it down).
- **The audit log is included.** Our HSM keeps at most 64 log entries and
  stops when full, so the benchmark acts as an audit collector: it copies the
  log out every 16 requests, and that time is counted.

## How to run it

```bash
./scripts/bench.sh                      # needs softhsm2 (sudo apt install softhsm2)
```

This runs the benchmark three times, then writes the report
([`docs/benchmarks/results.md`](benchmarks/results.md)), the raw numbers
([`docs/benchmarks/runs/`](benchmarks/runs/)) and the chart
([`docs/benchmarks/comparison.svg`](benchmarks/comparison.svg)). To test
another HSM, such as a real YubiHSM 2, point the benchmark at its PKCS#11 library:

```bash
target/release/quorum-bench --softhsm /path/to/other_pkcs11.so
```

## Results

Machine: Intel Xeon @ 2.10GHz, 4 cores, cloud VM. "Median" is the typical
time for one operation. The ranges cover all three runs. Full output from one
run is in [`benchmarks/results.md`](benchmarks/results.md); raw numbers from
all three are in [`benchmarks/runs/`](benchmarks/runs/).

### Speed

| What | quorum-hsm | SoftHSM2 | No HSM |
|---|---:|---:|---:|
| Sign a message (median) | **113–133 µs** | 194–199 µs | 17 µs |
| Create a key (median) | **0.43–0.62 ms** | 11.0–12.1 ms | n/a |
| Approve an agent action, saved safely to disk | **235–294 µs** | 429–446 µs ¹ | n/a |
| …with counters only in memory (SoftHSM2) / without waiting for the disk (ours, unsafe) | 100–110 µs | 205–214 µs ¹ | n/a |
| Approve an action that needs the user's OK | 536–571 µs | not possible ² | n/a |
| **Refuse** an action (the refusal is recorded and saved) | 164–198 µs | <1 µs, nothing recorded ¹ | n/a |
| Create an agent key with 2-of-3 sign-off + certificate, then delete it | 1.6–2.1 ms | not possible ² | n/a |
| Change an agent key's rules with 2-of-3 sign-off + new certificate | 0.81–1.05 ms | not possible ² | n/a |
| Receiver checks a signed action (no HSM needed) | 125 µs | n/a | n/a |
| Auditor checks a 1,000-entry log against a checkpoint (no HSM needed) | 228–246 µs | not possible ² | n/a |
| Signatures per second, 1 thread → 4 threads | ~8,600 → ~6,700 | ~5,000 → ~7,900 | n/a |
| Agent actions per second, 1 thread → 4 threads | ~2,700 → ~3,000 | n/a | n/a |

¹ The rules run on the computer, so these are the steps an attacker can skip (see below).
² SoftHSM2 has no way to do this inside the HSM.

### Security: attacks we actually ran

These aren't claims. The benchmark runs each attack and reports what happened,
and it fails if any attack ever gets through against quorum-hsm. The attacker
controls the computer and knows the PIN. All three runs gave the same result.

| Attack | quorum-hsm | SoftHSM2 + rules on the computer |
|---|---|---|
| Get a $9,999.99 payment signed when the limit is $1 | ✅ blocked | ❌ works: the attacker skips the rule check and signs |
| Keep spending after the $3 budget is used up | ✅ blocked after $3 | ❌ works: 10 of 10 signed |
| Create a new key with loose rules using only the PIN | ✅ blocked: needs 2 of 3 admins | ❌ works |
| Reset the budget by deleting and re-creating the key | ✅ blocked: needs admins | ❌ works: the counter is just a file |
| Read the private key out of the HSM | ✅ blocked | ✅ blocked |
| Fool a receiver about which rules approved a signature | ✅ blocked: the birth certificate proves it | ❌ works: nothing ties a key to its rules |
| **Loosen an existing key's rules using only the PIN** | ✅ blocked: needs 2 of 3 admins; the $3 budget still holds | ❌ works: the attacker edits the host's rules |
| **Erase the record of a refused attack** | ✅ blocked: editing or deleting the entry breaks the HSM-signed checkpoint | ❌ works: the log line is deleted and nothing can tell |

**quorum-hsm blocks 8 of 8. SoftHSM2 used the conventional way blocks 1 of 8.**
SoftHSM2 still protects the key itself; it just signs whatever it's asked to.

## What the numbers mean

1. **The rules are almost free.** Inside the core, approving an agent action
   takes 55 µs against 34 µs for a plain signature. Reading the action,
   checking every rule, building the statement and writing the audit entry
   add about **20 µs**. A refusal is even cheaper (11 µs), since nothing is signed.

2. **Saving safely to disk was the real cost, and two-slot storage cut it.**
   The HSM used to save by writing a new file and renaming it over the old
   one, which waits for the disk twice. Now the state file has two
   fixed-size slots, and each save overwrites the older slot in place and
   waits once. The file never changes size, so that wait doesn't have to
   flush any file-system bookkeeping either. If power is lost mid-save, the
   half-written slot fails its hash check and the other slot is used. A
   test cuts a save off at every single byte to prove this. This is how
   secure-chip firmware usually keeps state in flash.

3. **Refusals cost about two-thirds of an approval.** A refused action is
   written to the audit log and saved *before* the HSM answers, so there is
   no way to probe the rules without leaving a trace. Someone with the PIN
   can still make the HSM do a disk write per refusal; people without the
   PIN can't (see the README).

4. **Rare admin work is cheap.** Changing a key's rules with two admin
   signatures and a new certificate takes under a millisecond. An auditor
   can check a 1,000-entry log in about a quarter of a millisecond, on any
   computer.

5. **The conventional setup could save faster too.** Its counter file is
   appended to, so it grows, and every save has to update the file's size
   on disk as well. It could use the same two-slot trick. That wouldn't fix
   its security problems (the attack table), but it means the speed
   comparison above slightly flatters us on the "saved to disk" row.

6. **Crossing into the HSM costs more than the maths.** A signature takes
   17 µs on its own but about 110 µs through PKCS#11 and the socket. Our
   adapter also asks the HSM for its key list before every signature: one
   extra round trip that a small cache would remove.

7. **SoftHSM2 handles parallel requests better.** It gets faster with 4
   threads; we don't, because our HSM does one command at a time (like a
   single-core secure chip) and the adapter shares one connection.

8. **Key creation is much faster here** (about 0.5 ms against about 12 ms),
   mostly because SoftHSM2 encrypts and writes a separate file for every key.

### The disk-saving speed-up, measured

Same machine, same run: the benchmark runs one emulator with the old
storage next to the new one.

| What | Old: rewrite + rename | New: two slots | Faster by |
|---|---:|---:|---:|
| Approve an agent action, saved safely | 752–777 µs | 265–305 µs | **2.7×** |
| Refuse an action (recorded) | ~700 µs ³ | 172–194 µs | 3.9× |
| Action with the user's confirmation | ~1.0 ms ³ | 532–558 µs | 1.9× |
| Create a key | ~1.6 ms ³ | 0.37–0.51 ms | 3.4× |
| Change a key's rules (2 of 3 admins) | ~1.45 ms ³ | 0.66–0.89 ms | 1.8× |
| Agent actions per second (1 thread) | ~1,090 ³ | ~2,890 | 2.7× |

³ From the milestone 3 runs, which used the old storage; only the first row
was measured side by side in this run.

### The cost of glitch resistance (milestone 4)

Every decision that leads to a signature, a login or an admin change is now
made twice, by separate code. Same benchmark, before and after:

| What | Before | After | Why |
|---|---:|---:|---|
| Rule check for an agent action, inside the core | 55.2 µs | 54.9 µs | The second check is a few comparisons: too small to measure |
| Action with the user's confirmation | 535 µs | 567 µs | The phone's signature is checked twice (+~30 µs) |
| Create + delete an agent key | 1.59 ms | 1.88 ms | Admin signatures are checked twice for each of the two operations |
| Change a key's rules | 0.81 ms | 0.94 ms | Same reason, once |

Ordinary actions pay nothing measurable; the rare operations that involve
extra signatures pay for checking them twice.

### What changed since milestone 2

| What | Milestone 2 | Milestone 3 | + two-slot storage | Milestone 4 (+ double checks) | Milestone 5 (board port) |
|---|---:|---:|---:|---:|---:|
| Approve an agent action, saved safely | ~729 µs | ~821 µs | ~284 µs | ~242 µs ⁴ | **~242 µs** |
| Rule check inside the core | ~53 µs | ~55 µs | ~55 µs | ~55 µs | ~55 µs |
| Attacks blocked | 6 of 6 | 8 of 8 | 8 of 8 | 8 of 8 | **8 of 8** |

⁴ Lower than the column before it because the disk was faster in this run
(the old-storage row on the same disk also dropped ~10%), not because of
the code.

Milestone 5 moved the save-slot format into the core (so the emulator and
the board share it) and added the board firmware; the emulator's numbers
didn't change. Speed on the board itself will be measured once it arrives:
signing on a 150 MHz microcontroller and erasing flash will be much slower
than on a PC.

The audit log added about 10–15% to each action. Two-slot storage then took
away nearly two-thirds of the total. (The machine was restarted between some
of these runs, so treat differences under ~15% as noise.)

## Other kinds of HSM

These couldn't be measured here because they need hardware. The table compares
what each can do for *this* design. Capabilities are to the best of our
knowledge; check the vendor's documentation before relying on them.

| Option | Ed25519? | Can our rules run inside it? | What that means |
|---|---|---|---|
| Commercial HSMs that accept custom firmware (e.g. Thales Luna, Entrust nShield, Utimaco SDKs) | Yes | **Yes**, as custom code inside the HSM | The production version of this design; expensive |
| Cloud HSMs (e.g. AWS CloudHSM) | Varies | No custom code | Rules must run outside (the conventional setup) |
| YubiHSM 2 | Yes | No custom code; per-key permissions and an audit log | Better than plain SoftHSM2, but no amounts or budgets |
| TPM 2.0 chips | Usually not | Partly: built-in policies (require another signature, counters) | Could do "user must approve", but can't read a payment amount |
| Secure elements (e.g. ATECC608) | Usually not (P-256) | No, fixed functions | Good for storing a device's identity key, not for rules |
| ARM TrustZone (e.g. OP-TEE) | Yes, in software | **Yes**, as a trusted app | Our core can be ported (on the roadmap) |
| Secure microcontroller (e.g. Raspberry Pi RP2350) | Yes, in software | **Yes** | Our firmware for it is built (milestone 5, [`HARDWARE.md`](HARDWARE.md)); speed to be measured on the board |

Our benchmark tool works with anything that speaks PKCS#11. Running it on
real hardware is the way to fill in the speed column for these.

## Verdict

- **For security against a hacked computer:** the rules, the admin sign-off
  and the audit log must all live inside the HSM. The conventional setup can't
  stop an attacker who skips a check, edits the rules or deletes a log line.
  The attack table shows each of these directly.
- **For speed:** a fully checked, double-checked, logged and safely saved
  agent action takes about a quarter of a millisecond on this machine. That's tiny next to a person tapping
  "Approve" or a network payment.
- **For production:** run this same core on hardware that accepts custom code
  (a TEE, a secure microcontroller, or a commercial HSM with a firmware SDK).
  Fixed-function HSMs and cloud HSMs can't host the rules.

## Caveats

- The emulator is software running on the same machine as the benchmark. Real
  secure chips are much slower at the maths, so these numbers show
  *relative* costs, not real-hardware speed.
- Disk speed decides the "saved safely" rows, and cloud disks vary.
- One machine, three runs. Treat differences under ~10–15% as noise.
