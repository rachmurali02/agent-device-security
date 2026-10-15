# Benchmarks: is enforcing rules inside the HSM the right approach?

**Short answer:** yes, for our threat (someone controls the computer and knows
the PIN). It's the only option tested that blocks the attacks: **8 of 8**,
against 1 of 8 for the conventional setup. It costs about **0.35–0.6
milliseconds more per agent action** on this machine. Almost all of that is
*saving to disk safely*; the rules themselves cost microseconds.

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
| Sign a message (median) | **126–136 µs** | 198–235 µs | 17 µs |
| Create a key (median) | **1.5–1.7 ms** | 10.1–12.2 ms | n/a |
| Approve an agent action, saved safely to disk | 819–825 µs | 434–460 µs ¹ | n/a |
| Approve an agent action, *not* saved safely (unsafe) | 291–369 µs | 207–214 µs ¹ | n/a |
| Approve an action that needs the user's OK | 0.98–1.13 ms | not possible ² | n/a |
| **Refuse** an action (the refusal is recorded and saved) | 696–914 µs | <1 µs, nothing recorded ¹ | n/a |
| Create an agent key with 2-of-3 sign-off + certificate, then delete it | 2.2–3.0 ms | not possible ² | n/a |
| Change an agent key's rules with 2-of-3 sign-off + new certificate | 1.1–1.5 ms | not possible ² | n/a |
| Receiver checks a signed action (no HSM needed) | 125–127 µs | n/a | n/a |
| Auditor checks a 1,000-entry log against a checkpoint (no HSM needed) | 226–228 µs | not possible ² | n/a |
| Signatures per second, 1 thread → 4 threads | ~8,500 → ~6,300 | ~4,900 → ~8,100 | n/a |

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
   takes 55 µs against 33 µs for a plain signature. Reading the action,
   checking every rule, building the statement and writing the audit entry
   add about **20 µs**. A refusal is even cheaper (11 µs), since nothing is signed.

2. **Saving safely to disk is the real cost.** An agent action takes about
   290–370 µs without waiting for the disk and about 820 µs with it. Waiting
   is what guarantees a power cut can't hand out a free signature, so it's not
   optional. The conventional setup pays for this too *if* it saves its
   counters carefully, and it can still be cheated (see the security table).

3. **Refusals now cost about as much as approvals.** A refused action is
   written to the audit log and saved *before* the HSM answers, so there is
   no way to probe the rules without leaving a trace. The flip side: someone
   with the PIN can make the HSM do a disk write per refusal, which is a way
   to slow it down. People without the PIN can't (see the README).

4. **Rare admin work is cheap enough not to matter.** Changing a key's rules
   with two admin signatures and a new certificate takes about 1.5 ms. An
   auditor can check a 1,000-entry log in a quarter of a millisecond, on
   any computer.

5. **Our disk saving can be about twice as fast.** Each change rewrites the
   whole state file and waits for the disk *twice* (once for the file, once
   for the folder). The state file also got bigger in milestone 3, since it
   holds up to 64 audit entries. Appending only what changed to a journal
   would wait once and write far less. On real hardware, counters that only
   go up (in secure chips or eMMC "RPMB" storage) would do the same job.

6. **Crossing into the HSM costs more than the maths.** A signature takes
   17 µs on its own but about 130 µs through PKCS#11 and the socket. Our
   adapter also asks the HSM for its key list before every signature: one
   extra round trip that a small cache would remove.

7. **SoftHSM2 handles parallel requests better.** It gets faster with 4
   threads; we don't, because our HSM does one command at a time (like a
   single-core secure chip) and the adapter shares one connection.

8. **Key creation is faster here** (about 1.6 ms against about 11 ms), mostly
   because SoftHSM2 encrypts and writes a separate file for every key.

### What changed since milestone 2

Same benchmark, before and after adding the audit log and rule/admin changes.
The machine was restarted between the two measurements, so treat changes
under ~15% as possibly just the machine.

| What | Milestone 2 | Milestone 3 | Why |
|---|---:|---:|---|
| Approve an agent action, saved safely | ~729 µs | ~821 µs | Bigger state file (audit entries), plus the collector's "release" step is itself a saved write every 16 actions |
| …without waiting for the disk | ~277 µs | ~368 µs | Same reasons, minus the waiting |
| Rule check inside the core | ~53 µs | ~55 µs | Writing the audit entry costs ~2 µs |
| Sign a message via PKCS#11 | ~115 µs | ~130 µs | Raw signing does no audit work; likely the machine |
| Attacks blocked | 6 of 6 | **8 of 8** | Two new attacks, both blocked |

The audit log costs roughly **+10–15% per agent action**, all of it in disk
writes. Point 5 above would more than win that back.

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
| Secure microcontroller (e.g. Raspberry Pi RP2350) | Yes, in software | **Yes** | Our core already builds for it (milestone 5) |

Our benchmark tool works with anything that speaks PKCS#11. Running it on
real hardware is the way to fill in the speed column for these.

## Verdict

- **For security against a hacked computer:** the rules, the admin sign-off
  and the audit log must all live inside the HSM. The conventional setup can't
  stop an attacker who skips a check, edits the rules or deletes a log line.
  The attack table shows each of these directly.
- **For speed:** the approach costs a few hundred microseconds per action,
  dominated by safe saving. That's tiny next to a person tapping "Approve" or
  a network payment, and it can be roughly halved (point 5).
- **For production:** run this same core on hardware that accepts custom code
  (a TEE, a secure microcontroller, or a commercial HSM with a firmware SDK).
  Fixed-function HSMs and cloud HSMs can't host the rules.

## Caveats

- The emulator is software running on the same machine as the benchmark. Real
  secure chips are much slower at the maths, so these numbers show
  *relative* costs, not real-hardware speed.
- Disk speed decides the "saved safely" rows, and cloud disks vary.
- One machine, three runs. Treat differences under ~10–15% as noise.
