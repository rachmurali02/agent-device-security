# Benchmarks: is enforcing rules inside the HSM the right approach?

**Short answer:** yes, for our threat (someone controls the computer and knows
the PIN). It's the only option tested that blocks the attacks. It costs about
**0.3–0.6 milliseconds more per agent action** than the conventional setup on
this machine, and almost all of that is *saving to disk safely*, not the rules
themselves.

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

## How to run it

```bash
./scripts/bench.sh                      # needs softhsm2 (sudo apt install softhsm2)
```

This writes [`docs/benchmarks/results.md`](benchmarks/results.md). To test
another HSM, such as a real YubiHSM 2, point the benchmark at its PKCS#11 library:

```bash
target/release/quorum-bench --softhsm /path/to/other_pkcs11.so
```

## Results

Machine: Intel Xeon @ 2.10GHz, 4 cores, cloud VM. "Median" is the typical
time for one operation. We ran the benchmark three times; the ranges below
cover all three runs (numbers moved by about ±15% between runs). Full output
from one run: [`benchmarks/results.md`](benchmarks/results.md).

### Speed

| What | quorum-hsm | SoftHSM2 | No HSM |
|---|---:|---:|---:|
| Sign a message (median) | **106–122 µs** | 191–201 µs | 17 µs |
| Create a key (median) | **1.4 ms** | 10–15 ms | n/a |
| Approve an agent action, saved safely to disk | 750–850 µs | 420–570 µs ¹ | n/a |
| Approve an agent action, *not* saved safely (unsafe) | 363 µs | 211–246 µs ¹ | n/a |
| Approve an action that needs the user's OK | 1.0 ms | not possible ² | n/a |
| Create an agent key with 2-of-3 admin sign-off + certificate, then delete it | 2.5 ms | not possible ² | n/a |
| Receiver checks a signed action (no HSM needed) | 125 µs | n/a | n/a |
| Signatures per second, 1 thread → 4 threads | ~7,500 → ~6,200 | ~4,500 → ~7,900 | n/a |

¹ The rules run on the computer, so these are the steps an attacker can skip (see below).
² SoftHSM2 has no way to do this inside the HSM.

### Security: attacks we actually ran

These aren't claims. The benchmark runs each attack and reports what happened.
The attacker controls the computer and knows the PIN.

| Attack | quorum-hsm | SoftHSM2 + rules on the computer |
|---|---|---|
| Get a $9,999.99 payment signed when the limit is $1 | ✅ blocked | ❌ works: the attacker skips the rule check and signs |
| Keep spending after the $3 budget is used up | ✅ blocked after $3 | ❌ works: 10 of 10 signed |
| Create a new key with loose rules using only the PIN | ✅ blocked: needs 2 of 3 admins | ❌ works |
| Reset the budget by deleting and re-creating the key | ✅ blocked: needs admins | ❌ works: the counter is just a file |
| Read the private key out of the HSM | ✅ blocked | ✅ blocked |
| Fool a receiver about which rules approved a signature | ✅ blocked: the birth certificate proves it | ❌ works: nothing ties a key to its rules |

**quorum-hsm blocks 6 of 6. SoftHSM2 used the conventional way blocks 1 of 6.**
SoftHSM2 still protects the key itself; it just signs whatever it's asked to.

## What the numbers mean

1. **The rules are almost free.** Inside the core, approving an agent action
   takes 53 µs against 33 µs for a plain signature. Reading the action,
   checking every rule and building the statement adds about **20 µs**.

2. **Saving safely to disk is the real cost.** An agent action takes about
   360 µs without waiting for the disk and 750–850 µs with it. Waiting is
   what guarantees a power cut can't hand out a free signature, so it's not
   optional. The conventional setup pays for this too *if* it saves its
   counters carefully, and it can still be cheated (see the security table).

3. **Our disk saving can be about twice as fast.** Each action rewrites the
   whole state file and waits for the disk *twice* (once for the file, once
   for the folder). Appending only the changed counters to a log would wait
   once and write far less. On real hardware, built-in counters that only go
   up (in secure chips or eMMC "RPMB" storage) would do the same job.

4. **Crossing into the HSM costs more than the maths.** A signature takes
   17 µs on its own but 106–122 µs through PKCS#11 and the socket. Our
   adapter also asks the HSM for its key list before every signature: one
   extra round trip that a small cache would remove.

5. **SoftHSM2 handles parallel requests better.** It gets faster with 4
   threads; we don't, because our HSM does one command at a time (like a
   single-core secure chip) and the adapter shares one connection. On real
   hardware the chip would be the limit anyway, but it matters if this were
   a busy server.

6. **Key creation is faster here** (1.4 ms against 10–15 ms), mostly because
   SoftHSM2 encrypts and writes a separate file for every key.

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

- **For security against a hacked computer:** the rules must be enforced
  inside the HSM. The conventional setup can't stop an attacker who skips the
  check. That's the main finding, and the attack table shows it directly.
- **For speed:** the approach costs a few hundred microseconds per action,
  dominated by safe saving. That's tiny next to a person tapping "Approve"
  or a network payment, and it can be roughly halved (point 3).
- **For production:** run this same core on hardware that accepts custom code
  (a TEE, a secure microcontroller, or a commercial HSM with a firmware SDK).
  Fixed-function HSMs and cloud HSMs can't host the rules.

## Caveats

- The emulator is software running on the same machine as the benchmark. Real
  secure chips are much slower at the maths, so these numbers show
  *relative* costs, not real-hardware speed.
- Disk speed decides the "saved safely" rows, and cloud disks vary.
- One machine, three runs. Treat differences under ~15% as noise.
