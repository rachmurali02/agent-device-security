## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 17.4 µs | 40.6 µs | 54427 |
| quorum-hsm core, in process (no socket) | 33.6 µs | 59.9 µs | 28450 |
| quorum-hsm emulator via PKCS#11 | 132.9 µs | 211.9 µs | 7411 |
| SoftHSM2 via PKCS#11 | 194.2 µs | 376.2 µs | 4725 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 618.4 µs | 1.52 ms | 1351 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 1.88 ms | 2.32 ms | 553 |
| quorum-hsm: change an agent key's rules with 2-of-3 sign-off + new certificate | 1.05 ms | 1.60 ms | 930 |
| SoftHSM2: key via PKCS#11 | 11.77 ms | 16.34 ms | 81 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 85.5 µs | 140.5 µs | 11956 |
| quorum-hsm core, refusing an action (refusal recorded, no disk) | 10.9 µs | 27.1 µs | 79353 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 294.1 µs | 931.1 µs | 3000 |
| quorum-hsm emulator, refusing an action (refusal recorded in the audit log, saved with fsync) | 176.8 µs | 504.4 µs | 4905 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 110.4 µs | 270.7 µs | 8237 |
| quorum-hsm emulator, previous storage (rewrite + rename, two disk waits) | 762.5 µs | 2.00 ms | 1196 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 535.6 µs | 1.14 ms | 1714 |
| SoftHSM2 + rules on the host, counters in memory only | 205.3 µs | 385.7 µs | 4595 |
| SoftHSM2 + rules on the host, counters saved with fsync | 437.4 µs | 888.5 µs | 2067 |
| SoftHSM2 + rules on the host, refusing an action (nothing recorded) | 0.0 µs | 0.0 µs | 15479756 |
| Receiver check: HSM identity -> certificate -> signed action | 125.0 µs | 164.8 µs | 7794 |
| Auditor check: 1,000-entry audit log against a signed checkpoint (no HSM) | 227.9 µs | 369.0 µs | 4276 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 8564 | 6948 |
| SoftHSM2: raw signing via PKCS#11 | 4968 | 7917 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 2660 | 3311 |

### 5. Security: attacks by someone who controls the computer and knows the PIN

| Attack | quorum-hsm | SoftHSM2 + rules on the host |
|---|---|---|
| Get a signature for a payment the rules forbid ($9,999.99) | ✅ blocked (the HSM checks the amount itself; raw signing with agent keys is refused) | ❌ attack works (C_Sign signs anything; the signature verifies) |
| Spend past the budget ($3 budget, ten $1 payments) | ✅ blocked (3 of 10 approved, then BudgetExceeded) | ❌ attack works (10 of 10 signed; the budget lives on the host) |
| Create a new signing key with loose rules, using only the PIN | ✅ blocked (agent keys need 2-of-3 admin sign-off) | ❌ attack works (C_GenerateKeyPair succeeds; receivers can't tell it apart) |
| Reset the budget by deleting and re-creating the key | ✅ blocked (deleting agent keys needs admin sign-off) | ❌ attack works (the host's counter file can simply be reset) |
| Read the private key out of the HSM | ✅ blocked (CKA_VALUE is sensitive) | ✅ blocked (CKA_VALUE is sensitive) |
| Pass off a signature as approved under rules it wasn't (receiver's view) | ✅ blocked (the birth certificate names the exact rules and the 2 approving admins) | ❌ attack works (nothing ties a key to its rules; receivers must trust the host) |
| Loosen an existing key's rules (lift the budget) using only the PIN | ✅ blocked (changing rules needs 2-of-3 admin sign-off; the $3 budget still holds) | ❌ attack works (the attacker edits the host's rules; the next $1 is signed) |
| Erase the record of a refused attack from the audit log | ✅ blocked (editing or deleting the entry breaks the HSM-signed checkpoint) | ❌ attack works (the line is deleted and nothing can tell) |
