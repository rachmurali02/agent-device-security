## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 17.4 µs | 41.1 µs | 54386 |
| quorum-hsm core, in process (no socket) | 34.3 µs | 54.5 µs | 28098 |
| quorum-hsm emulator via PKCS#11 | 106.0 µs | 146.9 µs | 9152 |
| SoftHSM2 via PKCS#11 | 192.7 µs | 303.5 µs | 5033 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 533.8 µs | 2.00 ms | 1400 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 1.56 ms | 2.00 ms | 629 |
| quorum-hsm: change an agent key's rules with 2-of-3 sign-off + new certificate | 789.2 µs | 1.21 ms | 1223 |
| SoftHSM2: key via PKCS#11 | 10.78 ms | 12.71 ms | 94 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 55.3 µs | 91.7 µs | 16727 |
| quorum-hsm core, refusing an action (refusal recorded, no disk) | 11.0 µs | 26.4 µs | 81572 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 242.1 µs | 856.7 µs | 3446 |
| quorum-hsm emulator, refusing an action (refusal recorded in the audit log, saved with fsync) | 193.7 µs | 561.3 µs | 4438 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 104.6 µs | 217.5 µs | 8827 |
| quorum-hsm emulator, previous storage (rewrite + rename, two disk waits) | 744.7 µs | 2.22 ms | 1070 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 573.3 µs | 1.66 ms | 1549 |
| SoftHSM2 + rules on the host, counters in memory only | 207.0 µs | 297.0 µs | 4702 |
| SoftHSM2 + rules on the host, counters saved with fsync | 449.6 µs | 858.1 µs | 2115 |
| SoftHSM2 + rules on the host, refusing an action (nothing recorded) | 0.0 µs | 0.0 µs | 15387456 |
| Receiver check: HSM identity -> certificate -> signed action | 126.9 µs | 202.7 µs | 7432 |
| Auditor check: 1,000-entry audit log against a signed checkpoint (no HSM) | 246.2 µs | 279.0 µs | 4051 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 8292 | 6376 |
| SoftHSM2: raw signing via PKCS#11 | 5018 | 8088 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 2167 | 2835 |

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
