## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 17.6 µs | 55.8 µs | 44621 |
| quorum-hsm core, in process (no socket) | 33.7 µs | 95.1 µs | 23979 |
| quorum-hsm emulator via PKCS#11 | 109.0 µs | 174.8 µs | 8668 |
| SoftHSM2 via PKCS#11 | 200.2 µs | 370.0 µs | 4473 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 481.9 µs | 1.70 ms | 1485 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 1.58 ms | 2.07 ms | 641 |
| quorum-hsm: change an agent key's rules with 2-of-3 sign-off + new certificate | 807.7 µs | 1.42 ms | 1181 |
| SoftHSM2: key via PKCS#11 | 14.12 ms | 19.13 ms | 70 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 55.2 µs | 89.3 µs | 17017 |
| quorum-hsm core, refusing an action (refusal recorded, no disk) | 10.9 µs | 28.3 µs | 80590 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 305.2 µs | 873.3 µs | 2897 |
| quorum-hsm emulator, refusing an action (refusal recorded in the audit log, saved with fsync) | 193.7 µs | 627.9 µs | 4436 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 123.4 µs | 298.0 µs | 7165 |
| quorum-hsm emulator, previous storage (rewrite + rename, two disk waits) | 776.8 µs | 2.03 ms | 1172 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 534.9 µs | 1.36 ms | 1677 |
| SoftHSM2 + rules on the host, counters in memory only | 208.2 µs | 377.0 µs | 4540 |
| SoftHSM2 + rules on the host, counters saved with fsync | 474.3 µs | 1.02 ms | 1930 |
| SoftHSM2 + rules on the host, refusing an action (nothing recorded) | 0.0 µs | 0.0 µs | 12868688 |
| Receiver check: HSM identity -> certificate -> signed action | 123.6 µs | 197.1 µs | 7662 |
| Auditor check: 1,000-entry audit log against a signed checkpoint (no HSM) | 228.0 µs | 300.6 µs | 4292 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 8145 | 7059 |
| SoftHSM2: raw signing via PKCS#11 | 4711 | 7851 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 2886 | 3091 |

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
