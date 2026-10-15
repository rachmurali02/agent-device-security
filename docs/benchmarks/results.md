## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 17.3 µs | 43.4 µs | 51570 |
| quorum-hsm core, in process (no socket) | 33.5 µs | 64.7 µs | 27316 |
| quorum-hsm emulator via PKCS#11 | 126.4 µs | 198.0 µs | 7687 |
| SoftHSM2 via PKCS#11 | 234.7 µs | 396.6 µs | 3978 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 1.63 ms | 3.09 ms | 543 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 2.96 ms | 3.81 ms | 333 |
| quorum-hsm: change an agent key's rules with 2-of-3 sign-off + new certificate | 1.45 ms | 2.76 ms | 651 |
| SoftHSM2: key via PKCS#11 | 12.18 ms | 18.43 ms | 80 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 54.2 µs | 93.2 µs | 17192 |
| quorum-hsm core, refusing an action (refusal recorded, no disk) | 10.9 µs | 30.6 µs | 80301 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 824.7 µs | 2.28 ms | 1094 |
| quorum-hsm emulator, refusing an action (refusal recorded in the audit log, saved with fsync) | 697.8 µs | 2.12 ms | 1264 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 368.8 µs | 1.02 ms | 2461 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 1.13 ms | 3.10 ms | 797 |
| SoftHSM2 + rules on the host, counters in memory only | 206.5 µs | 332.8 µs | 4674 |
| SoftHSM2 + rules on the host, counters saved with fsync | 455.1 µs | 867.4 µs | 2054 |
| SoftHSM2 + rules on the host, refusing an action (nothing recorded) | 0.0 µs | 0.0 µs | 14981498 |
| Receiver check: HSM identity -> certificate -> signed action | 125.3 µs | 263.2 µs | 7519 |
| Auditor check: 1,000-entry audit log against a signed checkpoint (no HSM) | 227.8 µs | 249.5 µs | 4354 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 8477 | 5929 |
| SoftHSM2: raw signing via PKCS#11 | 4657 | 7730 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 1017 | 920 |

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
