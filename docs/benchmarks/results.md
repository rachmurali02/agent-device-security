## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 17.2 µs | 41.9 µs | 53359 |
| quorum-hsm core, in process (no socket) | 33.1 µs | 62.9 µs | 28418 |
| quorum-hsm emulator via PKCS#11 | 121.8 µs | 186.5 µs | 7917 |
| SoftHSM2 via PKCS#11 | 191.2 µs | 271.0 µs | 5073 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 1.40 ms | 1.83 ms | 746 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 2.46 ms | 2.74 ms | 401 |
| SoftHSM2: key via PKCS#11 | 13.86 ms | 18.08 ms | 72 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 53.2 µs | 96.5 µs | 16982 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 747.4 µs | 2.11 ms | 1242 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 363.3 µs | 1.06 ms | 2524 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 1.01 ms | 2.62 ms | 935 |
| SoftHSM2 + rules on the host, counters in memory only | 211.1 µs | 477.1 µs | 4131 |
| SoftHSM2 + rules on the host, counters saved with fsync | 509.1 µs | 1.74 ms | 1744 |
| Receiver check: HSM identity -> certificate -> signed action | 125.5 µs | 249.4 µs | 7463 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 7902 | 6036 |
| SoftHSM2: raw signing via PKCS#11 | 4365 | 8615 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 1156 | 1147 |

### 5. Security: attacks by someone who controls the computer and knows the PIN

| Attack | quorum-hsm | SoftHSM2 + rules on the host |
|---|---|---|
| Get a signature for a payment the rules forbid ($9,999.99) | ✅ blocked (the HSM checks the amount itself; raw signing with agent keys is refused) | ❌ attack works (C_Sign signs anything; the signature verifies) |
| Spend past the budget ($3 budget, ten $1 payments) | ✅ blocked (3 of 10 approved, then BudgetExceeded) | ❌ attack works (10 of 10 signed; the budget lives on the host) |
| Create a new signing key with loose rules, using only the PIN | ✅ blocked (agent keys need 2-of-3 admin sign-off) | ❌ attack works (C_GenerateKeyPair succeeds; receivers can't tell it apart) |
| Reset the budget by deleting and re-creating the key | ✅ blocked (deleting agent keys needs admin sign-off) | ❌ attack works (the host's counter file can simply be reset) |
| Read the private key out of the HSM | ✅ blocked (CKA_VALUE is sensitive) | ✅ blocked (CKA_VALUE is sensitive) |
| Pass off a signature as approved under rules it wasn't (receiver's view) | ✅ blocked (the birth certificate names the exact rules and the 2 approving admins) | ❌ attack works (nothing ties a key to its rules; receivers must trust the host) |
