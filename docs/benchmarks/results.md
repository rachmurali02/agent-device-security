## Environment

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores)
- Iterations per measurement: 2000
- Threads for throughput: 4
- Message size for raw signing: 64 bytes; signature scheme: Ed25519 everywhere

### 1. Signing a 64-byte message (raw signing)

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| No HSM: Ed25519 in the same process (floor) | 30.5 µs | 58.4 µs | 32604 |
| quorum-hsm core, in process (no socket) | 33.3 µs | 69.3 µs | 26443 |
| quorum-hsm emulator via PKCS#11 | 108.2 µs | 259.9 µs | 8316 |
| SoftHSM2 via PKCS#11 | 196.3 µs | 418.2 µs | 4324 |

### 2. Creating keys

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm: general key via PKCS#11 (fsync) | 1.29 ms | 2.75 ms | 644 |
| quorum-hsm: agent key with 2-of-3 admin sign-off + birth certificate (create + delete pair) | 2.07 ms | 2.32 ms | 493 |
| SoftHSM2: key via PKCS#11 | 11.62 ms | 12.51 ms | 87 |

### 3. Approving one agent action ("pay $0.01 to shop.example")

| Option | Median latency | 99th percentile | Ops per second |
|---|---:|---:|---:|
| quorum-hsm core, in process (no socket, no disk) | 53.0 µs | 97.1 µs | 17402 |
| quorum-hsm emulator, spending saved with fsync (safe default) | 729.1 µs | 1.82 ms | 1295 |
| quorum-hsm emulator, fsync off (unsafe; shows cost of durability) | 276.9 µs | 675.7 µs | 3236 |
| quorum-hsm emulator, with the user's confirmation (challenge + phone + approve) | 928.1 µs | 1.64 ms | 1043 |
| SoftHSM2 + rules on the host, counters in memory only | 202.7 µs | 296.0 µs | 4785 |
| SoftHSM2 + rules on the host, counters saved with fsync | 467.7 µs | 924.7 µs | 1982 |
| Receiver check: HSM identity -> certificate -> signed action | 142.0 µs | 239.8 µs | 6561 |

### 4. Many requests at once (4 threads)

| Option | Ops per second, 1 thread | Ops per second, 4 threads |
|---|---:|---:|
| quorum-hsm emulator: raw signing via PKCS#11 | 7995 | 6490 |
| SoftHSM2: raw signing via PKCS#11 | 4766 | 7051 |
| quorum-hsm emulator: agent actions (fsync), one connection per thread | 1140 | 1110 |

### 5. Security: attacks by someone who controls the computer and knows the PIN

| Attack | quorum-hsm | SoftHSM2 + rules on the host |
|---|---|---|
| Get a signature for a payment the rules forbid ($9,999.99) | ✅ blocked (the HSM checks the amount itself; raw signing with agent keys is refused) | ❌ attack works (C_Sign signs anything; the signature verifies) |
| Spend past the budget ($3 budget, ten $1 payments) | ✅ blocked (3 of 10 approved, then BudgetExceeded) | ❌ attack works (10 of 10 signed; the budget lives on the host) |
| Create a new signing key with loose rules, using only the PIN | ✅ blocked (agent keys need 2-of-3 admin sign-off) | ❌ attack works (C_GenerateKeyPair succeeds; receivers can't tell it apart) |
| Reset the budget by deleting and re-creating the key | ✅ blocked (deleting agent keys needs admin sign-off) | ❌ attack works (the host's counter file can simply be reset) |
| Read the private key out of the HSM | ✅ blocked (CKA_VALUE is sensitive) | ✅ blocked (CKA_VALUE is sensitive) |
| Pass off a signature as approved under rules it wasn't (receiver's view) | ✅ blocked (the birth certificate names the exact rules and the 2 approving admins) | ❌ attack works (nothing ties a key to its rules; receivers must trust the host) |
