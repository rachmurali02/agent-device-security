# agent-device-security

**A security chip, written in Rust, that guards the secret keys an AI agent uses, and that can't be tricked into misusing them.**

## The idea in one minute

When an AI agent on your phone or laptop does something important (sends an
email, makes a payment, installs an update), it proves the action is genuine
with a **digital signature**. A signature is made with a **secret key**. Whoever
steals that key can pretend to be your device.

So secret keys are kept in a special locked box called an **HSM** (Hardware
Security Module). Think of a notary with an official stamp locked in a safe:

- You never get the stamp. You hand over a document, and it comes back stamped.
- The stamp can't be copied out of the safe.

The weak spot: a normal HSM stamps **anything** the computer in front of it
asks for. If that computer is hacked, the attacker just asks the notary to stamp
their documents.

**This project builds a notary that checks the rules itself**, inside the safe.
It starts with the basics: a working HSM with keys, a PIN and signing. Next
come the rules for AI agents ("only send money under $100", "only if the user
confirmed").

## What works today

Milestone 1 is done ✅

- You can create signing keys inside the HSM. The secret half can never be read out.
- You can sign messages, but only after logging in with the right PIN.
- After 5 wrong PINs, the HSM locks itself.
- It speaks **PKCS#11**, the standard language for HSMs, so existing tools
  (like `pkcs11-tool`) work with it out of the box.
- Signatures check out with OpenSSL, separate software that shares no code with this project.
- The core code builds for a real $5 microcontroller chip (Raspberry Pi RP2350),
  not just for a PC.
- 19 automated tests, plus a demo script that runs everything from start to finish.

## Try it

You need [Rust](https://rustup.rs), `pkcs11-tool` and `openssl`
(on Ubuntu: `sudo apt install opensc openssl`).

```bash
./scripts/demo.sh        # the whole story, step by step
cargo test --workspace   # run all the tests
```

The demo creates an HSM, makes a key, signs a message, checks the signature
with OpenSSL, shows that a changed message fails, and shows a wrong PIN being refused.

<details>
<summary>Doing it by hand</summary>

```bash
cargo build --release
export QUORUM_HSM_SOCKET=/tmp/quorum-hsm.sock
MODULE=$PWD/target/release/libquorum_pkcs11.so

# Create and start an HSM
target/release/quorum-emulator init  --state hsm.state --pin 123456
target/release/quorum-emulator serve --state hsm.state --socket $QUORUM_HSM_SOCKET &

# Make a key, then sign a file with it
pkcs11-tool --module $MODULE --login --pin 123456 \
  --keypairgen --key-type EC:edwards25519 --label my-key --id 01
pkcs11-tool --module $MODULE --login --pin 123456 \
  --sign -m EDDSA --id 01 -i message.txt -o message.sig
```
</details>

## How the pieces fit together

```
 Any program              Adapter                   The "chip"
 (pkcs11-tool,   ──────►  quorum-pkcs11   ──────►   quorum-emulator
  OpenSSL, …)    PKCS#11  translates only   socket    └─ quorum-core
                                                         makes every decision:
                                                         keys, PIN, signing
```

| Folder | What it is | Plain-English role |
|---|---|---|
| `crates/core` | `quorum-core` | The brain of the HSM. All security decisions happen here. |
| `crates/emulator` | `quorum-emulator` | Pretends to be the chip, so we can develop on a normal computer. |
| `crates/pkcs11` | `quorum-pkcs11` | The adapter that lets standard tools talk to our HSM. |
| `scripts/demo.sh` | Demo | Runs the whole story with one command. |
| `tools/` | Helpers | A code generator for the adapter. |
| `docs/IDEAS.md` | Roadmap | Where the project is going. |

## Security choices, explained simply

| What we do | Why it matters |
|---|---|
| **Secret keys never leave the core.** There is no command that returns one. | Even a fully hacked computer can only ask for signatures, never steal the key. |
| **A wrong-PIN attempt is saved *before* the PIN is checked.** | An attacker can't cut the power at the right moment to get unlimited guesses. |
| **The PIN check takes the same time whether you're close or way off.** | Timing can't leak how many digits were right. |
| **If saving fails, the HSM stops working** until it restarts. | It would rather refuse than continue in an unknown state ("fail closed"). |
| **Deleted key numbers are never reused.** | An old reference can't accidentally point at a new key. |
| **The core is written without `unsafe` code** and without needing an operating system. | Rust checks it for whole classes of memory bugs, and it can run on a tiny chip. |
| **Every message from outside is checked strictly**: exact lengths, no extra bytes. | Malformed input is rejected instead of guessed at. |
| **Keys can't be created as "extractable".** | You can't ask the HSM to make a key that's allowed to leave. |

## Not done yet (honest limitations)

- The emulator is software pretending to be hardware. It is **not** real
  hardware protection yet.
- The HSM's saved state file (keys and PIN) is **not encrypted** yet. Encrypting
  it with a key unique to each device is on the roadmap.
- There is one user role (PIN holder). Admin actions will need approval from
  several people instead (milestone 3).

## Roadmap

| # | Milestone | Status |
|---|---|---|
| 1 | Working HSM: keys, PIN, signing, PKCS#11, tests | ✅ Done |
| 2 | **Rules inside the HSM** for agent actions (limits, user confirmation) | Next |
| 3 | Rule changes need sign-off from several people; tamper-proof audit log | Planned |
| 4 | Fuzzing (feeding random input to find crashes) and fault-injection tests | Planned |
| 5 | Run on a real chip (Raspberry Pi RP2350) with secure boot | Planned |

More detail in [`docs/IDEAS.md`](docs/IDEAS.md).

## Glossary

- **HSM**: a locked box (hardware) that keeps secret keys and uses them without revealing them.
- **Key pair**: a secret *private key* that makes signatures, and a *public key* anyone can use to check them.
- **Signature**: proof that a message came from the key holder and wasn't changed.
- **Ed25519**: the modern, fast signature method this project uses.
- **PKCS#11**: the standard way programs talk to HSMs, like USB for security hardware.
- **PIN**: the password that unlocks signing. Too many wrong tries lock the HSM.
- **Emulator**: software that acts like a hardware device, for development.
- **`no_std`**: Rust code that needs no operating system, so it can run on tiny chips.
