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
Give an AI agent a key with rules like "payments only, at most $50 each, $200
in total, and anything over $20 needs my OK on my phone". The HSM enforces
those rules itself. A hacked computer or a misbehaving agent can't talk it out
of them.

## What works today

### Milestone 2: rules for AI agents ✅

- **Agent keys** come with rules that are fixed when the key is created:
  - which kinds of action are allowed (payments, messages, installing apps…)
  - the most a single payment can be
  - a total spending budget
  - which actions need the user's OK
- The agent doesn't hand the HSM a blob of bytes to sign. It describes the
  action ("pay $15 to coffee-shop.example"). The HSM **reads it, checks it
  against the rules, and writes and signs the statement itself**. So what gets
  signed is always exactly what was checked.
- **The user's OK is real.** The user's phone (simulated here) has its own key.
  To approve, it signs a one-time code from the HSM together with the exact
  action. An old approval can't be reused, and an approval for $30 to the
  airline can't be moved to $49 to someone else.
- **Anyone can check a signed action** without the HSM: who approved it, what
  exactly, whether the user confirmed, and its number in sequence (so replays
  and gaps are visible).
- The HSM **records the spending before it signs**, so a crash or power cut can
  never produce a signature that wasn't counted.

```
Agent: "pay $35 to airline.example"
   │
   ▼
HSM checks, in order:  allowed kind? → under the per-payment limit? →
                       within budget? → user's OK needed? Is it genuine?
   │
   ├─ any "no"  → DENIED (nothing signed, nothing charged)
   └─ all "yes" → record spending → sign the statement → APPROVED
```

### Milestone 1: a working HSM ✅

- You can create signing keys inside the HSM. The secret half can never be read out.
- You can sign messages, but only after logging in with the right PIN.
- After 5 wrong PINs, the HSM locks itself.
- It speaks **PKCS#11**, the standard language for HSMs, so existing tools
  (like `pkcs11-tool`) work with it out of the box.
- Signatures check out with OpenSSL, separate software that shares no code with this project.
- The core code builds for a real $5 microcontroller chip (Raspberry Pi RP2350),
  not just for a PC.
- 39 automated tests, plus two demo scripts that run everything from start to finish.

## Try it

You need [Rust](https://rustup.rs), `pkcs11-tool` and `openssl`
(on Ubuntu: `sudo apt install opensc openssl`).

```bash
./scripts/demo-agent.sh  # milestone 2: an AI shopping agent and its rules
./scripts/demo.sh        # milestone 1: keys, PIN and signing basics
cargo test --workspace   # run all the tests
```

**The agent demo** gives a shopping agent a key with these rules: payments and
messages only, at most $50 each, $60 in total, and the user's OK for anything
over $20. Then it plays this out:

| The agent tries to… | Result |
|---|---|
| buy a $15 coffee | ✅ approved, and the coffee shop checks the signature |
| book a $35 flight on its own | ❌ needs the user's OK |
| book the same flight after the user approves on their phone | ✅ approved, marked "confirmed by the user" |
| pay $80, even with the user's OK | ❌ over the per-payment limit |
| delete the user's photos | ❌ not an allowed kind of action |
| spend another $15 ($50 already used) | ❌ over the $60 budget |
| (attacker) make the agent key sign anything it likes | ❌ refused |
| (attacker) edit a signed action afterwards | ❌ the signature no longer checks out |

**The basics demo** creates an HSM, makes a key, signs a message, checks the
signature with OpenSSL, shows that a changed message fails, and shows a wrong
PIN being refused.

<details>
<summary>Doing it by hand</summary>

```bash
cargo build --release
export QUORUM_HSM_SOCKET=/tmp/quorum-hsm.sock
Q=target/release/quorum
MODULE=$PWD/target/release/libquorum_pkcs11.so

# Create and start an HSM
target/release/quorum-emulator init  --state hsm.state --pin 123456
target/release/quorum-emulator serve --state hsm.state --socket $QUORUM_HSM_SOCKET &

# Make a key, then sign a file with it
pkcs11-tool --module $MODULE --login --pin 123456 \
  --keypairgen --key-type EC:edwards25519 --label my-key --id 01
pkcs11-tool --module $MODULE --login --pin 123456 \
  --sign -m EDDSA --id 01 -i message.txt -o message.sig

# Agent keys: a "phone" for approvals, a key with rules, then actions
$Q confirmer new --out phone
$Q agent-key create --pin 123456 --label shopper --allow payment \
  --max-amount 50 --budget 200 --confirm-above 20 --confirmer phone.pub
$Q act --pin 123456 --key 2 --kind payment --to shop.example --amount 15 --out buy1
$Q act --pin 123456 --key 2 --kind payment --to airline.example --amount 35 \
  --confirm-with phone --out buy2      # asks "Approve? [y/N]"
$Q verify --public-key <hex from agent-key create> --signed buy2
$Q agent-key show --key 2              # rules, money spent, budget left
```
</details>

## How the pieces fit together

```
 Any program               Adapter                    The "chip"
 (pkcs11-tool,   ──────►   quorum-pkcs11   ──┐
  OpenSSL, …)    PKCS#11   translates only   │
                                             ├─►  quorum-emulator
 AI agent        ──────►   quorum (CLI)    ──┘     └─ quorum-core
 user's phone              asks, shows,   socket      makes every decision:
 verifier                  checks                     keys, PIN, signing,
                                                      agent rules
```

| Folder | What it is | Plain-English role |
|---|---|---|
| `crates/core` | `quorum-core` | The brain of the HSM. All security decisions happen here. |
| `crates/emulator` | `quorum-emulator` | Pretends to be the chip, so we can develop on a normal computer. |
| `crates/pkcs11` | `quorum-pkcs11` | The adapter that lets standard tools talk to our HSM. |
| `crates/cli` | `quorum` | The command-line tool for agent keys: create, act, approve, check. |
| `crates/client` | `quorum-client` | The small piece that connects programs to the HSM. |
| `scripts/demo-agent.sh` | Demo | The AI-agent story with one command. |
| `scripts/demo.sh` | Demo | The basics with one command. |
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
| **Agent keys never sign bytes the computer chose.** The HSM writes the statement itself. | Otherwise a hacked computer could skip the rules by asking for a "raw" signature. |
| **An agent key's rules can't be changed** after it's created. | Nobody, not even someone with the PIN, can quietly loosen them. |
| **Spending is saved before signing.** | Cutting the power at the right moment can't get a free, uncounted signature. |
| **The user's approval covers a one-time code and the exact action.** | Approvals can't be replayed or moved to a different action. |
| **Recipients and details must be plain printable text.** | No hidden characters or look-alike letters that make the phone show one thing while something else gets signed. |
| **Every signed action carries a sequence number and a fingerprint of the rules.** | A verifier can spot replays and missing actions, and knows which rules approved it. |

## Not done yet (honest limitations)

- The emulator is software pretending to be hardware. It is **not** real
  hardware protection yet.
- The HSM's saved state file (keys and PIN) is **not encrypted** yet. Encrypting
  it with a key unique to each device is on the roadmap.
- There is one user role (PIN holder). Admin actions will need approval from
  several people instead (milestone 3).
- The user's "phone" is simulated by a key file and a yes/no prompt. On a
  real device it would be a secure chip with its own screen and button.
- The HSM has no trusted clock, so budgets are lifetime totals, not "per day".
- Agent actions use the `quorum` tool, not PKCS#11. Agent keys show up in
  PKCS#11 but refuse to sign there.

## Roadmap

| # | Milestone | Status |
|---|---|---|
| 1 | Working HSM: keys, PIN, signing, PKCS#11, tests | ✅ Done |
| 2 | Rules inside the HSM for agent actions (limits, budget, user confirmation) | ✅ Done |
| 3 | **Rule changes need sign-off from several people; tamper-proof audit log** | Next |
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
- **Agent key**: a key that only signs actions its rules allow.
- **Policy / rules**: what an agent key may do: kinds of action, limits, budget, when to ask the user.
- **Statement**: the HSM's signed record of exactly what it approved.
- **Confirmation device**: the user's phone, holding a key that proves "yes, I approve this".
- **Challenge**: a random one-time code from the HSM, so each approval can only be used once.
- **Verifier**: whoever receives a signed action and checks it (a shop, a server, an app store).
