# Threat model

What this project protects, from whom, how, and how we know it works. Every
"how we know" points at a test, a benchmark attack or a fuzz target you can
run yourself.

## What we protect

| Asset | Why it matters |
|---|---|
| **Agent keys** (the secret half) | Whoever has one can sign actions as the user's agent. |
| **The HSM identity key** | It vouches for agent keys (birth certificates) and for the audit log (checkpoints). |
| **The rules** of each agent key | Kinds of action, per-payment cap, budget, when the user must approve. |
| **The counters**: money spent and actions approved | If they can be reset or skipped, the budget means nothing. |
| **The admin list** | Admins decide which keys exist and what rules they follow. |
| **The audit log** | The record of what happened, including refused attempts. |
| **The PIN** | Unlocks day-to-day use. |

## Who we protect against

| Attacker | What they can do | Covered? |
|---|---|---|
| **A1. The computer is hacked** (the main threat) | Runs any code on the agent's computer, sees and replays everything sent to the HSM, **knows the PIN**, controls the agent. | ✅ Yes: this is what the design is for. |
| **A2. One admin goes rogue**, or one admin's key is stolen | Signs any proposal with that one key. | ✅ Yes, as long as the threshold is 2 or more. |
| **A3. A dishonest middleman or shop** | Replays signed actions, edits them, presents old certificates. | ✅ Yes. |
| **A4. Physical access to the device** | Cuts the power at any moment; "glitches" the chip to flip **one** decision. | ✅ For power cuts and single glitches. ❌ Not for multiple coordinated glitches, or for reading keys out of the chip (needs real hardware, milestone 5). |
| **A5. Someone copies the stored state** (disk image) | Reads the state file. | ❌ Not yet: the state file isn't encrypted (planned). |

## Where the trust boundary is

```
  untrusted                                    │  trusted (inside the HSM)
                                               │
  AI agent, apps, the PKCS#11 adapter,         │  quorum-core:
  the `quorum` tool, the computer's disk,  ────┼─►  parses every request strictly
  the network, shops                           │    checks PIN, rules, approvals
                                               │    signs only what it built itself
  user's phone (trusted for "yes, I approve")  │    keeps keys, counters, log
  admins' keys (trusted together, not alone)   │
```

Everything left of the line is assumed hostile under A1. Nothing on the left
makes a security decision.

## Threats and what stops them

| # | Threat | Attacker | What stops it | How we know |
|---|---|---|---|---|
| T1 | Get an action signed that the rules forbid | A1 | The HSM reads the action and checks every rule itself, then builds the statement it signs | Benchmark attack 1; fuzz `hsm_commands` checks every approval against the rules |
| T2 | Ask an agent key to sign raw bytes (skipping the rules) | A1 | Agent keys refuse raw signing, inside the key store | Test `agent_keys_never_sign_raw_bytes…`; fuzz `hsm_commands` |
| T3 | Keep spending past the budget | A1 | Spending is counted inside the HSM and saved before signing | Benchmark attack 2; test `total_budget_is_enforced…` |
| T4 | Reset the budget (delete and re-create the key) | A1 | Deleting or creating agent keys needs admin sign-off | Benchmark attack 4; tests in `quorum::` |
| T5 | Create a key with loose rules | A1, A2 | Needs `threshold` admins signing the exact rules | Benchmark attack 3; tests `one_of_two_required_admins…`, `approvals_cover_the_exact_rules` |
| T6 | Loosen an existing key's rules | A1, A2 | Same sign-off; spending carries over | Benchmark attack 7; tests in `milestone3::` |
| T7 | Replay an old approval (user's or admins') | A1 | Every approval covers a one-time code from the HSM, used up on first try | Tests `a_confirmation_cannot_be_replayed`, `approvals_are_single_use` |
| T8 | Move the user's approval to a different action | A1 | The approval covers the full action, including the shop's code and expiry | Tests `a_confirmation_cannot_be_moved…`, `the_users_approval_covers_the_code_and_expiry_too` |
| T9 | Make the phone show one thing while another is signed | A1 | Recipients and details must be plain printable text; one encoding per action | Test `misleading_or_ambiguous_actions…`; fuzz `wire_request` |
| T10 | Replay a signed payment to a shop, or send it late | A3 | The shop's one-time code and expiry are signed in; the shop accepts each code once | Agent demo steps 4 and 7 |
| T11 | Claim a signature was approved under different rules | A1, A3 | Birth certificates bind key and rules; statements carry the rules' fingerprint | Benchmark attack 6; test `full_receiver_check…` |
| T12 | Hide a refused attempt by editing or deleting the log | A1 | Hash-chained log; HSM-signed checkpoints | Benchmark attack 8; tests `editing_removing_or_reordering…` |
| T13 | Do things without leaving a log entry | A1 | Refusals are logged before answering; when the log is full, the HSM stops | Tests `a_full_log_stops_the_hsm…`, `the_log_starts_at_the_factory…` |
| T14 | Fill the log to stop the HSM, without the PIN | anyone | Only logged-in activity is logged; wrong PINs are capped at 5 | Test `people_without_the_pin_cannot_flood_the_log` |
| T15 | Cut the power to get a free signature or extra PIN guesses | A4 | Spending and PIN attempts are saved before acting; saves are all-or-nothing | Tests `pin_attempt_is_committed_before_comparison`, `a_failing_disk_never_yields_an_unsaved_signature`, `a_save_cut_off_at_any_byte…` |
| T16 | Make the disk fail to leave the HSM half-updated | A4 | Any failed save stops the HSM until restart (fail closed) | Test `a_failing_disk_never_yields_an_unsaved_signature` (fails every save in turn) |
| T17 | Glitch one decision (over budget → OK, wrong PIN → right) | A4 | Every decision that leads to a signature, a login or an admin change is made twice, by separate code; a mismatch stops the HSM | Tests in `glitches::` (one per decision point) |
| T18 | Crash or confuse the HSM with malformed input | A1 | Strict parsing: exact lengths, no extra bytes, one encoding per message | Fuzz `wire_request`, `hsm_commands`, `verifiers` |
| T19 | Corrupt or tamper with the stored state | A1, A4 | State is checked strictly on load (canonical, consistent) and each save slot has a hash | Fuzz `state_load`, `slot_file`; test `corrupted_state_is_rejected` |
| T20 | Learn the PIN from timing | A1 | Constant-time PIN comparisons | Code review (`pin_matches`, `pin_matches_again`) |
| T21 | Slip in a malformed or weak admin or phone key | A1 | Public keys must be canonical and not small-order | Test `bad_admin_setups_are_refused_at_the_factory` |

## Bugs this process found

| What | Found by | Fixed in |
|---|---|---|
| The signature library accepted a malformed (non-canonical) public key | Unit test | Milestone 2 |
| Lowering a budget below what was spent would have stopped the HSM from restarting | Code review while adding rule changes | Milestone 3 |
| An empty admin list got past the parser | Unit test | Milestone 3 |
| State files with junk in a label's padding were accepted (not canonical) | **Fuzzing** (`state_load`, within seconds) | Milestone 4 |

## Not covered yet

- **Reading keys out of the chip, and power-analysis attacks** on the signing
  maths. These need real hardware and hardware countermeasures (milestone 5).
- **More than one coordinated glitch.** The double checks assume one fault per
  operation; real secure chips add glitch sensors for the rest.
- **Encrypting the state at rest** with a key unique to each device (A5).
- **Revocation:** telling shops that a key was deleted.
- **A PIN holder slowing the HSM down** with many refused actions (each costs
  a disk write). Rate limits could help.
- **A trusted clock**, so budgets could be "per day".
- **A real secure screen** for the user's approval: the phone is simulated.
