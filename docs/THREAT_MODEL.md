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
| **A4. Physical access to the device** | Cuts the power at any moment; "glitches" the chip to flip **one** decision; damages the flash. | ✅ For power cuts, single glitches and damaged flash. ❌ Not for multiple coordinated glitches, or power analysis. |
| **A5. Someone copies the stored state** (disk image, or the Pico 2's flash chip with a clip-on programmer) | Reads the state; later writes an old copy back ("rollback"). | ❌ Not yet: the state isn't encrypted, and an old genuine copy is accepted. Planned: encrypt and authenticate it with a key in the chip's OTP, and count saves in OTP (milestone 6). |
| **A6. Someone replaces the firmware** on the board | Installs firmware that ignores the rules. | ⚠️ Secure boot (RP2350 OTP) stops it, but turning it on is a manual, permanent step ([`HARDWARE.md`](HARDWARE.md)); not yet tried on a board. |

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
| T22 | Re-provision a board that's in use (new PIN, own admins) | A1 | `Provision` works only on a blank board; damaged flash makes the board refuse everything, never blank again | Tests `provisioning_survives_a_restart_and_happens_only_once`, `damaged_flash_is_refused_and_never_reprovisioned`; fuzz `board` |
| T23 | Cut the power while the board writes flash (erase or write half-done) | A4 | Two flash slots: erase and write the older one, read it back; the hash rejects a half-done slot | Tests `a_power_cut_at_any_moment_of_a_save_keeps_a_valid_state` (every byte), `…during_provisioning…` |
| T24 | Worn-out flash silently keeps old bytes | A4 | Every save is read back and compared; a mismatch stops the board | Test `a_save_that_does_not_read_back_correctly_stops_the_device` |
| T25 | Put a save in the "wrong" slot so the next save overwrites the only good copy | A4 | A save is only trusted in the slot its number belongs to | Test `a_save_in_the_wrong_slot_is_not_trusted` |
| T26 | Confuse the board with a broken USB byte stream | A1 | Strict framing: a bad length ends the session; every frame gets exactly one well-formed reply | Tests `frames_are_reassembled…`, `oversized_frames_are_refused`; fuzz `board` |
| T27 | Run different firmware on the board | A6 | RP2350 secure boot with your signing key (manual, permanent setup) | Not tested yet (needs the board) |
| T28 | Spend past the budget by racing many connections at once | A1 | One command at a time; the budget is checked and charged in the same step | Lab attack 8 (exactly 10 of 100 approved); lab load test (72,116 payments, counter exact) |
| T29 | Make the spending counter wrap around | A1 | Overflow-checked arithmetic | Lab attack 7 |
| T30 | Lose a counter update by killing the HSM mid-traffic | A4 | Save before answering; two-slot saves | Lab crash test: 25 `kill -9`s, no uncounted signature, no reused action number |
| T31 | Slow the HSM for everyone (denial of service) | A1, anyone | Requests without the PIN never touch the disk; half-sent requests block nobody | Lab noisy-neighbour test: 1.1–1.6x without the PIN. ⚠️ 6–9x with the PIN (not covered yet) |
| T32 | Fill the key store so admins can't create agent keys | A1 | ❌ Not covered yet (new finding) | Lab attack 19 |
| T33 | Delete audit entries before they are collected | anyone | Detected: the collector sees the gap and the checkpoint check fails. ⚠️ Not prevented | Lab attack 12 |

## Bugs this process found

| What | Found by | Fixed in |
|---|---|---|
| The signature library accepted a malformed (non-canonical) public key | Unit test | Milestone 2 |
| Lowering a budget below what was spent would have stopped the HSM from restarting | Code review while adding rule changes | Milestone 3 |
| An empty admin list got past the parser | Unit test | Milestone 3 |
| State files with junk in a label's padding were accepted (not canonical) | **Fuzzing** (`state_load`, within seconds) | Milestone 4 |
| A save found in the wrong slot was trusted, and the next save would then have overwritten the only good copy | Design review while moving storage to flash | Milestone 5 |
| A PIN holder can fill the key store so admins can't create agent keys | **Experiments** (`quorum-lab`, attack 19) | Open (fix: reserve slots for agent keys) |
| Under heavy load, the audit collector waits in the same queue as everyone, so the log fills and clients retry | **Load experiments** | Open (fix: bigger log buffer, or collector first) |

## Not covered yet

- **Reading the Pico 2's flash chip** (A5): the state, keys included, is not
  encrypted yet, and an old copy written back would be accepted (rollback).
  Planned for milestone 6: encryption and a save counter, both anchored in
  the RP2350's OTP memory.
- **Power-analysis attacks** on the signing maths. These need hardware
  countermeasures and measurement equipment.
- **Secure boot hasn't been tried on a board yet** (A6).
- **More than one coordinated glitch.** The double checks assume one fault per
  operation; real secure chips add glitch sensors for the rest.
- **Encrypting the state at rest** with a key unique to each device (A5).
- **Revocation:** telling shops that a key was deleted.
- **A PIN holder slowing the HSM down** with many refused actions (each costs
  a disk write): measured at 6–9x. Taking turns between sessions and rate
  limits could help.
- **Filling the key store** (T32) and **deleting audit entries before
  collection** (T33, detected but not prevented).
- **A trusted clock**, so budgets could be "per day".
- **A real secure screen** for the user's approval: the phone is simulated.
