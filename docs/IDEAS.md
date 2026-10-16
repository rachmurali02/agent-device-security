# Project ideas: existing tech, new spin

Target: the **policy-to-HSM boundary**. Policy is enforced *inside* the trust
boundary, not in a host service that asks the HSM to sign whatever it's given.
Language: Rust (`no_std` core) with a C ABI where interfaces require it.

## Flagship: `quorum-hsm` — a policy-enforcing HSM for agent actions

**Existing tech:** HSMs + PKCS#11 sign opaque hashes; policy lives on the host.
**Spin:** "What you see is what you sign" for AI agents. The HSM firmware
*parses* a structured agent-action request (action type, target, amount,
device attestation, user-presence proof) and evaluates a signed policy
internally before signing. A compromised host or agent cannot get an
out-of-policy signature.

Components:
1. **Trusted core (`no_std` Rust):** key store, mechanisms (Ed25519, ECDSA P-256),
   policy evaluator, monotonic counters (spend/rate limits that survive reboot).
2. **Quorum-authorized policy updates:** new policy bundles must carry m-of-n
   admin signatures; the HSM verifies them and rejects rollback via a version counter.
3. **Tamper-evident audit log:** hash chain inside the boundary with signed
   checkpoints, so log truncation or rewriting is detectable.
4. **Policy attestation:** the HSM signs a statement of `{firmware hash,
   policy hash, counter values}` so a relying party can verify which rules were enforced.
5. **PKCS#11 v3 provider (`cdylib`):** standard host interface plus a vendor
   mechanism `CKM_VENDOR_AGENT_ACTION`; test with `pkcs11-tool`.
6. **Transport:** host↔HSM over a framed serial/USB protocol with a session
   secured by authenticated key exchange.
7. **Assurance tooling:** `cargo-fuzz` on the parser and policy engine,
   property tests, and a fault-injection harness (simulated instruction skips/bit
   flips in signature verification) to demonstrate glitch countermeasures
   (double-checks, redundant comparisons, constant-time code).

Runs first on a host emulator, then on real hardware (see below).

## Additional projects (each extends the flagship)

| # | Project | Existing tech | Spin |
|---|---------|---------------|------|
| 2 | **Factory provisioning + restore** | Key injection, EST | A device secure element generates its identity key; an ECDH-wrapped protocol gets it certified by an HSM-backed CA running on `quorum-hsm`; factory restore re-provisions without exposing keys. |
| 3 | **Secure boot with measured models** | Secure boot, anti-rollback | Rust bootloader on an RP2350 checks the firmware *and* the on-device model blob, burns anti-rollback fuses (OTP), and produces an attestation token. |
| 4 | **OpenSSL 3 provider** | OpenSSL providers | Standard tools (`openssl`, nginx) use `quorum-hsm` keys, with policy still enforced in the HSM. |
| 5 | **OP-TEE trusted application** | ARM TrustZone | Port the policy core to an OP-TEE TA on QEMU (TrustZone-A): same policy logic, different trust boundary. |
| 6 | **HSM-backed code signing with transparency** | Sigstore / CT | Firmware releases need a quorum and are logged in an append-only log; devices reject unlogged images. |

## Hardware (all optional, cheap)
- Raspberry Pi Pico 2 (RP2350): TrustZone-M, secure boot, OTP fuses
- Microchip ATECC608B or Infineon OPTIGA Trust M breakout: real secure element
- Nitrokey HSM 2: compare against a commercial PKCS#11 device
- QEMU + OP-TEE for TrustZone-A without hardware

## Milestones
1. ✅ Emulator: key store + Ed25519 signing + PKCS#11 provider passing `pkcs11-tool` tests
2. ✅ Structured agent-action parsing + per-key policy + spend/sequence counters + user confirmation
3. ✅ Quorum for agent key create/delete, rule changes and admin changes; key birth certificates with rules versions; receiver nonces; tamper-evident audit hash chain with signed checkpoints
4. ✅ Fuzzing (5 targets incl. stateful whole-HSM), glitch double-checks with fault injection, disk-failure tests, threat model (`docs/THREAT_MODEL.md`); bonus: two-slot storage (2.7x faster safe saves)
5. ✅ RP2350 (Pico 2) firmware with embassy: USB CDC transport, flash A/B storage with read-back, TRNG, one-time provisioning, LED status; host-testable `quorum-device` crate (power cut at every flash byte op), board emulator over a pseudo serial port, `board` fuzz target, UF2 build in CI, secure boot guide (`docs/HARDWARE.md`). On-board testing pending hardware.
6. State encryption + authentication with an OTP-held key (page-locked after boot), OTP-backed anti-rollback save counter, secure boot + debug disable + glitch detector on a real board, on-board benchmarks; later: manufacturer-certified identity / attestation

## Proposed extension: the agent wallet (not built yet)

An application on top of the HSM, so real AI agents can use it. Paused in
favour of running experiments on the board first; a first version of its
core was written and then reverted (git history: "Agent wallet, part 1").

**The idea:** the agent never holds a key. It asks; the board decides.

```
 AI agent (Claude Desktop, Cursor, …)
   │  "pay $15 to coffee-shop.example"      via MCP (the standard way agents use tools)
   ▼
 quorum-wallet (on the computer)            holds the board session, waits for approvals,
   │                                        saves receipts, collects the audit log
   ▼
 the board (HSM)                            checks the rules itself; signs or refuses
        └─ needs the user's OK? ──► web page on the phone: "Approve $35 to airline.example?"
```

**Pieces:**
1. Wallet service: one logged-in HSM session; requests that need the user's
   OK wait until approved, denied or expired; signed receipts (statement +
   birth certificate) a receiver can check offline; audit log copied out
   after every action and verified against a signed checkpoint.
2. MCP server for agents, with tools such as `wallet_status` (what am I
   allowed to do, how much budget is left) and `wallet_request_action`.
3. Approval web page: pending requests with Approve / Deny, keys and
   budgets, history, and the audit log with a "verified" check. Separate
   tokens for the agent and the user, so an agent can't approve itself.

**Honest limit of a first version:** the approval key would live in the
wallet on the computer. That fully stops a misbehaving or tricked agent,
but a hacked computer could fake the "user said yes" step (the board's
limits and budget would still hold). Stronger options, in order:
- **Touch to approve on the board:** press the board's button to say yes,
  like tapping a YubiKey (needs a firmware change; no screen, so the user
  approves "presence", not details).
- **A phone app** holding the approval key and showing the action decoded
  from the exact bytes it signs.

**Open questions:** one board session shared by the wallet and admin
commands (the serial port is exclusive); how receivers learn a key was
retired; no real money until the security limits above are closed.
