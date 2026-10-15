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
1. Emulator: key store + Ed25519 signing + PKCS#11 provider passing `pkcs11-tool` tests
2. Structured agent-action parsing + signed policy + monotonic counters
3. Quorum policy updates, audit hash chain, policy attestation
4. Fuzzing + fault-injection harness, threat model (`docs/THREAT_MODEL.md`)
5. Port trusted core to the RP2350; provisioning protocol with a secure element
