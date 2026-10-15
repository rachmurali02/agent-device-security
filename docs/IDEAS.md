# Project ideas: existing tech, new spin

| # | Project | Existing tech | The spin |
|---|---------|---------------|----------|
| 1 | **Agent Passkeys** | WebAuthn / FIDO2 | Device-bound keys sign each agent *action* (not just login); high-risk actions need user presence in the secure enclave. |
| 2 | **Measured Inference** | TPM measured boot + remote attestation | Extend PCR-style measurements to model weights hash, system prompt hash, and tool manifest; the backend verifies a quote before trusting agent output. |
| 3 | **Agent-aware KMS** | Cloud KMS / HSM key custody | Agents never hold secrets; they request signing ops through a policy engine (Cedar/OPA) with rate limits, intent logs, and m-of-n human approval. |
| 4 | **Model & Firmware Transparency Log** | Sigstore / Rekor, Certificate Transparency | One HSM-signed, append-only log for firmware *and* on-device model updates; devices refuse unlogged artifacts. Threshold signing (FROST) for release keys. |
| 5 | **Factory Provisioning Simulator** | EST, ACME `device-attest-01` | Simulate secure-element key generation at manufacture, CSR to an HSM-backed intermediate CA, device identity certs, and revocation at fleet scale. |
| 6 | **Bound Capability Tokens** | Macaroons / Biscuit, DPoP | Attenuable tokens for agent tool calls, proof-of-possession bound to the device key, so a stolen token is useless off-device. |
| 7 | **Secure OTA for Agents** | TUF / Uptane | Rollback- and freeze-attack protection for model + agent-config updates, with hardware monotonic counters. |

## Recommended flagship

Combine **3 + 2 + 6** into a single demo:

1. Device boots (vTPM) → produces quote covering firmware + model hash.
2. Backend verifies the quote and issues a device-bound capability token.
3. Agent requests "send email" → signing service (SoftHSM via PKCS#11)
   checks policy, asks the user for confirmation if needed, and signs.
4. Third-party API verifies the full chain: device → model → token → action.

Ships with a threat model (STRIDE), a key ceremony doc, and attack demos
(token replay, swapped model weights, rollback).

## Stack suggestions
- Go or Rust for services; `python-pkcs11`/`cryptoki` for HSM access
- SoftHSM2 (dev), YubiHSM 2 or Nitrokey HSM (real hardware, cheap)
- `swtpm` + `tpm2-tools` for attestation without real hardware
