# agent-device-security

Hardware-rooted trust for AI agents running on consumer devices.

The core question: **when an agent on a device takes an action, how does anyone
(the user, the backend, a third-party API) know *which* device, *which* model,
and *whose* intent produced it — and that none of it was tampered with?**

This repo explores that by putting HSM / secure-element ideas (key custody,
attestation, signing policy, provisioning) to work on agent workloads.

See [`docs/IDEAS.md`](docs/IDEAS.md) for the project roadmap.

## Planned layout

```
hsm/          PKCS#11-backed signing service (SoftHSM2 for dev)
attest/       device + model attestation (TPM/vTPM quotes, measured inference)
tokens/       device-bound, attenuable capability tokens for agent tool calls
provision/    factory provisioning simulator (device identity, CA, revocation)
docs/         design notes and threat models
```
