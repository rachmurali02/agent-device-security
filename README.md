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
core/         no_std Rust trusted core: keys, mechanisms, policy engine, counters, audit log
emulator/     host-side HSM emulator running the core over a framed transport
pkcs11/       PKCS#11 v3 provider (cdylib) incl. vendor agent-action mechanism
tools/        admin CLI: policy bundles, quorum signing, audit verification
fuzz/         cargo-fuzz targets + fault-injection harness
firmware/     RP2350 (TrustZone-M) port and secure bootloader
docs/         design notes, threat model, key ceremony
```
