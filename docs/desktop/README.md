# OpenCred Desktop User Guide

The OpenCred Desktop Client is an Electron application for issuing and verifying W3C Verifiable Credentials. It is the primary OpenCred product: fully local, offline-capable, and signing always happens on the user's machine. The issuer's private key never leaves the device.

## Pages in this section

* [Installation](installation.md) — supported platforms, downloading, and installing
* [Getting started](getting-started.md) — first launch, the onboarding wizard
* [Key management](key-management.md) — software keys, hardware tokens, OS cert store, generated keys
* [Issuing credentials](issuing-credentials.md) — single and batch issuance, schemas, proof formats, exports
* [Verifying credentials](verifying-credentials.md) — verification flow, offline mode
* [Settings and logging](settings-and-logging.md) — preferences, logging, redaction, bug reports, auto-updater

## Quick navigation

| Want to... | Go to |
|---|---|
| Install on macOS, Windows, or Linux | [Installation](installation.md) |
| Import an existing PFX/PEM key | [Key management — Importing a software key file](key-management.md#importing-a-software-key-file) |
| Use a YubiKey or smart card | [Key management — Connecting a hardware token](key-management.md#connecting-a-hardware-token) |
| Generate a fresh key for did:web | [Key management — Generating a key](key-management.md#generating-a-key) |
| Issue a single credential from a template | [Issuing credentials — Single issuance](issuing-credentials.md#single-credential-issuance) |
| Issue 1,000 credentials from a CSV | [Issuing credentials — Batch issuance](issuing-credentials.md#batch-issuance) |
| Verify a credential | [Verifying credentials](verifying-credentials.md) |
| Find log files for a bug report | [Settings and logging — Logging](settings-and-logging.md#logging) |

## How OpenCred Desktop is built

The Desktop Client is an Electron app split between a **main process** (Node.js) and a **renderer process** (React). All cryptographic operations — key import, signing, verification, native cert store calls — run in the main process. The renderer never sees private key material; it interacts with the main process over a typed IPC bridge defined in `apps/desktop/src/shared/ipc-types.ts`.

| Layer | Location | Responsibility |
|---|---|---|
| Main process | `apps/desktop/src/main/` | IPC handlers, key import, signing, verification, native bindings |
| Preload | `apps/desktop/src/main/preload.ts` | exposes the IPC API to the renderer via contextBridge |
| Renderer | `apps/desktop/src/renderer/` | React UI: pages, components, schemas |
| Shared | `apps/desktop/src/shared/` | TypeScript types shared by both sides of the IPC boundary |

The main process consumes the same `@opencred/*` workspace packages that the Docker server uses, so the issuance and verification logic is identical across the two interfaces.

## Related documentation

* [Concepts](../concepts/README.md) — what VCs and DIDs are
* [Security model](../security/README.md) — what OpenCred protects against
* [Docker operator guide](../docker/README.md) — the headless variant for cloud and CI/CD
