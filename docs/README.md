# OpenCred Documentation

OpenCred is a local-first platform for issuing and verifying W3C Verifiable Credentials. It ships as a **Desktop Client** (Electron) for interactive use and a **Docker Image** (headless HTTP API + CLI) for cloud deployment. All signing happens locally — issuer private keys never leave the machine.

## Desktop App

- [Getting Started](desktop/getting-started.md) — install, first launch, onboarding wizard
- [Key Management](desktop/key-management.md) — key sources, algorithms, DID derivation
- [Issuing Credentials](desktop/issuing-credentials.md) — single and batch issuance, schemas, proof formats, export
- [Verifying Credentials](desktop/verifying-credentials.md) — verification flow, checks, offline mode
- [Key Attestation](desktop/attestation.md) — domain verification, business VC, OpenCred-Attested flow
- [Settings and Logging](desktop/settings-and-logging.md) — preferences, logging, bug reports, auto-updater

## Server / Docker

- [Getting Started](server/getting-started.md) — Docker build, env setup, first request
- [Configuration Reference](server/configuration.md) — all environment variables
- [API Reference](server/api-reference.md) — HTTP endpoints with request/response schemas
- [CLI Reference](server/cli-reference.md) — `opencred` command-line tool
- [Cloud HSM](server/cloud-hsm.md) — AWS KMS, Azure Key Vault, GCP Cloud KMS
- [OID4VCI](server/oid4vci.md) — OpenID for Verifiable Credential Issuance

## Other Resources

- [Deployment Guide](../deploy/README.md) — GCP Cloud Run, VM deployment, TLS
- [Demo Walkthrough](../demos/WALKTHROUGH.md) — end-to-end demos
- [Manual Test Plan](testing/manual-test-plan.md) — manual testing procedures
- [Technical Spikes](spikes/) — research findings
- [Standards Proposals](proposals/) — W3C CCG proposals
