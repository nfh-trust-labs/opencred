# OpenCred Documentation

OpenCred is a local-first platform for issuing and verifying W3C Verifiable Credentials. It ships as a **Desktop Client** (Electron) for interactive use and a **Docker Image** (headless HTTP API + CLI) for cloud deployment. All signing happens locally — issuer private keys never leave the machine.

## Desktop App

* [Getting Started](desktop/getting-started.md) — install, first launch, onboarding wizard
* [Key Management](desktop/key-management.md) — key sources, algorithms, DID derivation
* [Issuing Credentials](desktop/issuing-credentials.md) — single and batch issuance, schemas, proof formats, export
* [Verifying Credentials](desktop/verifying-credentials.md) — verification flow, checks, offline mode
* [Key Attestation](desktop/attestation.md) — domain verification, business VC, OpenCred-Attested flow
* [Settings and Logging](desktop/settings-and-logging.md) — preferences, logging, bug reports, auto-updater

## Docker Image (Self-Hosted)

The Docker image is the headless version of the Desktop app for deploying in your own infrastructure. All operations run locally — no data is sent to OpenCred.

* [Getting Started](self-hosted/getting-started.md) — Docker build, env setup, first request
* [Configuration Reference](self-hosted/configuration.md) — all environment variables
* [API Reference](self-hosted/api-reference.md) — endpoints exposed by your deployment
* [CLI Reference](self-hosted/cli-reference.md) — `opencred` command-line tool
* [Cloud HSM](self-hosted/cloud-hsm.md) — AWS KMS, Azure Key Vault, GCP Cloud KMS
* [OID4VCI](self-hosted/oid4vci.md) — OpenID for Verifiable Credential Issuance

## Other Resources

* [Deployment Guide](../deploy/) — GCP Cloud Run, VM deployment, TLS
* [Demo Walkthrough](../demos/WALKTHROUGH.md) — end-to-end demos

