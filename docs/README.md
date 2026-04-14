# OpenCred Documentation

OpenCred is a local-first platform for issuing and verifying W3C Verifiable Credentials. It ships as a **Desktop Client** (Electron) for interactive use and a **Docker Image** (headless HTTP API + CLI) for cloud and CI/CD deployment. Issuer private keys never leave the issuer's environment — all signing happens locally on the issuer's machine or inside the issuer-operated container.

OpenCred is published by [NFH Trust Labs](https://github.com/nfh-trust-labs).

## Start Here

Pick the path that matches your role.

| You are... | Start here |
|---|---|
| New to verifiable credentials | [Concepts](concepts/README.md) — what VCs, DIDs, and trust chains are |
| Installing the desktop app | [Desktop User Guide](desktop/README.md) |
| Deploying the Docker image | [Docker Operator Guide](docker/README.md) |
| Reviewing OpenCred's security posture | [Security Model](security/README.md) |
| Contributing or building from source | [Developer Guide](development/README.md) |

## Documentation Sections

### Concepts

Background reading for anyone working with OpenCred.

* [Concepts overview](concepts/README.md)
* [Verifiable Credentials](concepts/verifiable-credentials.md) — what a VC is, payload structure, proof formats, status
* [DIDs](concepts/dids.md) — `did:key`, `did:jwk`, and `did:web`, and when to use each
* [Trust chains](concepts/trust-chains.md) — the three issuer types and how trust flows
* [Revocation](concepts/revocation.md) — how OpenCred handles status checks and DeDi

### Desktop Client

Interactive credential issuance and verification on macOS, Windows, and Linux.

* [Desktop overview](desktop/README.md)
* [Installation](desktop/installation.md)
* [Getting started](desktop/getting-started.md) — first launch and onboarding wizard
* [Key management](desktop/key-management.md) — DSC import, hardware tokens, OS cert store, generated keys
* [Issuing credentials](desktop/issuing-credentials.md) — single and batch issuance
* [Verifying credentials](desktop/verifying-credentials.md)
* [Settings and logging](desktop/settings-and-logging.md)

### Docker Image

Headless deployment for cloud, on-prem, and CI/CD pipelines. The Docker image runs in **your** infrastructure — no data is sent to OpenCred or NFH Trust Labs.

* [Docker overview](docker/README.md)
* [Deployment](docker/deployment.md) — `docker run`, Compose, environment variables, volumes
* [API reference](docker/api-reference.md) — HTTP endpoints
* [CLI reference](docker/cli-reference.md) — `opencred` command-line tool
* [Cloud HSM](docker/cloud-hsm.md) — AWS KMS, Azure Key Vault, GCP Cloud KMS
* [Observability](docker/observability.md) — logging, health checks, metrics
* [OID4VCI](docker/oid4vci.md) — OpenID for Verifiable Credential Issuance (planned)

### Security Model

How OpenCred handles keys, what it protects against, and where the guarantees are enforced.

* [Security overview](security/README.md)
* [Threat model](security/threat-model.md) — what we protect against and what we don't
* [Key handling](security/key-handling.md) — the never-touch-issuer-keys guarantee
* [Invariants](security/invariants.md) — the seven mandatory rules and where they're enforced

### Developer Guide

Contributing to OpenCred itself.

* [Developer overview](development/README.md)
* [Package layout](development/package-layout.md) — monorepo structure
* [Building](development/building.md) — pnpm, Turborepo, native addons
* [Testing](development/testing.md) — vitest, integration tests, coverage

## Reference Docs

Standalone reference documents for quick access:

* [Server API Reference](api-reference.md) -- all HTTP endpoints with request/response schemas and curl examples
* [Deployment Guide](deployment-guide.md) -- Docker, Compose, nginx reverse proxy, environment variables, production checklist
* [Credential Customization](credential-customization.md) -- branding colors, logos, display names for packaged credentials
* [Architecture Overview](architecture.md) -- monorepo structure, package responsibilities, key flows, security model

## Source of Truth

Requirements live in [`OpenCred_PRD.md`](../OpenCred_PRD.md). The implementation plan is in [`implementation-plan.md`](../implementation-plan.md). Per-issue work is tracked on [GitHub Issues](https://github.com/nfh-trust-labs/opencred/issues). The contributor protocol is in [`CLAUDE.md`](../CLAUDE.md).
