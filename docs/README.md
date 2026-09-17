# OpenCred Documentation

OpenCred is a local-first platform for issuing and verifying W3C Verifiable Credentials. It ships as a **Desktop Client** (Electron) for interactive use and a **Docker Image** (headless HTTP API + CLI) for cloud and CI/CD deployment. Issuer private keys never leave the issuer's environment — all signing happens locally on the issuer's machine or inside the issuer-operated container.

OpenCred is published by [NFH Trust Labs](https://github.com/nfh-trust-labs).

> **Open source.** OpenCred is open source under the [MIT licence](https://github.com/nfh-trust-labs/opencred/blob/main/LICENSE). Source code, issues, and release notes live at [github.com/nfh-trust-labs/opencred](https://github.com/nfh-trust-labs/opencred); contributions are welcome — see [CONTRIBUTING.md](https://github.com/nfh-trust-labs/opencred/blob/main/CONTRIBUTING.md). Desktop installers ship for macOS, Windows, and Linux. On first launch macOS shows a one-time approval prompt (see the [installation guide](desktop/installation.md#macos-first-launch)).
>
> **Support:** for bug reports, feature requests, or questions, [open an issue](https://github.com/nfh-trust-labs/opencred/issues). Security vulnerabilities go through [private reporting](https://github.com/nfh-trust-labs/opencred/security/advisories/new), not a public issue.

## Get OpenCred

| | Where | How |
|---|---|---|
| **Desktop** (macOS / Windows / Linux) | <https://github.com/nfh-trust-labs/opencred-releases/releases> | Download the `.dmg` (Apple Silicon or Intel) / `.exe` / `.AppImage` / `.deb` for your platform |
| **Docker server** | `ghcr.io/nfh-trust-labs/opencred/opencred-server:latest` | `docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest` |

Both are public — no authentication required. The source code is open source (MIT) at <https://github.com/nfh-trust-labs/opencred>; release binaries are mirrored to the [opencred-releases](https://github.com/nfh-trust-labs/opencred-releases/releases) download repo.

## Start Here

Pick the path that matches your role.

| You are... | Start here |
|---|---|
| New to verifiable credentials | [Concepts](concepts/README.md) — what VCs, DIDs, and trust chains are |
| Running a workshop or evaluating end-to-end | [Bootcamp Guide](bootcamp/README.md) — guided 3-hour path through the Docker image |
| Installing the desktop app | [Desktop User Guide](desktop/README.md) |
| Deploying the Docker image | [Docker Operator Guide](docker/README.md) |
| **Verifying a credential someone gave you** | [Verifying credentials](#verifying-a-credential) (below) |
| Reviewing OpenCred's security posture | [Security Model](security/README.md) |
| Contributing or building from source | [Developer Guide](development/README.md) |

## Verifying a credential

Anyone holding an OpenCred-issued credential has four supported ways to verify it. All four run the same `@opencred/verification` engine — pick the surface that matches your environment.

| Path | Best for | Inputs accepted |
|---|---|---|
| **Desktop app — Verify tab** | Casual / one-off verification by humans | Pasted JSON · drag-dropped `.json` / `.jsonld` · QR-code image upload (PNG/JPG) · `.pdf` upload · live camera QR scan · pasted compact tokens (vc-jwt, sd-jwt-vc, bare PixelPass QR data) |
| **Docker server — `POST /v1/credentials/verify`** | Programmatic / server-to-server / CI/CD | JSON body for text-shaped formats (auto-detected: JSON-LD VC, vc-jwt, sd-jwt-vc, PixelPass QR data) **or** raw PDF body with `Content-Type: application/pdf` |
| **`opencred verify` CLI** | One-shot verification from a shell, no HTTP server needed | File path or stdin. Auto-detects JSON-LD, vc-jwt, sd-jwt-vc, PixelPass QR data, or PDF. `--json` flag for scripted consumers. Ships inside the public Docker image. |
| **`@opencred/verification` library** | Embedding verification inside another Node.js app | Same formats as above, via `verifyCredential` and `verifyPdf` |

In every case the result has the same shape: a top-level `valid: true|false`, an enum `code` (`VALID`, `REVOKED`, `EXPIRED`, `INVALID`, `UNRESOLVABLE`, `CONTEXT_MISSING`), and a per-check breakdown — signature, expiry, key resolution, x5c chain (where applicable), revocation, schema, context.

**`did:key`-issued credentials verify fully offline.** `did:web` credentials need network access to fetch the issuer's DID document. DSC-backed credentials carrying an `x5c` chain need a CSCA trust store on disk — see [Trust chains](concepts/trust-chains.md) and [Docker → API reference → Verify](docker/api-reference.md#post-v1credentialsverify).

**PDF certificates.** OpenCred packages credentials as printable PDFs with a scannable QR embedded **and** a copy of the credential payload tucked into the PDF's info dictionary. Either path works: drop the PDF into the desktop Verify tab, POST it to `/v1/credentials/verify`, or pipe it into `opencred verify --input -`. Older PDFs issued before the info-dict embedding shipped (no payload in metadata) surface as a clear "scan the QR or extract the embedded JSON" message rather than a generic failure.

For full step-by-step, see [Desktop → Verifying credentials](desktop/verifying-credentials.md) or [Docker → API reference](docker/api-reference.md#post-v1credentialsverify).

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

### Bootcamp

A guided, hands-on 3-hour path attendees follow at workshops or that you can use to evaluate the project end-to-end. Two parallel tracks: laptops only, or one shared cloud VM.

* [Bootcamp overview](bootcamp/README.md)
* [Local Docker track](bootcamp/local-docker.md) — every attendee runs the container on their own laptop
* [GCP VM track](bootcamp/gcp-vm.md) — one shared GCP VM, IAP-tunnelled SSH, optional Cloud KMS

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

OpenCred is open source under the [MIT license](../LICENSE). Source code, issues, and releases all live in this repository.

For end users:

* **Download a release**: <https://github.com/nfh-trust-labs/opencred-releases/releases>
* **Pull the Docker image**: `docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest`
* **Bug reports / feature requests**: <https://github.com/nfh-trust-labs/opencred/issues>

For contributors: product requirements live in [`docs/PRD.md`](PRD.md), and the contribution workflow (branch model, commit conventions, DCO) in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
