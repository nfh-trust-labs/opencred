# OpenCred

**Make trusted records portable.**

OpenCred is an open-source toolkit for issuing and verifying W3C Verifiable Credentials.
It helps institutions turn the records they already hold into signed, tamper-evident credentials
that people and businesses can keep and share to access opportunities and services.

## Why this matters

A new job. A health consultation. A place at university. A loan to grow a business. A public benefit.
Each can begin with the same request: prove something about yourself.

The evidence already exists, spread across employers, schools, hospitals, banks, and government
agencies. Yet people repeatedly collect documents, submit copies, and wait for someone to check them.
A qualification that cannot be verified can hold up a job offer. Medical records that cannot be
shared can interrupt continuity of care. Income records that cannot be trusted can limit access to
credit or public benefits.

Digitizing the paperwork alone does not establish trust. In the AI era, convincing documents can be
generated on the fly, and PDFs can be copied or altered. Meanwhile, connecting every institution to
every other institution to share data creates a growing integration burden.

OpenCred provides a building block for a different approach: **let the source sign the record, give
it to the person, and let the next service verify it.**

## From institutional silos to portable proof

Two practical changes can make trusted records easier to share and reuse: make records cryptographically verifiable, and return them to
the people or businesses they concern for custody and onward use.

A university could issue a qualification, an employer a work record, or a healthcare provider a
medical record. The holder could then choose to share it with another service. That service can check
its authenticity without building a separate connection to every source's records API.
Public-key discovery and current status checks may still require network access.

Like reusable bank connections in fintech, this creates infrastructure that many applications can
build on. Portable credentials add another possibility: the person carries verifiable evidence
between institutions, sectors, and jurisdictions wherever it is accepted.


## One foundation, many opportunities

These examples illustrate integrations that can be built around portable credentials:

| Opportunity or service | Evidence a person or business could choose to share |
| --- | --- |
| **A new job** | Qualifications, professional licenses, and employment history for a prospective employer to verify. |
| **A health consultation** | Relevant medical records, referrals, or coverage details for a new healthcare provider. |
| **Education and training** | Transcripts, prior learning, and qualifications for admission or recognition of credits. |
| **Credit and housing** | Income, bank statements, or rental history for a lender or housing provider. |
| **Public benefits** | Identity, income, residency, and household evidence for applications and renewals. |
| **Business and trade** | Registrations, licenses, and certifications for market access or supplier onboarding. |
| **Energy services** | Metering records and energy credentials for participation in energy markets or financing. |

### How it works

1. **Issue from the source.** An institution creates a signed credential from records it is authorized
   to attest to, with a defined scope and validity period.
2. **Return it to the holder.** The person or business keeps the credential in a compatible wallet
   or another storage option they control.
3. **Share for a purpose.** The holder chooses which evidence to present for a particular opportunity
   or service, disclosing only the required claims where supported.
4. **Verify and act.** The receiving organization checks the signature, issuer authority, validity,
   relevant credential status, and the relationship between the evidence and its presenter. It then
   applies its own rules or professional judgment.
5. **Reuse while current.** The holder can present the same evidence to another accepting service.
   Updated circumstances or freshness requirements call for updated credentials.

The goal is to make trusted evidence reusable so each new opportunity does not require starting
from scratch. A signature makes alterations detectable; accepting organizations still need to
establish trust in the issuer and assess whether the claims are sufficient for the intended use.
People also need accessible ways to correct records and challenge decisions.

## What OpenCred provides today

OpenCred supplies credential issuance and verification through a desktop app and a headless HTTP
API, with multiple proof formats, schema support, QR output, and DeDi integration. The technical
features and setup instructions follow below.

Building a complete service around OpenCred requires source-system connections and issuance authority,
compatible holder tools and consent flows, agreed schemas and issuer trust policies, and integration
with the receiving organization's workflow. The examples above describe possible applications of
this credential layer; they do not establish deployed sector integrations or an existing AI assistant.

If you are building tools that help people and businesses access opportunities, OpenCred offers an
open-source starting point for trusted, portable evidence. We welcome contributions from record
issuers, service providers, wallet developers, and application teams through
[GitHub issues](https://github.com/nfh-trust-labs/opencred/issues) and the
[contribution guide](CONTRIBUTING.md).

## Key Features

- **Desktop app** (Electron) for interactive credential issuance with local signing
- **Docker image** for headless cloud deployment with an HTTP API
- **W3C VC 2.0 compliant** -- supports vc-jwt, data-integrity, jws-2020 (JsonWebSignature2020), and sd-jwt-vc proof formats
- **36 bundled credential schemas** across 8 categories (identity, education, health, energy, finance, traceability, open badges, DIF), including the India Energy Stack `ies/electricity-credential/v1.2` and `ies/meter-data-credential/v0.6`
- **DeDi integration** for revocation and directory services
- **did:web issuance and key rotation** -- self-host the DID Document at your domain or publish to DeDi's `public_key_registry`; rotate keys in-place via `POST /v1/keys/rotate` without changing the DID
- **QR code generation** with PixelPass compression
- **Credential customization** -- colors, logos, seals, and issuer branding
- **PKCS#11 hardware token support** for HSM-backed signing
- **OS certificate store integration** -- macOS Keychain and Windows CNG
- **Cloud HSM support** -- AWS KMS, Azure Key Vault, GCP Cloud KMS

## Quick Start

### Desktop

Download the latest release for your platform from the [Releases](https://github.com/nfh-trust-labs/opencred-releases/releases) page.

See the [Desktop User Guide](docs/desktop/README.md) for installation and first-launch instructions.

### Docker

```bash
# Build the image
docker build -f apps/server/Dockerfile -t opencred:latest .

# Generate an API key
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

# Run with a signing key mounted read-only
docker run -d \
  --name opencred \
  -p 3100:3100 \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -v /path/to/issuer-key.pem:/secrets/issuer-key.pem:ro \
  --read-only \
  --cap-drop ALL \
  opencred:latest

# Issue a credential
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schemaId": "functional-identity/v1",
    "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "credentialSubject": {
      "name": "Jane Doe",
      "dateOfBirth": "1990-01-15",
      "nationality": "US"
    },
    "validFrom": "2026-01-01T00:00:00Z",
    "proofFormat": "vc-jwt"
  }'
```

See the [Deployment Guide](docs/deployment-guide.md) for Docker Compose, reverse proxy, and production configuration.

## Documentation

Full documentation is in the [`docs/`](docs/README.md) directory:

- [Documentation Index](docs/README.md) -- start here
- [Server API Reference](docs/api-reference.md) -- all HTTP endpoints with request/response schemas
- [Deployment Guide](docs/deployment-guide.md) -- Docker, Compose, nginx, environment variables
- [Credential Customization](docs/credential-customization.md) -- branding, colors, logos
- [Architecture Overview](docs/architecture.md) -- monorepo structure and package responsibilities

### did:web setup

Running an issuer under `did:web`? The DID Document can be **self-hosted at your own domain** (the canonical, standards-compliant path that works with every W3C did:web verifier) OR **published to DeDi's `public_key_registry`** (no domain needed, but only OpenCred-aware verifiers can resolve it). Both paths share the same signing key — only discovery differs. For key rotation under did:web, the server appends the new key to `verificationMethod[]` and keeps the old key around (annotated with `supersededAt`) so already-issued credentials continue to verify against their original `kid`.

Start with [`docs/bootcamp/local-docker.md`](docs/bootcamp/local-docker.md) §7d.i ("did:web in 5 minutes — Path A vs Path B") for the step-by-step walkthrough, or [`docs/concepts/dids.md`](docs/concepts/dids.md#publishing-your-didweb-did-document) for the trade-off discussion.

### Existing Docs

- [Concepts](docs/concepts/README.md) -- verifiable credentials, DIDs, trust chains, revocation
- [Desktop User Guide](docs/desktop/README.md) -- installation, key management, issuance
- [Docker Operator Guide](docs/docker/README.md) -- deployment, API reference, observability
- [Security Model](docs/security/README.md) -- threat model, key handling, invariants
- [Developer Guide](docs/development/README.md) -- building, testing, package layout

## Architecture

OpenCred is a monorepo built with pnpm workspaces and Turborepo.

### Apps

| App | Description |
|-----|-------------|
| `apps/desktop` | Electron desktop client for interactive credential issuance |
| `apps/server` | Headless HTTP server for Docker deployment |

### Packages

| Package | Description |
|---------|-------------|
| `packages/crypto` | Cryptographic primitives -- key generation, signing, proof construction |
| `packages/vc-core` | W3C VC 2.0 credential builder and JSON-LD context bundling |
| `packages/did` | DID resolution for did:key, did:jwk, and did:web |
| `packages/verification` | Composite credential verification engine |
| `packages/schema-engine` | JSON Schema registry with 36 bundled credential schemas |
| `packages/templates` | SVG credential templates and rendering |
| `packages/signing` | Signing key providers -- software, PKCS#11, OS cert store |
| `packages/shared` | Shared types, error hierarchy, and utilities |
| `packages/dedi-client` | Client library for DeDi revocation and directory services |
| `packages/ca-adapter` | Certificate authority adapter for DSC facilitation |

## Security

OpenCred enforces seven mandatory security invariants:

1. **Never touch issuer private keys.** All signing happens locally -- the server never receives, handles, or stores issuer private keys via the API.
2. **Never log key material.** Logs contain only key IDs and fingerprints, never private keys or signing buffers.
3. **Session data is ephemeral.** Credential payloads are purged within the configured TTL (default 4 hours).
4. **CSPRNG only.** All key generation uses `crypto.randomBytes`.
5. **No secrets in error responses.** Error responses never leak key material, internal paths, or signing buffers.
6. **JSON-LD contexts are bundled.** No remote context fetching at runtime.
7. **SSRF protection for did:web.** Resolved IPs are validated as public and the connection is pinned to them (DNS-rebinding safe), HTTPS only, no redirects, 10-second timeout.

See the [Security documentation](docs/security/README.md) for the full threat model and invariant enforcement details.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
branch model (PRs target `new-opencred-dev`), commit conventions, and the DCO
sign-off requirement. Security issues should be reported privately per
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 NFH Trust Labs. Bundled third-party material (fonts,
JSON-LD contexts, schemas) is attributed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

> **Where things live:** this repository holds the source, issues, and
> development. Release binaries are also published to
> [`opencred-releases`](https://github.com/nfh-trust-labs/opencred-releases/releases),
> which is the download page and the desktop auto-updater feed.
