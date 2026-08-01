# OpenCred

Open-source toolkit for issuing and verifying W3C Verifiable Credentials.

## Key Features

- **Desktop app** (Electron) for interactive credential issuance with local signing
- **Docker image** for headless cloud deployment with an HTTP API
- **W3C VC 2.0 compliant** -- supports vc-jwt, data-integrity, and sd-jwt-vc proof formats
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
