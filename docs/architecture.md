# Architecture Overview

OpenCred is a monorepo built with pnpm workspaces and Turborepo. It ships two applications -- a Desktop Client (Electron) and a Docker Image (headless HTTP server) -- that share the same core packages for cryptography, credential building, verification, and schema management.

## Monorepo Structure

```
opencred/
  apps/
    desktop/          Electron desktop client
    server/           Headless HTTP server (Docker image)
  packages/
    crypto/           Cryptographic primitives
    vc-core/          W3C VC 2.0 credential builder
    did/              DID resolution
    verification/     Credential verification engine
    schema-engine/    JSON Schema registry
    templates/        SVG credential templates
    signing/          Signing key providers
    shared/           Shared types and utilities
    dedi-client/      DeDi client library
    ca-adapter/       Certificate authority adapter
  deploy/             Nginx config, deployment scripts
  docs/               Documentation
```

## Applications

### Desktop Client (`apps/desktop`)

An Electron application for interactive credential issuance and verification. Runs on macOS, Windows, and Linux.

- Electron main process handles signing, key management, and IPC
- Renderer process provides the UI (React)
- All signing happens locally -- private keys never leave the machine
- Supports software keys (PEM/JWK/PFX), hardware tokens (PKCS#11), and OS certificate stores (macOS Keychain, Windows CNG)

### Server (`apps/server`)

A headless HTTP API server built on Hono, designed to run as a Docker container in the issuer's infrastructure.

- Stateless request/response design -- no persistent server-side sessions
- Signing key loaded once at startup from a local file or Cloud HSM
- Bearer token authentication (fail-closed by default)
- Prometheus metrics and OpenTelemetry tracing
- Supports software keys (PEM/JWK/PFX), PKCS#11 hardware tokens, and Cloud HSM (AWS KMS, Azure Key Vault, GCP Cloud KMS)

## Package Responsibilities

### `@opencred/crypto`

Cryptographic primitives for key generation, signing, and proof construction. Supports ECDSA (P-256, P-384), EdDSA (Ed25519), and RSA (2048, 3072, 4096). Provides functions for VC-JWT, Data Integrity, and SD-JWT-VC proof preparation and completion. Includes JCS canonicalization and revocation hash computation.

### `@opencred/vc-core`

W3C Verifiable Credentials Data Model 2.0 credential builder. Handles the `@context`, `type`, `issuer`, `credentialSubject`, `validFrom`, `validUntil`, `credentialStatus`, and `credentialSchema` fields. Bundles JSON-LD context documents -- contexts are never fetched remotely at runtime (supply-chain attack prevention).

### `@opencred/did`

DID resolution for three methods:

- `did:key` -- derives the public key from the DID itself
- `did:jwk` -- decodes the JWK from the DID
- `did:web` -- resolves the DID document from the domain's `.well-known` path (with SSRF protection)

Provides a `CompositeDIDResolver` that routes resolution by method prefix.

### `@opencred/verification`

Composite credential verification engine. Runs a pipeline of checks:

- Signature verification (VC-JWT, Data Integrity, SD-JWT-VC)
- Date validation (validFrom/validUntil)
- X.509 certificate chain validation (for DSC-backed credentials)
- Revocation status check (via DeDi or Bitstring Status List)
- DID resolution

Returns a structured result with per-check pass/fail status and a top-level code (`VALID`, `REVOKED`, `EXPIRED`, `INVALID`, `UNRESOLVABLE`, `CONTEXT_MISSING`).

### `@opencred/schema-engine`

JSON Schema registry with 34+ bundled credential schemas across 8 categories: identity, education, health, energy, finance, traceability, open badges, and DIF. Provides schema validation via AJV, schema listing and lookup, and schema generation from field examples. Supports optional remote schema updates from a manifest URL.

### `@opencred/templates`

SVG credential templates for visual rendering. Templates use `{{placeholder}}` tokens substituted at render time. Supports issuer customization (colors, logos, display names). Used by the packaging pipeline to generate PDFs and QR codes.

### `@opencred/signing`

Signing key providers that abstract the key source:

- Software key files (PEM, JWK, PKCS#8, PFX)
- PKCS#11 hardware tokens (via pkcs11js native bindings)
- OS certificate stores (macOS Security.framework via N-API, Windows CNG via N-API)

Each provider exposes a `Signer` interface with `sign(data)`, `algorithm`, `id`, and `metadata`.

### `@opencred/shared`

Shared types, error hierarchy (`OpenCredError` and subclasses), SSRF protection utilities (`isPrivateIP`), credential format detection, and common constants. The error hierarchy ensures consistent error response shapes across all packages.

### `@opencred/dedi-client`

Client library for DeDi (Decentralized Directory) integration. Provides methods for publishing and querying revocation hashes, managing namespaces, and ensuring registry existence. Supports API key and bearer token authentication.

### `@opencred/ca-adapter`

Certificate authority adapter for DSC (Document Signing Certificate) facilitation. Used in the issuer auth flow where an issuer seeking a DSC interacts with a certificate authority.

## Key Flows

### Credential Issuance

```
Request (credentialSubject, schemaId, issuerDid, proofFormat)
    |
    v
Schema validation (schema-engine validates credentialSubject against schemaId)
    |
    v
Credential building (vc-core builds unsigned VC with @context, types, dates, status)
    |
    v
Proof construction (crypto prepares signing input for the chosen proof format)
    |
    v
Signing (signing provider signs the data -- key never leaves the provider)
    |
    v
Proof completion (crypto assembles the final proof from the signature)
    |
    v
Optional packaging (templates + QR generation for visual formats)
    |
    v
Response (signed credential + optional packaged outputs)
```

### Credential Verification

```
Input (signed credential -- JSON, JWT, SD-JWT-VC, or PixelPass-encoded)
    |
    v
Format detection (shared detects the credential format)
    |
    v
DID resolution (did resolves the issuer's DID to a public key)
    |
    v
Signature verification (verification checks the proof against the resolved key)
    |
    v
Date validation (verification checks validFrom/validUntil)
    |
    v
X.509 chain validation (verification validates certificate chains if present)
    |
    v
Revocation check (verification queries DeDi or Bitstring Status List if credentialStatus is present)
    |
    v
Result (verified: boolean, code, checks[])
```

### Revocation

```
Credential issued with revocationRegistryUrl
    |
    v
Server generates UUID credential ID and SHA-256 revocation hash
    |
    v
credentialStatus block added to credential (type: "dedi", linking to the registry)
    |
    v
Later: POST /v1/credentials/revoke publishes the hash to DeDi
    |
    v
Verifiers: POST /v1/credentials/verify queries DeDi for revocation status
```

## Security Model

OpenCred's security model is built around seven mandatory invariants enforced throughout the codebase:

1. **Local signing only.** Private keys are loaded at startup and never accepted via the API. The server is a signing oracle -- it holds the key in memory and signs on behalf of the issuer. The key is loaded from a local file, PKCS#11 device, or Cloud HSM.

2. **Bundled JSON-LD contexts.** The `@opencred/vc-core` package ships all required JSON-LD contexts in `src/contexts/`. Contexts are never fetched from the network at runtime, preventing supply-chain attacks through malicious context documents.

3. **SSRF protection.** `did:web` resolution and any outbound HTTP calls validate that target IPs are public. Private, loopback, link-local, and IPv4-mapped IPv6 addresses are rejected. HTTPS only, no redirects, 10-second timeout.

4. **Sanitized error responses.** All errors flow through the `OpenCredError` hierarchy, which guarantees a consistent JSON shape with no key material, file paths, or internal state. The server's verify endpoint additionally strips `detail` fields from verification checks before returning them to the caller.

5. **Fail-closed authentication.** The server refuses to start without an explicit authentication decision. There is no silent fallback to unauthenticated operation.

6. **Ephemeral data.** No credential data is persisted server-side. Batch results and packaged outputs live in memory and are purged within the session TTL (default 4 hours).

7. **Defense-in-depth key rejection.** Every POST endpoint recursively scans the request body for forbidden key field names and PEM private key headers before any other processing.

For the full threat model and invariant enforcement details, see [Security documentation](security/README.md).

## Key Source Matrix

| Key Source | Desktop | Docker |
|------------|---------|--------|
| Software key file (PFX/PEM/JWK) | Yes | Yes |
| OS certificate store (macOS Keychain, Windows CNG) | Yes | N/A |
| Hardware token (PKCS#11) | Yes | Yes |
| Cloud HSM (AWS KMS, Azure Key Vault, GCP KMS) | No | Yes |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js 20+ |
| Package manager | pnpm 9+ with workspaces |
| Build orchestration | Turborepo |
| Server framework | Hono |
| Desktop framework | Electron |
| Validation | Zod (HTTP API), AJV (credential schemas) |
| Testing | Vitest |
| Logging | Pino (structured JSON) |
| Metrics | prom-client (Prometheus) |
| Tracing | OpenTelemetry (opt-in) |
| Native addons | N-API (macOS Keychain, Windows CNG), pkcs11js |
