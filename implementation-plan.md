# OpenCred v2 Implementation Plan

## Context

OpenCred is a desktop-first W3C Verifiable Credential issuance and verification application by NFH Trust Labs. The PRD (v2.0) defines a desktop application as the primary product, with a Docker image for headless cloud deployment. All signing is local -- the issuer always signs with their own key. For issuers without a DSC, OpenCred provides Key Attestation (signing the issuer's public key with OpenCred's DSC).

**Decisions:**
- **Stack:** TypeScript / Node.js
- **v2 Scope:** Desktop Client (primary) + Docker Image (headless)
- **Eliminated from v1:** Web UI (`apps/web`), standalone REST API (`apps/api`), Interface Signing, Delegated Signing, capability tokens, delegation certificates
- **New in v2:** Key Attestation (`packages/key-attestation`), SVG templates (`packages/templates`), Docker entrypoint (`apps/server`)
- **DeDi:** Live, API available
- **Deferred (issuance/protocol):** did:web, KERI, JWT/SD-JWT issuance, OpenID4VCI, Cloud KMS in browser
- **Verification flexibility:** Multi-format verification supported (Data Integrity, VC-JWT, SD-JWT VC) even though v2 issuance is Data Integrity only
- **Dev mode:** Solo developer with Claude Code -- accelerated execution
- **Integration branch:** `new-opencred-dev` (permanent)

**Bitstring Status List Policy:**
OpenCred v2 does not generate or host Bitstring Status Lists. Issuer-managed BitstringStatusList endpoints are supported by the verifier when `credentialStatus.type` is `BitstringStatusListEntry`.

**revocationRegistryUrl Policy:**
OpenCred accepts `revocationRegistryUrl` as issuer-provided input. The service validates only basic URL requirements (parseable HTTPS URL, optional DeDi host restrictions) and reuses the exact value across build/package flow. OpenCred does NOT verify namespace ownership. Issuer is responsible for revocation registry misconfiguration.

**Revocation Publishing Policy:**
OpenCred does NOT publish revocation hashes to DeDi. OpenCred only computes revocation hashes (JCS → SHA-256). The issuer is responsible for publishing hashes to their own DeDi revocation registry using their own credentials. The Desktop Client supports this by accepting issuer DeDi credentials per publish request.

---

## Architecture

### Monorepo Structure (pnpm workspaces + Turborepo)

```
opencred/
  pnpm-workspace.yaml
  tsconfig.base.json
  vitest.workspace.ts

  packages/
    vc-core/           # W3C VC Data Model 2.0 construction
    crypto/            # Data Integrity proofs, cryptosuites, JCS, hashing
    did/               # DID resolution (did:key)
    dedi-client/       # DeDi HTTP client (revocation, DID cache)
    schema-engine/     # JSON Schema validation, built-in schema registry
    verification/      # Verification orchestrator (multi-format)
    key-attestation/   # Key attestation builder, validator, JSON-LD context
    templates/         # SVG template registry, renderer
    shared/            # Shared types, errors, constants

  apps/
    desktop/           # Desktop Client (Electron)
      src/
        main/          # Electron main process
        renderer/      # UI (React)
        signing/       # Local signing engine
        packaging/     # QR + PDF + SVG generation
    server/            # Docker image entrypoint (headless, endpoints + CLI)
```

### Key Patterns
- **No persistent credential storage**: All credential data is ephemeral within TTL (default 4h)
- **No DI framework**: Factory functions with explicit dependencies
- **Error hierarchy**: `OpenCredError` base class → domain-specific subclasses (including `AttestationError`)
- **JSON-LD contexts**: Bundled at build time, custom document loader (never fetch remote in production)
- **Config**: Environment variables validated with Zod at startup
- **All signing is local**: Issuer always signs with their own key; OpenCred never signs credentials

### Key npm Packages

| Package | Purpose |
|---|---|
| `zod` | Schema/config validation |
| `jsonld` | JSON-LD processing |
| `@digitalbazaar/data-integrity` | DataIntegrityProof framework |
| `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite` | ecdsa-rdfc-2019 cryptosuite |
| `@digitalbazaar/ecdsa-multikey` | ECDSA key management |
| `json-canonicalize` | JCS (RFC 8785) for revocation hashes |
| `ajv` + `ajv-formats` | JSON Schema validation |
| `uuid` | Credential IDs |
| `pino` | Structured logging |
| `vitest` | Testing |
| `electron` + `electron-builder` | Desktop Client |
| `electron-store` | Desktop local config |
| `qrcode` | QR code generation |
| `hono` + `@hono/node-server` | Docker image HTTP endpoints |

---

## Phases

### Phase 0: Core Foundation (DONE)
> All library packages with comprehensive tests. No app code.

**`packages/vc-core`** -- VC Construction Engine
- Build unsigned VCs conforming to W3C VC Data Model 2.0
- `CredentialBuilder`: schema + issuer + credentialSubject + dates → complete unsigned VC
- Generate `urn:uuid:*` IDs, set `validFrom`/`validUntil`, embed `credentialStatus`
- Manage `@context` arrays (W3C credentials/v2 + data-integrity/v1 + key-attestation/v1)
- Bundle JSON-LD contexts as static files with custom document loader

**`packages/crypto`** -- Data Integrity Proof Engine
- W3C VC Data Integrity 1.0 proof generation/verification (ecdsa-rdfc-2019)
- Full local signing path: `signCredential()`
- Verification: `verifyProof()`
- JCS canonicalization (RFC 8785) for revocation hashes
- SHA-256 hashing via Node.js native `crypto`
- Built on `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite` + `@digitalbazaar/data-integrity`

**`packages/did`** -- DID Resolution
- `did:key` -- decode multibase public key from DID string (P-256 multicodec: `0x1200`)
- Unified resolver interface (extensible for did:web later)

**`packages/dedi-client`** -- DeDi Integration
- HTTP client against live DeDi API
- `publishRevocationHash()`, `queryRevocationHash()`, `resolveDID()`
- Retry logic, timeouts, circuit breaking

**`packages/schema-engine`** -- Schema Validation
- `ajv`-based JSON Schema validation
- Built-in schemas: education, employment, identity, health, business
- Custom schema registration with validation
- Map credential types to JSON-LD contexts

**`packages/verification`** -- Verification Engine (multi-format)
- Common interface dispatches by credential/proof format:
  - `verifyDataIntegrity()` -- W3C Data Integrity proofs (ecdsa-rdfc-2019)
  - `verifyVcJwt()` -- VC-JWT format (for business VC onboarding input)
  - `verifySdJwtVc()` -- SD-JWT VC format (for business VC onboarding input)
- Parse issuer field → determine key retrieval method
- did:key → decode embedded key
- Verify proof signature (format-specific)
- DSC/CSCA chain validation (Node.js `crypto.X509Certificate`)
- Key Attestation chain validation (attestation → OpenCred DSC → CSCA)
- Check `validFrom`/`validUntil` dates
- Compute revocation hash → query DeDi
- BitstringStatusList check when `credentialStatus.type` is `BitstringStatusListEntry`
- Result codes: VALID / REVOKED / EXPIRED / INVALID / UNRESOLVABLE / ATTESTATION_INVALID

**`packages/key-attestation`** -- Key Attestation
- `KeyAttestationBuilder`: build Key Attestation Credentials binding issuer public key to identity
- `KeyAttestationValidator`: validate attestation chain (signature, expiry, key match)
- Custom JSON-LD context (`OPENCRED_KEY_ATTESTATION_V1_CONTEXT`)
- Bundled context document

**`packages/templates`** -- SVG Templates
- SVG template registry (per-schema templates)
- Template renderer (credential data → SVG output)

**Testing:** W3C VC Data Integrity test vectors, NIST ECDSA P-256 vectors, RFC 8785 JCS test data. Target 90%+ coverage on crypto, vc-core, key-attestation.

---

### Phase 1: Desktop -- DSC Import + Local Signing (DONE)
> Issuer with DSC can import their certificate and sign credentials locally.

**DSC Import Module:**
- PFX/PEM file parsing and certificate extraction
- Certificate metadata extraction (subject, issuer, validity, key algorithm)
- DID derivation from DSC public key (`did:key`)
- X.509 chain validation against configured CSCA trust store

**Desktop UI:**
- 4-tab layout: Issue, Verify, Settings, (Onboarding for new users)
- `IssuePage`: schema selection, credential data entry, sign + export
- `VerifyPage`: paste/upload VC JSON → verification result display
- `SettingsPage`: key management, trust store config
- `OnboardingWizard`: DSC import flow

**Credential Export:**
- SVG template rendering using `@opencred/templates`
- JSON-LD export (complete VC with proof)
- QR code generation (VC data encoded)

**Local Signing Flow:**
1. Select schema (built-in or custom)
2. Validate payload against schema
3. Build VC + proof input (Data Integrity)
4. Embed `credentialStatus` (issuer-provided `revocationRegistryUrl`)
5. Sign VC with DSC private key (Node.js `crypto`)
6. Package output (SVG, JSON-LD, QR)

**Testing:** Full round-trip: import DSC → build VC → sign → export → verify. DSC chain validation against test CSCA. PFX and PEM import paths.

---

### Phase 2: Desktop -- OpenCred-Attested + Key Attestation (DONE)
> Issuers without DSC can generate keys, get attested by OpenCred, and sign credentials.

**Key Generation:**
- ECDSA P-256 keypair generation via `crypto.generateKeyPairSync()`
- Key storage in local attestation store (in-memory Map, persisted to disk)
- DID derivation from generated public key

**Attestation Store:**
- In-memory Map with persistence
- 5 IPC channels for renderer ↔ main process communication
- Store, retrieve, list, delete attestation entries
- Proof embedding in credential signatures

**Desktop UI -- Onboarding Wizard (OpenCred-Attested flow):**
- `KeyGenerationStep`: generate ECDSA P-256 keypair
- `OrganizationInfoStep`: collect issuer identity info
- `DomainVerificationStep`: domain verification challenge (mock in Phase 2, real in Phase 3)
- `AttestationResultStep`: display attestation result + attested key info

**Key Attestation by OpenCred:**
- API endpoints: `POST /attestation/challenge` + `POST /attestation/challenge/:id/verify`
- OpenCred signs issuer's public key with its DSC
- Returns Key Attestation Credential to issuer
- Issuer embeds attestation in credential proofs

**Testing:** Key generation round-trip. Attestation store CRUD. IPC channel integration. Proof embedding and verification.

---

### Phase 3: Desktop -- Issuer Authentication + CA Integration
> Full issuer authentication for OpenCred-Attested flow + CA extension point.

**Domain Verification (Full Implementation):**
- DNS TXT challenge: generate `opencred-verify=<token>`, verify via `dns.resolveTxt()`
- HTTP challenge: place file at `https://<domain>/.well-known/opencred-challenge/<token>`, verify via HTTPS fetch
- Challenge tokens: 256-bit entropy (CSPRNG)
- 24h challenge expiry

**Business VC Verification:**
- Accept existing verifiable credentials as identity proof for OpenCred-Attested auth
- Verify business VC signature, revocation status, and expiry using `packages/verification`
- Multi-format support: Data Integrity, VC-JWT, SD-JWT VC
- Extract issuer identity from verified business VC

**CA API Integration (Extension Point):**
- Define `CertificateAuthorityAdapter` interface: `requestDSC()`, `checkStatus()`
- No implementations in v2 -- extension point only
- User Type 2 (Issuer Seeking DSC) flow: CA request → DSC received → import as Type 1

**Verification Engine Updates:**
- Full Key Attestation chain validation in production (Phase 2 had mock)
- `ATTESTATION_INVALID` result code for failed attestation chains

**Security:** DNS cache poisoning mitigation (multiple resolvers). HTTP challenge SSRF prevention (validate resolved IP is public). Challenge tokens: 256-bit entropy. 24h challenge expiry.

**Testing:** Domain verification with mock DNS/HTTP. Business VC verification (valid + invalid). CA adapter interface tests. End-to-end attestation flow.

---

### Phase 4: Desktop -- Hardware Tokens + OS Cert Store
> Add hardware token and OS certificate store signing to the Desktop Client.

**PKCS#11 Hardware Token Support:**
- `pkcs11js` or `graphene-pk11` npm bindings
- PIN entry and session management flow
- Supports USB tokens (ePass, SafeNet, YubiKey), smart cards
- Signature byte format conversion (DER ↔ raw) if needed for proof engine compatibility
- Key management UI: connect hardware tokens, list available keys, select signing key

**OS Certificate Store Signing:**
- **Windows:** CNG/CryptoAPI bindings via N-API native addon -- enumerate certs from Windows Certificate Store, sign with non-exportable keys
- **macOS:** Security.framework bindings via N-API native addon -- enumerate certs from Keychain, sign with non-exportable keys
- **Linux:** PKCS#11 fallback (hardware tokens) or PEM file import (software keys)
- UI: browse OS cert store, select signing certificate, sign VC using platform-native APIs
- Signature byte format conversion if needed for Data Integrity proof compatibility

**Additional npm packages:** `node-gyp` (build tooling for native addons)

**Testing:** PKCS#11 mock tests via `softhsm2`. Platform-specific cert store enumeration + signing on Windows and macOS. Hardware token signing round-trip. E2E: select OS cert → sign VC → verify.

---

### Phase 5: Desktop -- Bulk Issuance + Distribution
> Batch credential processing and production distribution.

**Bulk Issuance:**
- CSV file import with column-to-field mapping
- Validate-first-then-issue two-phase processing
- Batch signing with issuer's key (software, hardware, or OS cert store)
- Batch QR/PDF/SVG packaging
- Progress tracking UI with per-row status
- Max 500-1,000 rows per batch (v2 limit)

**Batch Revocation:**
- Batch revocation hash computation from loaded credentials
- Queue hashes for publish to DeDi when online using issuer's DeDi credentials

**Distribution:**
- Code signing: Apple notarization, Windows Authenticode
- Auto-update mechanism (`electron-updater`)
- Schema library updates delivered via auto-update

**E2E Testing:** Playwright tests for full issue/verify/revoke flows. Batch processing at limit (1000 rows). CSV import with validation errors. Offline queue drain.

---

### Phase 6: Docker Image (`apps/server`)
> Headless version of the Desktop Client for cloud deployment and workflow integration.

**Server Entrypoint:**
- Thin Hono-based HTTP server wrapping shared packages
- Same credential issuance, verification, and key attestation capabilities as Desktop -- minus the GUI
- Shared packages (`vc-core`, `crypto`, `did`, `verification`, `schema-engine`, `key-attestation`, `templates`) wired via factory functions

**Endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/credentials/issue` | POST | Build + sign credential (key loaded at startup or per-request) |
| `/credentials/verify` | POST | Verify credential (full chain) |
| `/credentials/batch` | POST | Submit batch issuance job |
| `/credentials/batch/{jobId}` | GET | Poll batch status |
| `/credentials/batch/{jobId}/results` | GET | Retrieve batch results |
| `/credentials/revocation-hash` | POST | Compute revocation hash (single) |
| `/credentials/revocation-hash/batch` | POST | Compute revocation hashes (batch) |
| `/attestation/challenge` | POST | Request attestation challenge |
| `/attestation/challenge/:id/verify` | POST | Submit proof + get Key Attestation Credential |
| `/schemas` | GET | List available schemas |

**Authentication:**
- Optional API key auth via `OPENCRED_API_KEY` environment variable
- Simple middleware: if env var set, require `Authorization: Bearer <key>` on all endpoints
- No JWT system, no capability tokens, no user accounts

**Cloud HSM Signing Support:**
- AWS KMS: `@aws-sdk/client-kms` for sign operations
- Azure Key Vault: `@azure/keyvault-keys` for sign operations
- GCP Cloud KMS: `@google-cloud/kms` for sign operations
- Key reference via environment variables (e.g., `OPENCRED_KMS_KEY_ARN`)

**CLI Mode:**
- `opencred issue --schema education --input data.json --key key.pem --output cred.json`
- `opencred verify --input cred.json`
- `opencred hash --input cred.json`
- `opencred batch --schema education --input data.csv --key key.pem --output-dir ./creds/`
- Suitable for CI/CD pipelines and scripting

**Testing:** Endpoint round-trip tests. Cloud HSM mock tests. CLI mode tests. Batch processing. Key attestation flow via endpoints.

---

### Phase 7: Containerization & Deployment
> Docker images, orchestration, and production deployment configuration.

**Docker Image (multi-stage build):**

`apps/server/Dockerfile` -- Headless OpenCred
- Stage 1: `node:20-alpine` -- install pnpm, copy monorepo, `pnpm install --frozen-lockfile`, build all packages + `apps/server`
- Stage 2: `node:20-alpine` -- copy built output only, run as non-root user (`node`), expose port
- Health check: `HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1`
- JSON-LD contexts bundled in image (no runtime fetching -- per security invariant)

**Docker Compose (`docker-compose.yml`):**
- `server` service: builds from `apps/server/Dockerfile`, environment variables via `.env`, port mapping, restart policy
- Optional `nginx` reverse proxy: TLS termination, rate limiting
- Shared network, named volumes for CSCA trust store PEMs
- `docker-compose.override.yml` for local dev (bind mounts, debug ports)

**Environment & Secrets:**
- `apps/server/.env.example` -- documents all required environment variables
- Secrets (OpenCred DSC for attestation, DeDi credentials) via environment variables -- never baked into images
- Zod config validation at startup catches missing/invalid env vars before the server starts

**Production Configuration:**
- `pino` JSON logging to stdout (container-native)
- Graceful shutdown handling (`SIGTERM` → drain connections → exit)
- Non-root container user in all images
- Read-only filesystem where possible (`--read-only` with tmpfs for `/tmp`)
- No `latest` tag -- images tagged with git SHA + semver

**CI/CD Pipeline Extensions (GitHub Actions):**
- `docker-build` job: build images on every PR (validates Dockerfiles compile)
- `docker-push` job (on merge to `new-opencred-dev`): build + tag + push to container registry
- Image scanning: `trivy` or `grype` for vulnerability scanning before push

**Deployment Options:**
- **Cloud Run** (GCP): auto-scaling, managed TLS, zero-infra overhead
- **GCE VM / org-managed VM**: `docker compose up -d`, systemd service, TLS via Caddy/Certbot
- Backup: CSCA trust store PEMs and `.env` only (no persistent credential data -- ephemeral by design)

**`.dockerignore`:**
- `node_modules/`, `.git/`, `apps/desktop/`, `docs/`, `*.md`, `.env`, test fixtures

**Security Hardening:**
- No `--privileged`, no `SYS_ADMIN` capabilities
- Drop all capabilities, add only `NET_BIND_SERVICE` if binding to port 80/443
- Pin base image digests in Dockerfiles for reproducible builds
- OpenCred DSC for attestation signing: mount as read-only volume or inject via env, never in image layers
- Container network isolation: egress limited to DeDi endpoints

**Testing:** Docker build succeeds in CI. Compose stack starts and `/health` returns 200. E2E smoke test against containerized stack (issue → verify → revoke). Image vulnerability scan passes with no critical/high CVEs.

---

## Verification Plan

### Per-Phase Testing
1. **Phase 0:** Unit tests against W3C test vectors, NIST ECDSA vectors, RFC 8785 JCS vectors. 90%+ coverage on crypto, vc-core, key-attestation.
2. **Phase 1:** Full round-trip: import DSC → build VC → sign → export → verify. PFX and PEM import. DSC chain validation.
3. **Phase 2:** Key generation, attestation store, IPC channels. Proof embedding + verification. Onboarding wizard flows.
4. **Phase 3:** Domain verification (DNS TXT, HTTP challenge). Business VC verification. CA adapter interface. ATTESTATION_INVALID result code.
5. **Phase 4:** PKCS#11 mock tests (softhsm2). Platform cert store signing (Windows CNG, macOS Security.framework). Hardware token round-trip.
6. **Phase 5:** Batch validation rejection, partial failure, batch at limit (1000 rows). CSV import. Playwright E2E. Auto-update. Code signing.
7. **Phase 6:** Docker endpoint round-trips. Cloud HSM mock. CLI mode. Batch via endpoints. Key attestation via endpoints.
8. **Phase 7:** Docker images build in CI. Compose stack starts. `/health` returns 200. Image vulnerability scan. E2E against containerized stack.

### End-to-End Verification
After each phase, run the complete flow manually:
- **Phase 1:** Import DSC → build VC → sign locally → export → verify → revoke → verify returns REVOKED
- **Phase 2:** Generate key → get attestation → sign VC with attested key → verify with attestation chain → verify returns ATTESTATION_INVALID for bad chain
- **Phase 3:** Verify domain → attest key → sign VC → verify full chain. Verify with business VC → attest → sign → verify.
- **Phase 4:** Connect hardware token → sign VC → verify. Select OS cert → sign VC → verify.
- **Phase 5:** Upload CSV batch → sign all → package → verify random sample. QR round-trip. PDF embedding.
- **Phase 6:** Docker endpoint: issue → verify → revoke → verify returns REVOKED. CLI: issue → verify. Cloud HSM: issue → verify.
- **Phase 7:** `docker compose up` → `/health` returns 200 → issue credential via endpoint → verify → revoke → verify returns REVOKED. All running in containers.

### CI Pipeline
- GitHub Actions: lint + type-check + test on every PR
- Separate jobs per package (parallel execution)
- Integration test job that runs after package tests pass
- **Desktop build matrix:** macOS, Windows, Linux smoke builds (from Phase 4 onward)
- **Docker build + push** (from Phase 7 onward): build images on PR, push to registry on merge to `new-opencred-dev`, vulnerability scan gate

---

## Critical Files

| File | Why it matters |
|---|---|
| `packages/crypto/src/data-integrity.ts` | Core proof engine: local signing path (`signCredential()`), verification (`verifyProof()`). Built on Digital Bazaar libs. |
| `packages/vc-core/src/credential-builder.ts` | Every issuance flow depends on this to correctly assemble W3C VC 2.0 documents |
| `packages/verification/src/verifier.ts` | Orchestrates verification -- dispatches by proof format, 6 result codes, attestation chain validation |
| `packages/verification/src/vc-jwt.ts` | VC-JWT verification (for business VC onboarding input) |
| `packages/verification/src/sd-jwt-vc.ts` | SD-JWT VC verification (for business VC onboarding input) |
| `packages/key-attestation/src/builder.ts` | Builds Key Attestation Credentials binding issuer public key to verified identity |
| `packages/key-attestation/src/validator.ts` | Validates attestation chain: signature, expiry, key match |
| `packages/templates/src/registry.ts` | SVG template registry -- maps schemas to templates |
| `apps/desktop/src/signing/software-signer.ts` | PEM/JWK/PFX key loading + signing |
| `apps/desktop/src/signing/pkcs11-signer.ts` | Hardware token integration (Phase 4) |
| `apps/desktop/src/signing/os-cert-signer.ts` | Native OS cert store signing -- Windows CNG + macOS Security.framework bindings (Phase 4) |
| `apps/desktop/src/main/index.ts` | Electron main process: key store access, attestation store, IPC handlers |
| `apps/server/src/index.ts` | Docker image entrypoint: Hono HTTP server + CLI dispatch |
| `apps/server/Dockerfile` | Multi-stage image -- bundles all packages, JSON-LD contexts, runs as non-root |
| `docker-compose.yml` | Orchestrates server + optional reverse proxy for deployment |
| `.github/workflows/docker.yml` | CI/CD: build images on PR, push to registry on merge, vulnerability scan |
| `OpenCred_PRD.md` | Source of truth for all implementation decisions |

---

## 2026-06 — Production-readiness & credential-matrix workstream

Post-phase-7 hardening driven by the 2026-06-10 production-readiness audit and the goal that **every valid credential permutation issues and verifies, with full DeDi key lifecycle, on both Desktop and Docker**. Plan of record: [`docs/plans/credential-matrix-dedi-plan.md`](docs/plans/credential-matrix-dedi-plan.md); the resulting contract: [`docs/concepts/support-matrix.md`](docs/concepts/support-matrix.md).

Delivered (issues #675–#682): vc-jwt JSON-envelope verification with envelope-consistency cross-validation; verify-sdk structured-failure facade + first test suite + LICENSE; `publicKeyJwk` surfaced by every signer type (Cloud HSM, PKCS#11, OS cert store) unblocking DeDi key lifecycle for all key sources; PS256 added to vc-jwt/sd-jwt-vc verification allowlists (RSA credentials were unverifiable); RSA software keys can boot the server (did:jwk accepted as a self-describing issuer DID); expired vc-jwts classify as EXPIRED; per-key status writes serialised + Retry-After honoured on 429; E2E matrix harness (`e2e/`, release-gate on `v*` tags since 2026-07, originally nightly) exercising every valid cell against the real Docker image, with env-gated DeDi staging lifecycle cells.
