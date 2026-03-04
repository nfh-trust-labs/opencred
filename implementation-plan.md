# OpenCred v1 Implementation Plan

## Context

OpenCred is a stateless W3C Verifiable Credential issuance and verification service by NFH Trust Labs. The PRD (981 lines) is complete. No code exists yet — greenfield implementation. Goal: accelerated development without compromising testing or security. Target: 1M users across DeDi + OpenCred by July 2026.

**Decisions:**
- **Stack:** TypeScript / Node.js
- **Dependencies:** Build from scratch using W3C specs + npm modules as needed
- **v1 Scope:** REST API + Web UI + Desktop Client (all three interfaces)
- **DeDi:** Live, API available
- **Deferred (issuance/protocol):** did:web, KERI, JWT/SD-JWT issuance, OpenID4VCI, Cloud KMS in browser
- **Verification flexibility:** Multi-format verification supported (Data Integrity, VC-JWT, SD-JWT VC) even though v1 issuance is Data Integrity only
- **Dev mode:** Solo developer with Claude Code — accelerated execution

**PRD Issues to Address During Implementation:**
1. Delegation certificate JSON-LD structure needs to be defined (PRD underspecifies)
2. Capability token format/lifecycle needs design (PRD only mentions the concept)
3. Native Signing Bridge (Path B) — included via Desktop Client; Web UI bridge deferred

**Bitstring Status List Policy:**
OpenCred v1 does not generate or host Bitstring Status Lists. Issuer-managed BitstringStatusList endpoints are supported by the verifier when `credentialStatus.type` is `BitstringStatusListEntry`.

**revocationRegistryUrl Policy:**
OpenCred accepts `revocationRegistryUrl` as issuer-provided input. The service validates only basic URL requirements (parseable HTTPS URL, optional DeDi host restrictions) and reuses the exact value across build/package flow. OpenCred does NOT verify namespace ownership. Issuer is responsible for revocation registry misconfiguration.

**Revocation Publishing Policy:**
OpenCred does NOT publish revocation hashes to DeDi. OpenCred only computes revocation hashes (JCS → SHA-256). The issuer is responsible for publishing hashes to their own DeDi revocation registry using their own credentials. The Desktop Client supports this by accepting issuer DeDi credentials per publish request.

---

## Architecture

### Framework: Hono
TypeScript-first, lightweight, Zod-integrated. Runs on Node.js with clean middleware model.

### Monorepo Structure (pnpm workspaces)

```
opencred/
  pnpm-workspace.yaml
  tsconfig.base.json
  vitest.workspace.ts

  packages/
    vc-core/           # W3C VC Data Model 2.0 construction
    crypto/            # Data Integrity proofs, cryptosuites, JCS, hashing
    did/               # DID resolution (did:key only in v1)
    dedi-client/       # DeDi HTTP client (revocation, DID cache, delegation registry)
    auth/              # JWT capability tokens, scope checks
    state/             # Sessions + jobs TTL store (in-memory Map, 4h purge)
    schema-engine/     # JSON Schema validation, built-in schema registry
    delegation/        # Delegation certificate create/validate/embed
    verification/      # Verification orchestrator — multi-format (Data Integrity, VC-JWT, SD-JWT VC)

  apps/
    api/               # REST API (Hono)
      routes/          # credentials, verification, batch, onboarding, health
      middleware/      # auth, rate-limit, error-handler, request-logger
    web/               # Web UI (React + Vite + Tailwind)
    desktop/           # Desktop Client (Electron + Local Signing)
      src/
        main/          # Electron main process
        renderer/      # UI (shared components with web/)
        signing/       # Local signing engine
        packaging/     # Offline QR + PDF generation
```

### Key Patterns
- **Ephemeral-state:** No persistent credential storage; transient in-memory TTL state for sessions/jobs — lives in `packages/state`
- **No DI framework:** Factory functions with explicit dependencies
- **Error hierarchy:** `OpenCredError` base class → domain-specific subclasses → HTTP status mapping in middleware
- **JSON-LD contexts:** Bundled at build time, custom document loader (never fetch remote in production)
- **Config:** Environment variables validated with Zod at startup

### Key npm Packages

| Package | Purpose |
|---|---|
| `hono` + `@hono/node-server` + `@hono/zod-validator` | API framework |
| `zod` | Schema/config validation |
| `jsonld` | JSON-LD processing |
| `@digitalbazaar/data-integrity` | DataIntegrityProof framework |
| `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite` | ecdsa-rdfc-2019 cryptosuite |
| `@digitalbazaar/ecdsa-multikey` | ECDSA key management |
| `json-canonicalize` | JCS (RFC 8785) for revocation hashes |
| `ajv` + `ajv-formats` | JSON Schema validation |
| `jose` | JWT for capability tokens |
| `uuid` | Credential IDs |
| `pino` | Structured logging |
| `vitest` | Testing |
| `electron` + `electron-builder` | Desktop Client |
| `electron-store` | Desktop local config |

---

## Risk Spikes (Pre-Phase 0, 3–5 days)

Prove critical technical assumptions before committing to the full build. Each spike produces a minimal working proof-of-concept or a documented decision to change approach.

### Spike 1: VC Data Integrity External Signing
**Goal:** Prove `prepareProof()` / `completeProof()` works end-to-end with Digital Bazaar library stack.
- Validate exact `dataToSign` generation from an unsigned VC
- Validate ECDSA signature encoding (DER vs raw) compatibility
- Assemble final proof from external signature bytes
- **Deliverable:** One working build → external sign → complete proof → verify round-trip

### Spike 2: DSC / CSCA Validation
**Goal:** Prove the planned PKI validation approach works for expected certificate chains.
- Test chain parsing, trust-anchor loading, validity checks, and failure modes using Node.js `crypto.X509Certificate`
- Decide whether Node-native APIs are sufficient or if a dedicated PKI library is needed
- **Deliverable:** Verification of a known-good test DSC chain + expected failure cases

### Spike 3: Desktop PKCS#11 Integration
**Goal:** Prove Electron + Node can load a PKCS#11 library and perform a signing operation.
- Validate PIN/session flow and signature byte format compatibility with the VC proof engine
- Test on at least one target OS
- **Deliverable:** Minimal Electron/Node signing proof-of-concept using a hardware token or mock PKCS#11 module (`softhsm2`)

### Spike 4: Multi-Format VC Verification (for Type D)
**Goal:** Validate verification of at least one VC-JWT and/or SD-JWT VC using chosen libraries, to confirm Type D onboarding can accept business credentials in multiple proof formats.
- Test VC-JWT parsing and signature verification
- Test SD-JWT VC parsing, disclosure handling, and signature verification
- **Deliverable:** Onboarding verification PoC per selected format

---

## Phases

### Phase 0: Core Foundation
> All library packages with comprehensive tests. No API, no UI.

**`packages/vc-core`** — VC Construction Engine
- Build unsigned VCs conforming to W3C VC Data Model 2.0
- `CredentialBuilder`: schema + issuer + credentialSubject + dates → complete unsigned VC
- Generate `urn:uuid:*` IDs, set `validFrom`/`validUntil`, embed `credentialStatus` (issuer-provided `revocationRegistryUrl`, validated as parseable HTTPS)
- Manage `@context` arrays (W3C credentials/v2 + data-integrity/v1)
- Bundle JSON-LD contexts as static files with custom document loader

**`packages/crypto`** — Data Integrity Proof Engine
- W3C VC Data Integrity 1.0 proof generation/verification (ecdsa-rdfc-2019)
- **Two-phase split for Interface Signing:**
  - `prepareProof()` → returns `dataToSign` bytes + `proofConfig`
  - `completeProof()` → accepts external signature bytes → assembles final proof
- Full signing path for Delegated Signing: `signCredential()`
- Verification: `verifyProof()`
- JCS canonicalization (RFC 8785) for revocation hashes
- SHA-256 hashing via Node.js native `crypto`
- Built on `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite` + `@digitalbazaar/data-integrity`

**`packages/did`** — DID Resolution
- `did:key` — decode multibase public key from DID string (P-256 multicodec: `0x1200`)
- Unified resolver interface (extensible for did:web later)

**`packages/dedi-client`** — DeDi Integration
- HTTP client against live DeDi API
- `publishRevocationHash()`, `queryRevocationHash()`, `resolveDID()`, `registerDelegation()`, `resolveDelegation()`
- Retry logic, timeouts, circuit breaking

**`packages/schema-engine`** — Schema Validation
- `ajv`-based JSON Schema validation
- Built-in schemas: education, employment, identity, health, business
- Custom schema registration with validation
- Map credential types to JSON-LD contexts

**`packages/auth`** — Capability Tokens
- Signed JWTs scoped to issuer namespace (`sub`, `scope`, `exp`)
- Token validation, scope checks

**`packages/state`** — Session & Job Store
- In-memory Map with TTL (4h default), lazy + periodic eviction (60s sweep)
- Used by API for Interface Signing sessions and batch job state

**Testing:** W3C VC Data Integrity test vectors, NIST ECDSA P-256 vectors, RFC 8785 JCS test data, PRD sample VC (Section 10.1). Target 90%+ coverage on crypto and vc-core.

---

### Phase 1: Type A (DSC) + Interface Signing + Verification
> Complete happy path: issuer with DSC signs their own VC via API. Web UI supports software-key interface signing only.

**API Endpoints:**

`POST /credentials/build` — Interface Signing step 1
- Input: `{ schema, issuer (DID), publicKey, credentialSubject, validFrom, validUntil, revocationRegistryUrl }`
- Processing: validate schema, validate `revocationRegistryUrl` (parseable HTTPS, optional DeDi host restrictions), build unsigned VC, prepare proof (compute dataToSign), store session
- Output: `{ sessionId, unsignedCredential, dataToSign (base64url), proofConfig }`

`POST /credentials/package` — Interface Signing step 2
- Input: `{ sessionId, signature (base64url) }`
- Processing: retrieve session, validate signature against public key, assemble proof, package
- Output: `{ credential (complete VC with proof), formats: { jsonld } }`

`POST /credentials/revocation-hash` — Hash computation
- Input: `{ credential }`
- Processing: compute hash (JCS → SHA-256)
- Output: `{ hash }`

`POST /verify` — Credential verification
- Input: `{ credential }`
- Processing: Phase 1 subset of PRD verification flow (did:key + signature + expiry + revocation + DSC chain; delegation checks in Phase 2; did:web deferred)
- Output: `{ status, checks: { signature, expiry, revocation, dscChain? } }`

**`packages/verification`** — Verification Engine (multi-format)
- Common interface dispatches by credential/proof format:
  - `verifyDataIntegrity()` — W3C Data Integrity proofs (ecdsa-rdfc-2019)
  - `verifyVcJwt()` — VC-JWT format (for Type D onboarding input)
  - `verifySdJwtVc()` — SD-JWT VC format (for Type D onboarding input)
- Parse issuer field → determine key retrieval method
- did:key → decode embedded key
- Verify proof signature (format-specific)
- DSC/CSCA chain validation (Node.js `crypto.X509Certificate`)
- Check `validFrom`/`validUntil` dates
- Compute revocation hash → query DeDi
- BitstringStatusList check when `credentialStatus.type` is `BitstringStatusListEntry`
- **Phase 1 result codes:** VALID / REVOKED / EXPIRED / INVALID / UNRESOLVABLE

**DSC/CSCA Validation:**
- Trust store: configurable directory of CSCA PEM files, loaded at startup
- X.509 chain validation via Node.js native `crypto`

**Type A Onboarding + Capability Tokens:**

`POST /onboarding/type-a` — Type A token issuance
- Input: `{ dscChain (PEM[]), publicKey }`
- Processing: validate DSC → CSCA chain → extract subject identity → create namespace → issue capability token
- Output: `{ capabilityToken, namespace, expiresAt }`

- Token required for `/credentials/build`, `/credentials/revoke`

**Web UI (software-key interface signing only):**
- Credential Builder: schema selection, data entry, software key import via `SubtleCrypto.importKey()`, client-side signing via `SubtleCrypto.sign()`, download JSON-LD result
- Credential Verifier: paste/upload VC JSON → verification result display
- Type A / DSC issuance is primarily API-first in Phase 1
- React + Vite + Tailwind CSS

**Testing:** Full round-trip integration tests (build → sign → package → verify). 5 verification result codes (VALID, REVOKED, EXPIRED, INVALID, UNRESOLVABLE). Self-signed CSCA + test DSC chain. Revocation round-trip.

**Security:** Validate signature before packaging. Rate limit verification endpoint. No credential data in logs. CORS locked to Web UI origin.

---

### Phase 2: Delegated Signing + Type D (Business VC)
> Issuers without keys can issue via OpenCred's signing capability.

**`packages/delegation`** — Delegation Certificate Management
- Define delegation certificate JSON-LD structure (extending PRD Section 5.3)
- Create, validate, embed/reference delegation certs
- Register in DeDi
- Track delegation status (active/expired/revoked)
- Validate delegation chains during verification

**OpenCred Signing Key Management:**
- `SigningKeyProvider` interface (pluggable: local key for dev, KMS for production)
- Generate ECDSA P-256 key at startup if not configured
- Key IDs in `did:key` format
- Support key rotation (multiple active keys)

**`POST /credentials/issue-delegated`**
- Input: `{ delegationId, schema, credentialSubject, validFrom, validUntil }`
- Processing: validate capability token → validate delegation (scope, expiry) → build VC (issuer = domain URL + name) → sign with OpenCred key → embed/reference delegation cert → embed credentialStatus
- Output: `{ credential (complete VC with proof + delegation) }`

**Type D Onboarding: `POST /onboarding/business-vc`**
- Input: `{ businessCredential, signingPreference, publicKey? }`
- Processing: verify business VC (format-pluggable — accepts Data Integrity, VC-JWT, SD-JWT VC proof formats) → extract identity → create DeDi namespace → issue capability token → set up delegation if needed
- Output: `{ namespace, capabilityToken, delegationId?, issuerIdentifier }`
- Type D onboarding can accept business credentials in multiple proof formats; verification dispatches via `packages/verification` common interface

**Delegation Authorisation Paths (v1):**
- Ephemeral keypair (WebCrypto in browser) — issuer signs delegation cert client-side
- DeDi registry entry — issuer creates authenticated entry in DeDi

**Extend Verification:**
- Detect URL issuer + delegation cert → resolve OpenCred key via DeDi → verify signature → validate delegation chain → check delegation was valid at `proof.created` time
- **Phase 2 adds result code:** DELEGATION_INVALID

**Testing:** Delegation round-trip, delegation expiry, scope enforcement, Type D onboarding (valid + invalid business VCs), key rotation.

---

### Phase 3: Type B (SSL) + Type C (CA API)
> Domain-verified issuers and CA integration point.

**Domain Ownership Verification:**
- DNS TXT challenge: generate `opencred-verify=<token>`, verify via `dns.resolveTxt()`
- HTTP challenge: place file at `https://<domain>/.well-known/opencred-challenge/<token>`, verify via HTTPS fetch

**`POST /onboarding/domain-verify`** — Initiate challenge
- Input: `{ domain, method: "dns-txt" | "http-challenge" }`
- Output: `{ challengeId, challenge, instructions, expiresAt }`

**`POST /onboarding/domain-verify/confirm`** — Confirm challenge
- Input: `{ challengeId }`
- Processing: execute DNS/HTTP verification → extract SSL cert subject (org name) → create namespace → issue capability token → set up delegation
- Output: `{ namespace, capabilityToken, delegationId, issuerIdentifier }`

**SSL Certificate Subject Extraction:**
- Node.js `tls` module to connect and extract CN, O, OU, C from domain's TLS cert
- Used for `issuer.name` in delegated credentials

**CA API Integration (Type C):**
- Define `CertificateAuthorityAdapter` interface: `requestDSC()`, `checkStatus()`
- No implementations in v1 — extension point only
- Endpoint: `POST /onboarding/ca-request` (forwards to configured CA adapter)

**Security:** DNS cache poisoning mitigation (multiple resolvers). HTTP challenge SSRF prevention (validate resolved IP is public). Challenge tokens: 256-bit entropy. 24h challenge expiry.

---

### Phase 4: Bulk Issuance
> Async job-based batch credential processing.

**Batch Processing Engine:**
- In-memory job queue (uses `packages/state`)
- Two-phase: validate all → issue all (PRD Section 5.5.3)
- Job state in TTL store (subject to 4h purge)

**API Endpoints:**

`POST /credentials/batch` — Submit batch
- Input: `{ schema, signingFlow, credentials[], publicKey?, delegationId? }`
- Output: `202 { jobId, status: "validating", total }`

`GET /credentials/batch/{jobId}` — Poll status
- Delegated flow: validating → issuing → completed
- Interface flow: validating → awaiting_signatures → packaging → completed

`GET /credentials/batch/{jobId}/results` — Per-row results

`POST /credentials/batch/{jobId}/signatures` — Submit signatures (Interface Signing)

`POST /credentials/revocation-hash/batch` — Batch hash computation

**CSV Support:**
- Multipart form upload, `csv-parse` for parsing
- Headers map to `credentialSubject` fields

**Limits:** v1 max 500–1,000 rows per batch. 10,000 rows marked as future optimization target (requires durable store/queue).

**Testing:** Batch validation rejection, partial failure, batch at limit (1000 rows), session expiry mid-job.

---

### Phase 5: Web UI Polish + QR/PDF
> Full-featured Web UI and output formats.

**Web UI Pages:**
- Issue (Interface Signing): full flow with SubtleCrypto
- Issue (Delegated): onboarding + delegation setup + issuance
- Verify: JSON paste, file upload, QR scan
- Revocation Hash: single + batch hash computation (issuer publishes to DeDi)
- Batch Issue: CSV upload, progress tracking

**Output Formats:**
- QR code generation (`qrcode` npm package)
- PDF generation (`pdfkit`): human-readable + embedded VC + QR
- All formats returned from `/credentials/package`

**E2E Testing:** Playwright tests for full issue/verify/revoke flows.

---

### Phase 6A: Desktop Client — Software Keys + Offline Core
> Electron app with software key signing and full offline VC lifecycle.

**App Framework:** Electron (mature, native Node.js crypto access).

**Architecture:**
- Electron main process: file system access, local signing engine, offline queue
- Renderer process: shared React components from `apps/web/` (schema selection, credential builder, verifier)
- All core logic from shared packages: `vc-core`, `crypto`, `schema-engine`, `verification`

**Local Signing Flow (PRD Section 5.1):**
1. Select schema (built-in or custom) — offline
2. Validate payload against schema — offline
3. Build VC + proof input (Data Integrity) — uses `packages/vc-core`
4. Embed `credentialStatus` (issuer-provided `revocationRegistryUrl`) — offline
5. Sign VC with software key (PEM / JWK / PKCS#8) — Node.js `crypto` module
6. Package output (QR, JSON-LD, PDF) — offline
7. Publish queued revocation hashes when credential is revoked — using issuer's own DeDi credentials

**Offline Capabilities:**
- All VC construction, signing, packaging works without network
- Schema library + JSON-LD contexts bundled with app
- QR/PDF generation runs locally (`qrcode`, `pdfkit`)
- Network needed only for: publishing revocation hashes to DeDi (using issuer's credentials), DID resolution for verification
- Offline queue: revocation operations queued and published using issuer's DeDi credentials when connectivity is available

**Bulk Issuance (Desktop):**
- Read CSV locally, build each VC, sign with issuer's software key, package — all offline
- Batch revocation hashes queued for publish on revocation using issuer's own DeDi credentials

**Desktop UI:**
- Key management panel: import PEM/JWK/PKCS#8 key files
- Offline indicator + DeDi revocation queue (uses issuer's DeDi credentials per publish)
- Local CSV batch import with progress
- Credential verifier (offline signature check, online revocation check)

**Distribution:** electron-builder for macOS (.dmg), Windows (.exe/.msi), Linux (.AppImage/.deb).

**Testing:** Full offline round-trip (build → sign → package → verify). Software key import for PEM/JWK/PKCS#8.

---

### Phase 6B: Desktop — PKCS#11 Hardware Token Support
> Add hardware token signing to the Desktop Client.

- `pkcs11js` or `graphene-pk11` npm bindings
- PIN/session management flow
- Supports USB tokens (ePass, SafeNet, YubiKey), smart cards
- Signature byte format conversion (DER ↔ raw) if needed for proof engine compatibility
- Key management UI: connect hardware tokens, list available keys, select signing key

**Testing:** PKCS#11 mock tests via `softhsm2`. Manual testing with at least one physical token.

---

### Phase 6C: Desktop — OS Cert Store Signing + Distribution Hardening
> True platform-native signing from OS certificate store + production distribution.

**OS Cert Store Signing (native implementations):**
- **Windows:** CNG/CryptoAPI bindings via N-API native addon — enumerate certs from Windows Certificate Store, sign with non-exportable keys
- **macOS:** Security.framework bindings via N-API native addon — enumerate certs from Keychain, sign with non-exportable keys
- **Linux:** PKCS#11 fallback (covered by Phase 6B) or PEM file import (Phase 6A)
- UI: browse OS cert store, select signing certificate, sign VC using platform-native APIs
- Signature byte format conversion if needed for Data Integrity proof compatibility

**Distribution Hardening:**
- Code signing: Apple notarization, Windows Authenticode
- Auto-update mechanism (`electron-updater`)

**Additional npm packages:** `node-gyp` (build tooling for native addons)

**Testing:** Platform-specific cert store enumeration + signing on Windows and macOS. Signed distribution builds verified on each target OS. E2E: select OS cert → sign VC → verify.

---

### Phase 7: Containerization & Deployment
> Docker images, orchestration, and production deployment configuration for GCP / VM hosting.

**Docker Images (multi-stage builds):**

`apps/api/Dockerfile` — API Server
- Stage 1: `node:20-alpine` — install pnpm, copy monorepo, `pnpm install --frozen-lockfile`, build all packages + `apps/api`
- Stage 2: `node:20-alpine` — copy built output only, run as non-root user (`node`), expose port
- Health check: `HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1`
- JSON-LD contexts bundled in image (no runtime fetching — per security invariant)

`apps/web/Dockerfile` — Web UI (static)
- Stage 1: `node:20-alpine` — install pnpm, build Vite app (`pnpm build`)
- Stage 2: `nginx:alpine` — copy built static files to `/usr/share/nginx/html`, custom `nginx.conf` with security headers, gzip, and SPA routing

**Docker Compose (`docker-compose.yml`):**
- `api` service: builds from `apps/api/Dockerfile`, environment variables via `.env`, port mapping, restart policy
- `web` service: builds from `apps/web/Dockerfile`, depends on `api`, port mapping
- `nginx` reverse proxy (optional profile): TLS termination, rate limiting, proxies to `api` and `web`
- Shared network, named volumes for CSCA trust store PEMs
- `docker-compose.override.yml` for local dev (bind mounts, debug ports, hot reload)

**Environment & Secrets:**
- `apps/api/.env.example` — documents all required environment variables
- Secrets (signing keys, DeDi credentials, JWT secret) via environment variables — never baked into images
- GCP: use Secret Manager → injected as env vars at deploy time
- VM: `.env` file with restricted permissions (`chmod 600`), or systemd `EnvironmentFile`
- Zod config validation at startup catches missing/invalid env vars before the server starts

**Production Configuration:**
- `pino` JSON logging to stdout (container-native; GCP Cloud Logging auto-ingests)
- Graceful shutdown handling (`SIGTERM` → drain connections → exit)
- Non-root container user in all images
- Read-only filesystem where possible (`--read-only` with tmpfs for `/tmp`)
- No `latest` tag — images tagged with git SHA + semver

**CI/CD Pipeline Extensions (GitHub Actions):**
- `docker-build` job: build images on every PR (validates Dockerfiles compile)
- `docker-push` job (on merge to `anusree-dev`): build + tag + push to container registry
  - GCP: push to Artifact Registry (`gcr.io/<project>/opencred-api`, `gcr.io/<project>/opencred-web`)
  - Self-hosted: push to GitHub Container Registry (`ghcr.io`)
- Image scanning: `trivy` or `grype` for vulnerability scanning before push
- Optional: deploy job that triggers Cloud Run revision or SSH-deploys to VM

**GCP Deployment Options:**
- **Cloud Run (recommended for stateless API):** auto-scaling, managed TLS, zero-infra overhead
  - `gcloud run deploy opencred-api --image gcr.io/<project>/opencred-api --allow-unauthenticated`
  - Web UI: serve from Cloud Run or Cloud Storage + CDN
- **GCE VM:** `docker compose up -d` on a Compute Engine instance with Docker installed
  - Startup script pulls latest images and restarts services
  - TLS via Caddy or Certbot (Let's Encrypt)

**VM Deployment (org-managed):**
- `docker compose` as the orchestrator
- Systemd service file (`opencred.service`) to auto-start on boot and restart on failure
- TLS: reverse proxy (Caddy/Nginx) with Let's Encrypt or org-provided certificates
- Log rotation: Docker log driver config (`json-file` with `max-size`/`max-file`)
- Backup: CSCA trust store PEMs and `.env` only (no persistent credential data — ephemeral by design)

**`.dockerignore`:**
- `node_modules/`, `.git/`, `apps/desktop/`, `docs/`, `*.md`, `.env`, test fixtures

**Security Hardening:**
- No `--privileged`, no `SYS_ADMIN` capabilities
- Drop all capabilities, add only `NET_BIND_SERVICE` if binding to port 80/443
- Pin base image digests in Dockerfiles for reproducible builds
- Signing keys for Delegated Signing: mount as read-only volume or inject via env, never in image layers
- Container network isolation: only `web` and `api` can communicate; `api` egress limited to DeDi endpoints

**Testing:** Docker build succeeds in CI. Compose stack starts and `/health` returns 200. E2E smoke test against containerized stack (issue → verify → revoke). Image vulnerability scan passes with no critical/high CVEs.

---

## Verification Plan

### Per-Phase Testing
1. **Risk Spikes:** One working PoC per spike (4 spikes). Go/no-go decision on library choices.
2. **Phase 0:** Unit tests against W3C test vectors, NIST ECDSA vectors, RFC 8785 JCS vectors. 90%+ coverage on crypto and vc-core.
3. **Phase 1:** Integration tests — full build→sign→package→verify round-trip. 5 verification result codes (VALID, REVOKED, EXPIRED, INVALID, UNRESOLVABLE). Self-signed CSCA + test DSC chain. Revocation round-trip.
4. **Phase 2:** Delegation chain validation. DELEGATION_INVALID result code. Type D onboarding (valid + invalid business VCs). Key rotation.
5. **Phase 3:** DNS/HTTP challenge with mock resolvers. SSRF prevention.
6. **Phase 4:** Batch validation rejection, partial failure, batch at limit (1000 rows), session expiry.
7. **Phase 5:** QR round-trip, PDF embedding, Playwright E2E.
8. **Phase 6A:** Full offline round-trip. Software key import (PEM/JWK/PKCS#8).
9. **Phase 6B:** PKCS#11 mock tests (softhsm2). Hardware token signing round-trip.
10. **Phase 6C:** Platform cert store enumeration + native signing (Windows CNG, macOS Security.framework). Signed distribution builds. E2E: select OS cert → sign VC → verify.
11. **Phase 7:** Docker images build in CI. Compose stack starts cleanly. `/health` returns 200. Image vulnerability scan (trivy/grype) passes with no critical/high CVEs. E2E smoke test against containerized stack.

### End-to-End Verification
After each phase, run the complete flow manually:
- **Phase 1:** Issue a credential with a test DSC key → verify it → revoke it → verify returns REVOKED
- **Phase 2:** Onboard with a business VC → issue via delegated signing → verify with delegation chain → verify returns DELEGATION_INVALID for bad chain
- **Phase 3:** Verify domain ownership → issue delegated credential → verify
- **Phase 4:** Upload CSV batch → poll status → retrieve results → verify random sample
- **Phase 5:** Issue credential → download QR + PDF → scan QR → verify → confirm match
- **Phase 6A:** Import software key → build VC offline → sign locally → package → verify offline (signature) → revoke → publish hash to DeDi → verify returns REVOKED
- **Phase 6B:** Connect hardware token → sign VC → verify
- **Phase 6C:** Select OS cert (Windows CNG / macOS Keychain) → sign VC natively → verify. Install from signed distribution.
- **Phase 7:** `docker compose up` → `/health` returns 200 → issue credential via API → verify → revoke → verify returns REVOKED. All running in containers.

### CI Pipeline
- GitHub Actions: lint + type-check + test on every PR
- Separate jobs per package (parallel execution)
- Integration test job that runs after package tests pass
- **Desktop build matrix:** macOS, Windows, Linux smoke builds (from Phase 6A onward)
- **Docker build + push** (from Phase 7 onward): build images on PR, push to registry on merge to `anusree-dev`, vulnerability scan gate

---

## Timeline

Solo developer with Claude Code. Phases are sequential; each builds on the prior.

### Aggressive Prototype Timeline
Best-case with Claude Code acceleration. Produces a working system suitable for demos, internal testing, and early adopter feedback. May have rough edges in error handling, edge cases, and production hardening.

| Phase | Scope | Duration |
|---|---|---|
| Risk Spikes | 4 technical PoCs | 4–5 days |
| Phase 0: Core Foundation | All shared packages + tests | ~5 days |
| Phase 1: Type A + Interface Signing + Verification | API + basic Web UI + verification | ~5 days |
| Phase 2: Delegated Signing + Type D | Delegation certs + Business VC onboarding | ~4 days |
| Phase 3: Type B (SSL) + Type C (CA API) | Domain verification + CA interface | ~3 days |
| Phase 4: Bulk Issuance | Batch API + CSV + job queue | ~3 days |
| Phase 5: Web UI + QR/PDF | Full Web UI + output formats | ~3 days |
| Phase 6A: Desktop MVP | Electron + software keys + offline | ~4 days |
| Phase 6B: Desktop PKCS#11 | Hardware token support | ~2 days |
| Phase 6C: Desktop OS Signing | Native OS cert store signing + distribution hardening | ~3 days |
| Phase 7: Containerization & Deployment | Docker images + Compose + CI/CD + GCP/VM deploy | ~3 days |
| **Total** | **Complete v1** | **~6–7 weeks** |

### Production-Ready v1 Timeline
Includes thorough edge-case coverage, security hardening, error handling polish, documentation, and CI/CD maturity. Suitable for production deployment.

| Phase | Scope | Duration |
|---|---|---|
| Risk Spikes | 4 technical PoCs + documentation | 5–6 days |
| Phase 0: Core Foundation | All shared packages + comprehensive tests | ~8 days |
| Phase 1: Type A + Interface Signing + Verification | API + Web UI + verification + security hardening | ~8 days |
| Phase 2: Delegated Signing + Type D | Delegation + onboarding + key rotation | ~6 days |
| Phase 3: Type B (SSL) + Type C (CA API) | Domain verification + SSRF hardening | ~4 days |
| Phase 4: Bulk Issuance | Batch + CSV + error recovery | ~4 days |
| Phase 5: Web UI + QR/PDF | Full UI + E2E tests + accessibility | ~5 days |
| Phase 6A: Desktop MVP | Electron + software keys + offline | ~5 days |
| Phase 6B: Desktop PKCS#11 | Hardware tokens + mock tests | ~3 days |
| Phase 6C: Desktop OS Signing | Native OS cert store signing (CNG, Security.framework) + distribution hardening | ~5 days |
| Phase 7: Containerization & Deployment | Docker images + Compose + CI/CD + GCP/VM deploy + security hardening | ~4 days |
| **Total** | **Complete v1** | **~10 weeks** |

---

## Critical Files

| File (to create) | Why it matters |
|---|---|
| `packages/crypto/src/data-integrity.ts` | Most complex: two-phase proof split for Interface Signing, full sign for Delegated, verification. Built on Digital Bazaar libs. |
| `packages/vc-core/src/credential-builder.ts` | Every issuance flow depends on this to correctly assemble W3C VC 2.0 documents |
| `packages/verification/src/verifier.ts` | Orchestrates verification — dispatches by proof format, 6 result codes |
| `packages/verification/src/vc-jwt.ts` | VC-JWT verification (for Type D onboarding input) |
| `packages/verification/src/sd-jwt-vc.ts` | SD-JWT VC verification (for Type D onboarding input) |
| `packages/state/src/ttl-store.ts` | 4-hour purge constraint. Sessions + batch jobs depend on this. |
| `packages/auth/src/capability-token.ts` | JWT capability tokens — scope checks, validation |
| `packages/delegation/src/certificate.ts` | Delegation cert structure (PRD underspecifies — must be designed) |
| `apps/api/src/routes/credentials.ts` | Core API surface: build, package, issue-delegated, revoke |
| `apps/desktop/src/signing/software-signer.ts` | PEM/JWK/PKCS#8 key loading + signing (Phase 6A) |
| `apps/desktop/src/signing/pkcs11-signer.ts` | Hardware token integration (Phase 6B) |
| `apps/desktop/src/signing/os-cert-signer.ts` | Native OS cert store signing — Windows CNG + macOS Security.framework bindings (Phase 6C) |
| `apps/desktop/src/main/index.ts` | Electron main process: offline orchestration, key store access, revocation queue |
| `apps/api/Dockerfile` | Multi-stage API image — bundles all packages, JSON-LD contexts, runs as non-root |
| `apps/web/Dockerfile` | Static Web UI image — Vite build into nginx with security headers |
| `docker-compose.yml` | Orchestrates API + Web + optional reverse proxy for VM/local deployment |
| `.github/workflows/docker.yml` | CI/CD: build images on PR, push to registry on merge, vulnerability scan |
| `OpenCred_PRD.md` | Source of truth for all implementation decisions |
