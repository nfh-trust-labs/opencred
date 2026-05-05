# Changelog

All notable changes to OpenCred are documented here. Format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-05-05

### Added

- **Public release distribution** — Docker image now published to `ghcr.io/nfh-trust-labs/opencred/opencred-server` (public, no auth). Desktop installers mirrored to `nfh-trust-labs/opencred-releases` with SHA256SUMS for integrity verification. Source repo stays private; binaries are public so end users can install without GHCR / repo authentication. (#514)
- **`POST /v1/dedi/namespace/ensure`** — server endpoint to create a DeDi namespace and its four registries (`vc-revocation-registry`, `public_key_registry`, `schema_registry`, `context_registry`) on demand. Bootcamp attendees no longer need to pre-provision the namespace before booting the container. (#509)
- **Inline custom JSON Schema in issue requests** — `POST /v1/credentials/issue` now accepts a `credentialSchema.schema` field with an inline JSON Schema, validated by Ajv at request time. Previously schemas had to be pre-registered in the schema engine. (#506)
- **DeDi public-key registry routes** — `POST /v1/dedi/keys/publish` and resolution endpoints for self-published `did:web` keys. (#506)
- **JWT-aware credential packager** — PDF + QR packaging now decodes `vc-jwt` and `sd-jwt-vc` compact tokens for display while preserving the byte-exact token in the QR payload. (#508)
- **Bootcamp guide** — `docs/bootcamp/local-docker.md` and `docs/bootcamp/gcp-vm.md` ship a 3-hour, hands-on facilitator-led path through the Docker image. Includes a Postman collection covering every API endpoint. (#512)

### Changed

- **`docker-compose.yml` defaults to the public GHCR image.** Build-from-source remains available by uncommenting the `build:` block. (#514)
- **electron-updater polls `opencred-releases` for auto-updates** instead of the private source repo, so installed Desktop clients can fetch updates without authenticating. (#514)
- **400 INVALID_JSON for malformed bodies** — server now parses JSON at the route layer and returns a clean error response instead of letting Hono's default handler 500. (#511)
- **Discriminated `CredentialInput` union** for the packager and QR generator, replacing the previous `T | string` overload. Type system now reflects the JSON-LD-vs-compact-token split honestly. (#510)

### Fixed

- **Friendlier error messages** — issuance and verification surfaces now return actionable messages instead of internal stack traces for common failure modes (missing signing key, malformed VC, schema mismatch). (#508)
- **Bitstring revocation fetch timeout + KMS keepAlive/retry** — verification was hanging indefinitely on slow `credentialStatus` URLs and dropping under KMS connection pressure. (#486)
- **Five independent `validatorInstance` singletons collapsed to one.** Previously each surface (server routes, desktop preload, etc.) constructed its own Ajv instance, doubling-counting cache misses and burning startup memory. (#485)
- **Revocation hash unified with `credentialStatus.id`** — verification was computing the hash from a different field than issuance was writing it to, so DeDi-published revocations weren't being detected. (#467, #484)
- **`computeChecksum` made canonical** — JSON-LD context checksums now use a stable serialization, so cache lookups don't churn on whitespace differences. (#488)
- **Atomic `DeDiTokenManager.setTokens`** — partial writes during token refresh could leave the manager with an access token but no refresh token, requiring a server restart to recover. (#487)
- **`CORS_ORIGIN` required in production** — the server was silently allowing all origins when the var was unset, which is fine for local dev but unsafe in deployment. Production now refuses to start without it. (#495)

### Infrastructure

- **Audit remediation** — 2026-04-16 security audit findings closed: 3 HIGH, 5 MED, 4 LOW, 4 INFO. Highlights include credential-payload TTL purge, structured logger sanitization, error-handler PEM stripping. (#426)
- **CSV parsing extracted to `@opencred/batch-core`** — desktop bulk-issuance and server CLI now share one streaming parser. (#496)
- **PKCS#11 warnings routed through structured logger** — was previously console.log noise. (#494)
- **DeDi DNS cache** — 30s TTL cache to avoid repeated SSRF protection lookups on hot paths. (#490)
- **`bulkUpload` routed through shared `doFetch`** — uniform retry / SSRF / timeout behavior for all DeDi traffic. (#493)
- **Empty `CSC_*` env vars unset before electron-builder** — was causing CSC_LINK="" to resolve to cwd and fail with "apps/desktop not a file". (#503)
- **Windows temporarily dropped from the desktop release matrix** — `@electron/rebuild` hangs for 20+ min on the pnpm symlinked tree on NTFS. Native compile itself works (~48s); only the Electron-ABI rebuild step hangs. (#502)

## [1.0.2] - 2026-04-21

### Fixed

- **"App is damaged" on macOS** — v1.0.1 shipped with
  `forceCodeSigning: true` and no `MAC_CSC_LINK` configured in the
  repo secrets, causing `electron-builder` to fall through to an
  ad-hoc signature. macOS rejects that as a broken signature with
  no user-bypass path. Flipped `forceCodeSigning: false` and
  reworked the release workflow so missing signing secrets now
  produce cleanly unsigned artefacts. Users get the standard
  "unrecognised developer" prompt (right-click → Open) instead of
  "app is damaged". See [docs/desktop/release-signing.md](docs/desktop/release-signing.md)
  for the unsigned-state UX and the roadmap to signed releases (#498).

### Infrastructure

- **Preflight for signing secrets** — `.github/workflows/desktop-release.yml`
  now emits `sign_mac` / `sign_win` job outputs from a preflight
  check. All secrets present → signed + notarised build with full
  `codesign`/`spctl`/`stapler` + `Authenticode` verification.
  All absent → unsigned build with a warning. Partial → hard
  fail. No further workflow change is required when certs are
  eventually configured (#498).

### Docs

- **`docs/desktop/release-signing.md`** — new canonical record of
  the current unsigned state, auto-update implications, target
  state, and the exact steps to restore signing once Apple
  Developer Program + Windows Authenticode certs are acquired
  (tracked in #497).
- **`docs/desktop/installation.md`** — replaced the incorrect
  "signed + notarised" claim with the right-click → Open
  walkthrough for macOS, SmartScreen "Run anyway" workaround for
  Windows, and `xattr -cr` escape hatch for users still stuck on
  the v1.0.1 broken bundle.

## [1.0.1] - 2026-04-14

### Fixed

- **Desktop release pipeline** — `desktop-release.yml` had invalid
  `secrets: inherit` under `on.workflow_call`, making every run fail at
  parse time with no artifacts published. Fixed and added
  `workflow_dispatch` with a `tag` input so historical tags can be
  rebuilt on demand (#402).
- **Native addon rebuild on Node 20** — `@electron/rebuild@3.6.1`
  transitively pulls `node-gyp@9.4.1`, whose deprecated
  `util.promisify` patterns throw `TypeError [ERR_INVALID_ARG_TYPE]` on
  Node 20, blocking `pkcs11js` rebuild during `electron-builder
  --publish`. Added a pnpm override forcing `node-gyp@>=10` (#404).
- **release-please target branch** — defaulted to `main` (which has no
  config), now explicitly targets `new-opencred-dev` (#406).

### Chores

- Consolidated `docs/self-hosted/` into `docs/docker/`; audited every
  Docker doc against source code and fixed numerous inaccuracies
  (#399).
- Added `.claude/worktrees/`, `.claude/settings.local.json`, and
  `.pnpm-store/` to `.gitignore`; removed a stray worktree submodule
  left over from a past agent session (#401).

## [1.0.0] - unreleased

Tagged in git but never published as a GitHub Release. Superseded by
1.0.1, which includes the CI fixes needed to build release artifacts.

### Added — v1 schema library overhaul

- **Curated catalogue of ~33 credentials** sourced from existing standards
  rather than hand-rolled placeholders. The library now ships:
  - **9 OpenCred-defined schemas** authored against W3C VC 2.0 with sector
    anchors:
    - `electricity/v1` (Green Button / ESPI / Beckn)
    - `salary-slip/v1` (Schema.org Invoice)
    - `immunization/v1` (HL7 FHIR R4 Immunization + CVX/SNOMED)
    - `prescription/v1` (HL7 FHIR R4 MedicationRequest + RxNorm)
    - `test-result/v1` (HL7 FHIR R4 DiagnosticReport + LOINC)
    - `insurance-policy/v1` (generic, `policyType` discriminator)
    - `functional-identity/v1` (Schema.org `hasOccupation`, optional ISCO-08)
    - `employment-offer-letter/v1` (Schema.org `JobPosting` + `EmployeeRole`)
    - `business-entity/v1` (vLEI field shape, W3C VC envelope)
  - **24 referenced upstream schemas** fetched and SHA-256 verified at
    build time, bundled into the desktop app + Docker image:
    - Open Badges 3.0 (1EdTech)
    - DIF Verified Person v1.0, DIF Proof of Age v1.0
    - 21 W3C CCG Traceability Vocabulary credentials including Commercial
      Invoice, Bill of Lading, USMCA Certification of Origin, Purchase
      Order, Packing List, IATA Air Waybill, Importer Security Filing,
      Mill Test Report, SBOM, GAP Inspection, Phytosanitary, Oil and Gas
      Product, and others
- **Build-time fetch + verify pipeline** (`packages/schema-engine/scripts/fetch-and-embed-schemas.mjs`)
  pinned to a specific `opencred-vc-schemas` commit. Runs at release build,
  hard-fails on any tamper / hash mismatch / unreachable URL / non-allowlisted
  host. The runtime never fetches remote schemas — same security model as
  the existing JSON-LD context bundling.
- **`SchemaDefinition.source`** — every registered schema carries
  `{kind: "defined" | "referenced", upstreamUrl, upstreamOwner, upstreamLicense}`
  provenance. Surfaced in the desktop schema selector and in the server
  `GET /schemas` API response.
- **`canonicalJsonSha256`** in `@opencred/shared` — recursive sorted-key
  JSON SHA-256 used as the contract between the `opencred-vc-schemas`
  hash-pinner script and the monorepo's build-time verifier. Both must
  produce bit-identical output for the same input.
- **`TRACEABILITY_V1_CONTEXT`**, **`OPEN_BADGES_V3_CONTEXT`**, and 8
  OpenCred-defined context URL constants in `@opencred/vc-core/types`,
  bundled in `BUNDLED_CONTEXTS` so the document loader resolves every v1
  credential's context offline.
- **Data-driven default SVG template** rendering — `packages/templates`
  no longer needs a per-schema SVG file for v1; the default template
  renders generic VC fields for all 33 credentials. Schema-specific
  branded SVGs are a v1.1 follow-up.
- **`formatSchemaLabel(id)` helper** in
  `apps/desktop/src/renderer/utils/schema-label.ts` — derives a
  human-readable label from any v1 schema ID (`electricity/v1` →
  "Electricity v1", `traceability/commercial-invoice/v1` →
  "Commercial Invoice v1", `dif/verified-person/v1` →
  "Verified Person v1"). Replaces 4 copies of the hardcoded
  `SCHEMA_LABELS` map across the renderer components.

### Changed

- `SchemaDefinition.checksum` is now **required** (was optional). Bundled
  registry entries always carry their canonical hash.
- `Validator.validateCredentialSubject(schemaId, subject)` now extracts the
  `properties.credentialSubject` sub-schema when the registered schema is a
  full W3C VC 2.0 envelope (the v1 catalogue style), and falls back to
  validating against the whole schema for any legacy subject-only schemas.
  This unblocks subject validation against the new envelope-shaped schemas
  without changing the public API.
- `apps/server/src/routes/schemas.ts`: `GET /schemas` and `GET /schemas/:id`
  now return `version` and `source` fields per credential.

### Removed

- **5 generic placeholder schemas** are deleted with no migration aliases:

  | Old | Replaced by |
  |---|---|
  | `education/v1` | `open-badges/v3` (Open Badges 3.0 — adopted upstream) |
  | `employment/v1` | `employment-offer-letter/v1` (authored, Schema.org-anchored) |
  | `identity/v1` | `dif/verified-person/v1` + `dif/proof-of-age/v1` (DIF — adopted upstream) |
  | `health/v1` | `immunization/v1` + `prescription/v1` + `test-result/v1` (authored, FHIR-anchored) |
  | `business/v1` | `business-entity/v1` (authored, vLEI field shape in W3C VC envelope) |

  Rationale: the old schemas were 4-field placeholders that weren't usable
  in production. Replacements are either adopted upstream from mature
  standards (Open Badges 3.0, DIF, W3C CCG Traceability) or authored as
  thin W3C VC 2.0 wrappers around established domain data models (FHIR,
  LOINC, Schema.org, vLEI).

  Issued credentials in the wild that reference the old schema URLs at
  `raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/<old>/v1/schema.json`
  continue to validate at the URL level — those files still exist in the
  schemas repo. They are simply no longer registered in the bundled
  catalogue, the registry, or the desktop UI.

- **`packages/schema-engine/src/updater.ts`** — the runtime "check for
  schema updates" download path is deleted entirely. The new model is
  bundled-at-release-only; runtime never fetches remote schemas. The
  `checkForSchemaUpdates`, `downloadSchema`, `loadCachedSchemas`,
  `saveSchemasToCache`, and `validateSchemaChecksum` exports are gone.
- **`apps/desktop/src/main/schema-updater.ts`** — the desktop startup
  hook that called the deleted updater module. Removed along with its
  invocation in `apps/desktop/src/main/index.ts`.
- **5 NFH JSON-LD context constants** (`NFH_EDUCATION_V1_CONTEXT` etc.)
  and their bundled JSON files in `packages/vc-core/src/contexts/`.
- The 5 schema-specific SVG template files in
  `packages/templates/src/templates/` (education, employment, identity,
  health, business). Default template handles all v1 credentials.

### Fixed

- The schema-engine `Validator` now correctly handles W3C VC 2.0 envelope
  schemas. Previously, `validateCredentialSubject` compiled the entire
  schema and validated only the credentialSubject against it, which
  always failed for envelope schemas because they require top-level
  `@context`, `id`, `type`, `issuer`, etc. The validator now extracts
  the `credentialSubject` sub-schema (and its `$defs` / `definitions`)
  before compiling.

### Known issues

- E2E specs (`apps/desktop/e2e/*.spec.ts`) still reference the old schema
  IDs and need to be rewritten. They require a full electron app build and
  the schema selector UI to exercise the new IDs end-to-end.
- The `OPENCRED_SCHEMAS_SHA` constant in `packages/vc-core/src/types.ts`
  must be regenerated manually whenever
  `packages/schema-engine/scripts/schema-sources.json` `commit` is bumped.
  Auto-generation from the manifest is a v1.1 follow-up.
- The `https://w3id.org/traceability/v1` context is bundled manually
  (committed at `packages/vc-core/src/contexts/traceability-v1.json`)
  rather than fetched through the build pipeline. Should be migrated
  to the manifest in v1.1 so it gets the same hash-pinning treatment.
