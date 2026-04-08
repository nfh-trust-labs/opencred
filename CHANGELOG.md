# Changelog

All notable changes to OpenCred are documented here. Format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
