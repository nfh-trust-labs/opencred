# Package Layout

OpenCred is a TypeScript monorepo using **pnpm workspaces**. The two top-level directories are `apps/` (entry points) and `packages/` (reusable libraries). Both the Desktop client and the Docker server consume the same `@opencred/*` packages, so issuance and verification logic is shared.

## Workspace structure

`pnpm-workspace.yaml`:

```yaml
packages:
  - "packages/*"
  - "apps/*"
  - "demos"
```

## Apps

### `apps/desktop` — `@opencred/desktop`

The Electron-based Desktop Client. Primary OpenCred product.

| Layer | Path | What lives here |
|---|---|---|
| Main process | `src/main/` | IPC handlers, key import, signing, verification, logger, auto-updater, native bindings |
| Preload | `src/main/preload.ts` | contextBridge that exposes the typed `window.opencred` API to the renderer |
| Renderer | `src/renderer/` | React UI: `HomeScreen`, `OnboardingWizard`, `IssuePage`, `VerifyPage`, `SettingsPage`, etc. |
| Shared types | `src/shared/` | TypeScript types used on both sides of the IPC boundary |
| Build scripts | `scripts/` | `bundle-main.mjs` (esbuild), `prepare-native-deps.cjs`, `rebuild-native.cjs`, `electron-builder-hooks.cjs`, `verify-packaged-arch.cjs`, `notarize.cjs` |
| Native deps | (rebuilt at build time) | `pkcs11js` and the OS-cert addons, compiled against the Electron ABI **per target architecture**: the `beforePack` hook reruns `rebuild-native.cjs --arch=<target>` for each packaged arch, and the `afterPack` hook fails the build if any packaged `.node` binary doesn't match (#641/#642) |

Build pipeline: `vite build` for the renderer, `esbuild` for the main process, then `electron-builder` for the installer. See `apps/desktop/package.json` for `electron-builder` configuration (DMG/zip on macOS, NSIS on Windows, AppImage/deb on Linux).

### `apps/server` — `@opencred/server`

The headless Hono-based HTTP server that ships as the Docker image.

| Layer | Path | What lives here |
|---|---|---|
| Bootstrap | `src/index.ts` | Wires config, logger, auth, routes, middleware, tracing, error handler. Starts Hono. |
| Worker | `src/worker.ts` | Separate BullMQ worker process (started when `OPENCRED_BATCH_DISPATCH=queue`). Consumes the `opencred:batch` and `opencred:webhook` queues. |
| Configuration | `src/config.ts` | Zod schema for all `OPENCRED_*` env vars (auth, rate limits, job store, tracing, dispatch, …) |
| Logging | `src/logger.ts` | pino, structured JSON to stdout |
| Tracing | `src/tracing.ts`, `src/observability/*.ts` | OTel critical-path spans (signer, batch, verify, DeDi) |
| Middleware | `src/middleware/` | Auth, rate-limit, body-limit, read-only mode, cache-control, tracing, error handler |
| Routes | `src/routes/*.ts` | `health`, `schemas`, `credentials`, `batch`, `revocation`, `keys`, `dedi`, `packaging` |
| Signing | `src/signing/key-manager.ts`, `src/signing/cloud-hsm/` | Loads the active signer from a file or KMS |
| Batch processing | `src/batch/` | Streaming engine, CSV parser, BullMQ queue + webhook delivery, pluggable job store (`job-store/memory.ts`, `job-store/redis.ts`) |
| Packaging | `src/packaging/` | PDF, QR code, JSON-LD output |
| CLI | `src/cli.ts` | `opencred` command for one-off operations (issue, verify, hash, batch, config validate, identity show) |

The server depends on the same `@opencred/*` packages as the Desktop client. See `apps/server/package.json` for the dependency list.

## Packages

Every package is published as `@opencred/<name>` (private). All are TypeScript ESM, build with `tsc`, and follow the same `src/`, `dist/`, `package.json`, `tsconfig.json`, `vitest.config.ts` layout.

### `packages/shared` — `@opencred/shared`

The base package everything depends on.

| Module | Exports |
|---|---|
| `errors.ts` | `OpenCredError`, `ValidationError`, `AuthenticationError`, `AuthorizationError`, `NotFoundError`, `ConflictError`, `PayloadTooLargeError`, `RateLimitError`, `CryptoError`, `DIDResolutionError`, `SchemaValidationError`, `DelegationError`, `DeDiClientError`, `SessionExpiredError`, `VerificationError`, `NotImplementedError` |
| `config.ts` | Zod env schema, `loadConfig()`, `EnvConfig` type |
| `ssrf.ts` | `isPrivateIP(ip)` and `resolveDnsForSsrf(hostname)` for SSRF prevention (used by the did:web resolver) |
| `pinned-fetch.ts` | `fetchWithPinnedIp(url, addresses, opts)` — DNS-rebinding-safe HTTPS request (any method, optional body) that connects only to pre-validated IPs while keeping the hostname for TLS validation |

### `packages/vc-core` — `@opencred/vc-core`

W3C VC Data Model 2.0 construction.

| Export | Purpose |
|---|---|
| `CredentialBuilder` | Fluent builder for unsigned credentials |
| `createDocumentLoader()` | JSON-LD loader that serves *only* bundled contexts |
| `getBundledContextUrls()` | Set of URLs the loader will accept |
| `generateInlineContext` | Custom-schema inline context generator |
| Context constants | `W3C_CREDENTIALS_V2_CONTEXT`, `DATA_INTEGRITY_V1_CONTEXT`, `NFH_EDUCATION_V1_CONTEXT`, etc. |

The build script `scripts/embed-contexts.cjs` runs at build time to bake the context JSON files into the dist output.

### `packages/crypto` — `@opencred/crypto`

Proof generation, signing, hashing, JCS canonicalization.

| Export | Purpose |
|---|---|
| `prepareProof` / `completeProof` | Data Integrity (ECDSA) two-step signing |
| `prepareEdDsaProof` / `completeEdDsaProof` | Data Integrity (Ed25519) |
| `prepareVcJwtProof` / `completeVcJwtProof` | VC-JWT format |
| `prepareSdJwtVcProof` / `completeSdJwtVcProof` | SD-JWT VC format |
| `signCredential`, `signCredentialAuto` | High-level signing entry points |
| `verifyProof` | Signature verification |
| `jcsCanonicalize`, `computeRevocationHash` | RFC 8785 JCS + revocation hash |
| `sha256`, `sha256Hex`, `sha384` | Hashing |
| `LocalSigningKeyProvider` | Reference signing-key provider for development |
| `signingAlgorithmToJwsAlg` | Algorithm string mapping |

Built on `@digitalbazaar/data-integrity`, `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite`, `@digitalbazaar/ecdsa-multikey`, `jose`, `json-canonicalize`, `jsonld`.

### `packages/did` — `@opencred/did`

DID resolution.

| Export | Purpose |
|---|---|
| `DIDKeyResolver`, `deriveDidKeyId`, `computeKeyFingerprint`, `getCompressedPublicKey` | did:key |
| `DIDJwkResolver`, `encodeDidJwk`, `didJwkVerificationMethodId` | did:jwk |
| `DIDWebResolver`, `encodeDidWeb`, `didWebToUrl`, `generateDidWebDocument`, `didWebVerificationMethodId` | did:web (with SSRF protection) |
| `CompositeDIDResolver` | Method dispatcher used by the verifier |
| `DIDWebFallbackResolver` (type) | Optional DeDi fallback hook |

### `packages/verification` — `@opencred/verification`

Multi-format verification orchestrator.

| Export | Purpose |
|---|---|
| `verifyCredential(input, config)` | Top-level entry — auto-detects format and runs all checks |
| `detectFormat(input)` | Returns `data-integrity` / `vc-jwt` / `sd-jwt-vc` / `jws` |
| `verifyDataIntegrity` | Data Integrity proof verification |
| `verifyVcJwt`, `extractVcJwtCredentialFields`, `crossValidateVcJwtClaims` | VC-JWT verification |
| `verifySdJwtVc`, `parseSdJwtVc`, `processDisclosures` | SD-JWT VC verification |
| `verifyJwsProof` | JWS proof verification |
| `checkDates`, `checkRevocation`, `checkBitstringStatusList` | Common post-signature checks |
| `checkX509Chain` | X.509 chain validation against a trust store |

### `packages/schema-engine` — `@opencred/schema-engine`

JSON Schema validation and the built-in schema registry.

| Export | Purpose |
|---|---|
| `Validator` | AJV-based validator with `validateOrThrow` |
| `createRegistry()` | Returns a `SchemaRegistry` populated with built-in schemas |
| `SchemaRegistry` (type) | Registry interface with `get`, `register`, `list` |

Built-in schemas: `education`, `employment`, `identity`, `health`, `business`.

### `packages/templates` — `@opencred/templates`

SVG templates for credential rendering.

| Export | Purpose |
|---|---|
| `getTemplate(schemaId)` | Returns the SVG template for a schema |
| `renderTemplate(template, data)` | Renders a credential into SVG output |

`scripts/embed-svgs.cjs` bakes the SVG files into the dist output at build time.

### `packages/dedi-client` — `@opencred/dedi-client`

HTTP client for the [Decentralized Directory (DeDi)](https://dedi.global/).

| Export | Purpose |
|---|---|
| `DeDiClient` | High-level adapter (revocation, schemas, contexts, public keys) |
| `DeDiApiClient` | Low-level API client |
| `DeDiPublishManager` | Orchestrator for publishing operations |
| `DeDiTokenManager` | Bearer-token auth flow |
| `CircuitBreaker`, `withRetry` | Resilience helpers |
| Registry constants | `REVOCATION_REGISTRY`, `DELEGATION_REGISTRY`, `PUBLIC_KEY_REGISTRY`, `SCHEMA_REGISTRY`, `CONTEXT_REGISTRY` |

### `packages/signing` — `@opencred/signing`

Hardware token (PKCS#11) and OS certificate store backends. Native addons live under `native/`.

| Export | Purpose |
|---|---|
| `SoftwareSigner` | File-based signing |
| `Pkcs11Signer`, `Pkcs11Session`, `Pkcs11Loader`, p11-kit discovery | Hardware tokens |
| `OsCertSigner`, `MacOSCertProvider`, `WindowsCertProvider` | OS cert store signing |

The native addons (`packages/signing/native/macos-keychain.mm`, `windows-cng.cpp`) are built via `node-gyp`. The Desktop build pipeline rebuilds them against the Electron ABI per target architecture (`apps/desktop/scripts/rebuild-native.cjs --arch=<target>`, driven by the `beforePack` hook and arch-verified by `afterPack` — see #641/#642).

### `packages/ca-adapter` — `@opencred/ca-adapter`

Certificate Authority adapter — extension point for "Issuer Seeking DSC" (Type 2) onboarding. The package defines the `CertificateAuthorityAdapter` interface (`requestDSC`, `checkStatus`). No CA implementations ship in v2; deployments wire their own.

### `packages/batch-core` — `@opencred/batch-core`

Streaming CSV ingestion shared by the Desktop client and the Docker server's batch engines. Replaces the old `parseCsv(string)` path that materialised three in-memory copies of the input before signing began. The streaming parser yields one `ParsedRow` at a time and enforces both row-count and per-record-byte caps fail-fast inside the parser.

| Export | Purpose |
|---|---|
| `streamingParseCsv` | Async iterable over parsed rows; respects `maxRecordBytes` and `maxRows`. |
| `parseCsv`, `parseRawCsv`, `detectDelimiter`, `applyMapping` | One-shot helpers for non-streaming callers. |
| `StreamingCsvRecordSizeError`, `StreamingCsvLimitError` | Error types raised when caps are exceeded. |
| Types | `BatchProgress`, `BatchRowResult`, `BatchRowStatus`, `ColumnMapping`, `CsvParseOptions`, `CsvParseResult`, `Delimiter`, `ParsedRow`, `RowValidationVerdict`, `StreamingCsvInput`, `StreamingCsvOptions`, `StreamingCsvParser` |

### `packages/verify-sdk` — `@opencred/verify`

Public verification SDK published as a single-install facade over `@opencred/verification`. Use this in third-party verifier services that embed verification without pulling the full server or workspace deps.

| Export | Purpose |
|---|---|
| `createVerifier(options?)` | Returns a `Verifier` function with a `.pdf(bytes)` method. Reusable across many verifications. |
| `verifyCredential(input, options?)` | One-shot helper equivalent to `createVerifier(options)(input)`. |
| `verifyPdf(bytes, options?)` | One-shot helper for PDF inputs. |
| `detectFormat(input)` | Wire-format inspector (`data-integrity` / `vc-jwt` / `sd-jwt-vc` / etc.) without verifying. |
| Re-exported types | `CredentialVerificationResult`, `VerificationCheck`, `VerificationInput`, `CredentialFormat`, `VerificationResultCode` |

`VerifySdkOptions` accepts optional `dedi` config (for revocation + did:web fallback), `trustAnchors` (PEM-encoded CSCA roots for DSC chains), `didResolver` (override the default did:key / did:jwk / did:web composite), and `logger`. With zero config, the verifier handles `did:key` / `did:jwk` credentials fully offline.

## Dependency direction

Dependencies flow downward — `apps/*` depend on `packages/*`, packages may depend on other packages, but never vice-versa. The `shared` package has no dependencies on any other workspace package.

```
apps/desktop ─┐               ┌── packages/crypto ──┐
              ├── packages/   │                     ├── packages/shared
apps/server  ─┘   verification├── packages/did ─────┤
                              ├── packages/vc-core ─┤
                              └── packages/dedi-client
                              packages/schema-engine ┐
                              packages/templates ────┴── packages/shared
                              packages/signing ───── packages/crypto + did + shared
                              packages/ca-adapter ── packages/shared
                              packages/batch-core ── packages/shared
                              packages/verify-sdk ── packages/verification + did + dedi-client
```

## See also

* [Building](building.md) — how to build everything
* [Testing](testing.md) — how to test everything
* [`pnpm-workspace.yaml`](../../pnpm-workspace.yaml) — the workspace definition
* Each package's own `package.json` and `src/index.ts` for the canonical export list
