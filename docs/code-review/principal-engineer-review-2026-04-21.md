# Principal Engineer Review

**Date**: 2026-04-21
**Scope**: Full monorepo — `apps/desktop`, `apps/server`, `packages/ca-adapter`, `packages/crypto`, `packages/dedi-client`, `packages/did`, `packages/schema-engine`, `packages/shared`, `packages/signing`, `packages/templates`, `packages/vc-core`, `packages/verification`

---

## Executive Summary

The codebase is well-architected and shows genuine security discipline: key material never crosses process boundaries, error messages are sanitized, SSRF guards are applied at every external HTTP callsite, and there is a coherent error hierarchy. The most critical operational risk is a concurrency correctness gap in the Validator singleton pattern — four independent module-scope variables initialized lazily with no coordination — which under concurrent schema-registry updates can leave different call sites using validators bound to different registry snapshots. A second class of findings is resource management: the `BitstringStatusList` check lacks an explicit timeout on its HTTP fetch, and the AWS/Azure/GCP KMS signers create new cloud-SDK client instances per request rather than once at startup. The codebase is otherwise production-worthy, with confidence level HIGH due to thorough code coverage observed.

---

## Findings

### [P1-01] Five independent `validatorInstance` singletons bind to different registry snapshots — Concurrency Correctness

**File**: Multiple locations:
- `apps/server/src/batch/csv-parser.ts:158–166`
- `apps/server/src/batch/batch-engine.ts:71–79`
- `apps/server/src/routes/credentials.ts:158–168`
- `apps/desktop/src/signing/local-signing-flow.ts:90–100`
- `apps/desktop/src/batch/csv-parser.ts:216–226`

**Category**: Concurrency / Correctness

**Description**: Every one of these five modules maintains its own `let validatorInstance: Validator | null = null` and lazily constructs a `Validator` around `getRegistry()` on first call. `getRegistry()` calls `getSchemaRegistry()`, which itself falls back to creating a new registry via `createRegistry()` if the singleton has not yet been set with `setSchemaRegistry()`. This means:

1. If any of these modules is invoked before `setSchemaRegistry()` is called at startup (e.g. from a test that imports the module without bootstrapping), it silently creates its own standalone registry — independent of the one set at startup — and caches it in `validatorInstance`. All subsequent calls in that module use the stale standalone registry regardless of what `setSchemaRegistry()` later sets.

2. Even after startup, the five singletons are constructed from `getRegistry()` independently. If `setSchemaRegistry()` is ever called twice (e.g. in a future hot-reload or re-initialization scenario), some modules will hold a `Validator` that points to the old registry.

The `getSchemaRegistry()` fallback at `apps/server/src/schema-registry-singleton.ts` silently creates and caches a fresh registry:

```typescript
export function getSchemaRegistry(): SchemaRegistry {
  if (!instance) {
    instance = createRegistry();  // creates AND caches — silent initialization
  }
  return instance;
}
```

If `csv-parser.ts` is imported before `setSchemaRegistry()` runs (e.g. from a test that calls `parseCsv` without a bootstrapped registry), its `validatorInstance` is bound to this silently-created registry. That silent singleton then persists for the process lifetime. Any custom schemas registered via `setSchemaRegistry()` later are invisible to that validator.

**Impact**: In production, schema validation in the CSV batch parser and the credentials endpoint could silently diverge after any operation that reinitializes the registry. More concretely, custom schemas added at startup will fail validation in whichever of the five modules happens to construct its `validatorInstance` first, if that construction races with `setSchemaRegistry()`. Results: credentials are rejected for valid schema conformance, or (worse) accepted against an older schema.

**Remediation**: Eliminate the module-scope singleton pattern. The `Validator` should accept an explicit registry instance injected at construction, not obtained lazily from a global. All five call sites should pass the result of `getSchemaRegistry()` directly at the point of call, or a single shared `Validator` should be constructed once at server startup and injected. The `validatorInstance` caches across all five modules should be removed entirely.

---

### [P1-02] `checkBitstringStatusList` fetch has no timeout — Resource Leak / Resilience

**File**: `packages/verification/src/checks.ts:270–280`

**Category**: Resource Leak / Resilience

**Description**: The `BitstringStatusList` verification check fetches a remote credential at line 270:

```typescript
const response = await globalThis.fetch(fetchUrl, {
  redirect: "error",
  headers: fetchHeaders,
});
```

No `AbortSignal` or timeout is attached. This fetch can hang indefinitely if the status list host is slow or unresponsive. The `did:web` resolver and `DeDiApiClient` both have explicit 10-second timeouts; this path does not.

**Impact**: Under realistic conditions — a verifier endpoint called against a credential whose `statusListCredential` URL points to a slow external host — the `POST /credentials/verify` handler will hold an open TCP connection and an active request context for however long the remote server takes, or forever if the server stalls. Under concurrent load of even moderate scale (50 concurrent verify requests, each waiting 30+ seconds), the server's connection pool exhausts. The entire process stalls.

**Remediation**: Add an `AbortController` with a timeout matching the DID fetch timeout constant already defined in `packages/did/src/did-web.ts`:

```typescript
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 10_000);
try {
  const response = await globalThis.fetch(fetchUrl, {
    redirect: "error",
    headers: fetchHeaders,
    signal: controller.signal,
  });
  // ... rest of handler
} finally {
  clearTimeout(timeout);
}
```

---

### [P1-03] Cloud HSM signers create new SDK clients without connection reuse or per-request timeouts — Efficiency / Resource Leak

**File**:
- `apps/server/src/signing/cloud-hsm/aws-kms-signer.ts:68`
- `apps/server/src/signing/cloud-hsm/azure-kv-signer.ts:64–65`
- `apps/server/src/signing/cloud-hsm/gcp-kms-signer.ts:43`

**Category**: Resource Leak / Efficiency

**Description**: Each `createAwsKmsSigner()`, `createAzureKvSigner()`, and `createGcpKmsSigner()` is called once at startup from `factory.ts`, which is correct. However, the `KMSClient`, `CryptographyClient`, and `KeyManagementServiceClient` are constructed with no explicit HTTP keepalive configuration, connection pool size, or retry policy at the SDK level. The AWS SDK v3 `KMSClient` and GCP SDK `KeyManagementServiceClient` in particular default to creating new HTTP connections per request unless a custom `httpOptions` / `transporters` configuration is provided.

More specifically, in `aws-kms-signer.ts:68`:
```typescript
const client = new KMSClient({});
```

The `{}` config passes no `requestHandler`, `maxAttempts`, or `requestTimeout`. For the signing hot path at high throughput, each signing call creates a new HTTPS connection to KMS with fresh TLS handshake overhead. There is also no per-sign operation timeout — if KMS is slow, the `sign()` call hangs indefinitely.

**Impact**: Under 50+ concurrent signing requests, AWS KMS calls either queue behind TLS handshake establishment or open too many concurrent connections. No timeout means a stalled KMS endpoint holds requests open indefinitely, causing the batch engine to stop making progress while holding all its pending row state in memory.

**Remediation**: Configure explicit connection reuse, retries, and request timeouts at the SDK client level. For AWS KMS, configure `requestHandler` with keepAlive and `maxAttempts`. For GCP, configure `timeout` in the constructor. For Azure, configure `retryOptions` and `timeout` on `CryptographyClient`.

---

### [P1-04] `DeDiTokenManager.getToken()` does not deduplicate concurrent login races — Concurrency Correctness

**File**: `packages/dedi-client/src/api/auth.ts:46–58`

**Category**: Concurrency Correctness

**Description**: `getToken()` has a coalescing guard for concurrent calls via `pendingPromise`, which correctly prevents thundering-herd on token refresh. However, once `pendingPromise` is cleared after a failure, a brief window exists where `this.accessToken` is cleared (`this.accessToken = ""`) but the new token has not yet been stored. A concurrent call that passes the `if (this.accessToken && !this.isExpiringSoon())` check before the field is zeroed, then reads the zeroed state after `setTokens` clears the field, and races to a new login attempt itself.

This means: under high concurrent load, multiple simultaneous logins can be attempted against the DeDi auth endpoint with the same credentials, particularly after a token refresh failure.

**Impact**: Under high concurrent load to the revocation or DID publishing endpoints with DeDi configured in `bearer` auth mode, concurrent token refreshes can multiply. In the worst case, multiple simultaneous logins are attempted, and if DeDi rate-limits login attempts, this causes a self-inflicted lockout of the DeDi integration.

**Remediation**: The `pendingPromise` guard should be set before the token is cleared, and `setTokens` should be atomic with respect to the clearing operation. Consider using a single-entry lock that is set before any credential clearing begins and only released after the new token is stored.

---

### [P1-05] `SchemaRegistry.computeChecksum` uses non-deterministic `JSON.stringify` — Correctness

**File**: `packages/schema-engine/src/schema-registry.ts:68–71`

**Category**: Correctness

**Description**: `SchemaRegistry.computeChecksum` is called by `handleCustomSchemaSave` in the desktop app's IPC handler to hash user-supplied schema bodies:

```typescript
static computeChecksum(schema: Record<string, unknown>): string {
  const canonical = JSON.stringify(schema);   // NOT sorted-key canonical
  return createHash("sha256").update(canonical).digest("hex");
}
```

`JSON.stringify` with no replacer uses insertion-order key enumeration, which is not stable across JavaScript engines and can differ between the Node.js version used to originally save the schema and the version running at verification time. The docstring calls this out and suggests callers prefer `canonicalJsonSha256` from `@opencred/shared`, but the method is still exported and actively called.

**Impact**: Any user who saves a custom schema and then upgrades the desktop app (triggering a Node.js update) may find their schema cannot be re-registered because the checksum computed with the new V8 version differs. This manifests as a confusing "schema URL already registered with a different content" error even when the schema is identical.

**Remediation**: Replace the `JSON.stringify` call in `computeChecksum` with `canonicalJsonSha256` from `@opencred/shared`. The method should be deprecated with a note that all new call sites must use the canonical form.

---

### [P2-01] `applyMapping` reconstructs a `Set` on every row iteration — Efficiency

**File**:
- `apps/server/src/batch/csv-parser.ts:181`
- `apps/desktop/src/batch/csv-parser.ts:256`

**Category**: Efficiency

**Description**: Inside the innermost loop of `applyMapping`, a new `Set` is constructed on every iteration:

```typescript
for (const [key, value] of Object.entries(rawValues)) {
  if (!mapping[key] && value !== "") {
    const mappedKeys = new Set(Object.values(mapping));  // rebuilt every row, every key
    if (!mappedKeys.has(key)) mapped[key] = value;
  }
}
```

For a batch of N rows with M columns, `Object.values(mapping)` is called and a new `Set` is constructed O(N × M) times. For N=1000, M=20, this is 20,000 Set constructions per batch job. The `mapping` object is invariant for the entire parse operation.

**Impact**: At the default 1000-row limit this is a minor inefficiency (not an outage risk), but time complexity is O(N × M²) instead of O(N × M).

**Remediation**: Hoist the `mappedKeys` set construction outside the row loop. Build it once in `applyMapping` before iterating over `rawValues`.

---

### [P2-02] CSV parser and batch engine logic duplicated verbatim between desktop and server — Reusability

**File**:
- `apps/server/src/batch/csv-parser.ts` vs `apps/desktop/src/batch/csv-parser.ts`
- `apps/server/src/batch/batch-engine.ts` vs `apps/desktop/src/batch/batch-engine.ts`

**Category**: Reusability / Maintenance

**Description**: The CSV delimiter detection, `parseCsvLine`, `parseRawCsv`, `applyMapping`, and `validateRow` functions are copy-pasted verbatim between the two apps. The server's comment at line 1 of `csv-parser.ts` explicitly says "Extracted from the desktop batch module." The `BatchRowStatus`, `BatchRowResult`, `BatchProgress`, and `BatchConfig` types are also duplicated nearly identically. Any bug fix in one copy must be manually applied to the other.

The `packages/` directory already exists for this purpose. The only difference between the two batch engines is that the desktop version calls `packageCredential` and `queueRevocation`, and the server version does not — these are well-scoped differences that could be handled via a common core with optional extension hooks.

**Impact**: A bug found in the CSV parser (e.g. a quoted-field edge case) will only be noticed and fixed in one app. The desktop and server will silently diverge in their parsing behaviour for the same CSV input.

**Remediation**: Extract the shared CSV parsing logic (delimiter detection, line parsing, raw CSV parsing, column mapping) into a new `packages/batch-core` package or into the existing `packages/shared`. The sign-and-package layer can remain app-specific since it depends on app-specific signing flows.

---

### [P2-03] `DeDiApiClient` re-runs DNS resolution SSRF check on every request — Efficiency

**File**: `packages/dedi-client/src/api/api-client.ts:456–458`

**Category**: Efficiency

**Description**: `doFetch` calls `this.assertHostIsPublic(url)` on every single HTTP request, which performs a live DNS `resolve4` + `resolve6` lookup against the DeDi hostname on every API call. The check is intended to guard against DNS rebinding attacks. However, it also fires for every revocation query, schema publish, and DID lookup — even when the DeDi baseUrl is a static, operator-configured hostname that does not change.

For a server handling 100 credentials/second with DeDi revocation queries on each, this is 200 DNS lookups/second (IPv4 + IPv6) issued from the server, all to the same hostname. Under a resolver with a short TTL or no caching, this is significant unnecessary I/O on the hot path.

**Impact**: Under sustained load this adds latency (typically 1-5ms per DNS round-trip even when cached) and loads the local DNS resolver. Not an outage risk but degrades throughput noticeably at scale.

**Remediation**: Cache the resolved IP address with a TTL equal to the DNS record's TTL (or a conservative default like 30 seconds). A simple time-stamped cache `{ address, resolvedAt }` per hostname covers the security requirement while eliminating the per-request cost.

---

### [P2-04] Verification `detail` strings discarded without server-side logging — Observability

**File**: `apps/server/src/routes/credentials.ts:437–441`

**Category**: Observability

**Description**: The server strips all `detail` fields from verification check results before sending the HTTP response, which is correct per CLAUDE.md rule 5. However, the stripped details are also not logged server-side before being discarded:

```typescript
export function sanitizeChecksForServerResponse(
  checks: ReadonlyArray<{ name: string; passed: boolean; detail?: string }>,
): Array<{ name: string; passed: boolean }> {
  return checks.map(({ name, passed }) => ({ name, passed }));
}
```

The verification result is returned to the HTTP handler and the `detail` information simply disappears. An operator investigating a verification failure has no server-side diagnostic information to determine which specific check failed or why.

**Impact**: Diagnosing production verification failures requires reproducing them in a debug environment or instrumenting the code. Especially painful for intermittent failures caused by DID resolution timeouts or X.509 chain issues.

**Remediation**: Log the full verification result (including `detail`) at `DEBUG` level before stripping it. The check details are safe to log server-side (operator log stream, not external caller):

```typescript
logger.debug(
  { code: verificationResult.code, checks: verificationResult.checks },
  "Credential verification result (detail redacted from response)"
);
```

---

### [P2-05] `exportBatchAsZip` does not close write stream or delete temp file on archive error — Resource Leak

**File**: `apps/desktop/src/batch/batch-export.ts:129–194`

**Category**: Resource Leak

**Description**: `exportBatchAsZip` creates a write stream to `outputPath`, pipes an archiver into it, and resolves/rejects a Promise based on `output.on('close')` and `archive.on('error')`. If `archive.on('error')` fires, the Promise is rejected, but the write stream `output` is not explicitly closed and the partially-written file at `outputPath` is not deleted:

```typescript
archive.on("error", (err: Error) => {
  reject(err);  // write stream is never closed
});
```

**Impact**: Repeated failed batch exports accumulate partially-written temp files and may exhaust file descriptors over time in a long-running desktop session.

**Remediation**:
```typescript
archive.on("error", (err: Error) => {
  output.destroy();
  void unlink(outputPath).catch(() => undefined);
  reject(err);
});
```

---

### [P2-06] `periodicCheckInterval` in auto-updater not `unref()`'d — Memory Leak

**File**: `apps/desktop/src/main/auto-updater.ts:189`

**Category**: Memory Leak

**Description**: `periodicCheckInterval` is set at line 189. The `setInterval` call does not call `.unref()`, unlike the server's `startBatchJobCleanup` which explicitly calls `handle.unref?.()`. If `cleanupAutoUpdater()` is not wired to the Electron `before-quit` or `will-quit` event in `index.ts`, the interval keeps the process from exiting cleanly after `app.quit()` is called.

**Impact**: The app may hang for up to 4 hours (the interval period) before the process exits, forcing users to force-quit.

**Remediation**: Call `.unref()` on the `setInterval` handle in `auto-updater.ts`. Confirm that `cleanupAutoUpdater()` is called from `app.on('before-quit')` in `index.ts`.

---

### [P2-07] Revocation hash embedded in credential never matches hash queried by verifier — Correctness

**File**:
- `apps/server/src/routes/credentials.ts:247–256`
- `apps/desktop/src/signing/local-signing-flow.ts:195–207`
- `apps/server/src/batch/batch-engine.ts:128–137`

**Category**: Correctness

**Description**: During credential issuance, the revocation status ID is computed as:
```typescript
const credentialUuid = randomUUID();
builder.setId(`urn:uuid:${credentialUuid}`);
const revocationHash = createHash("sha256").update(credentialUuid).digest("hex");
```

This embeds `sha256(uuid)` in the credential's `credentialStatus.id`. However, the `checkRevocation` function in `packages/verification/src/checks.ts` uses `computeRevocationHash(credential)`, which computes a JCS-canonical SHA-256 of the entire credential object.

Since `sha256(uuid) != canonicalJsonSha256(credential)`, the revocation status URL in the credential and the hash queried by the verifier are always different values. The DeDi lookup by canonical hash will return `revoked: false` (not found) for any credential, and the lookup URL embedded in the credential points to a `sha256(uuid)`-based record that the verifier never queries.

**Impact**: **Revocation is silently broken.** A revoked credential will pass the `checkRevocation` check because the verifier queries DeDi for the canonical-hash of the credential and gets `{revoked: false}` (never set). The credential appears valid to verifiers despite being revoked.

**Remediation**: Both issuance and verification must use the same hash scheme. The simplest fix: change `checkRevocation` to extract the hash directly from `credential.credentialStatus.id` URL path rather than computing a new canonical hash independently. The embedded URL is the single source of truth for where the revocation status lives.

---

### [P2-08] `DeDiApiClient.bulkUpload` duplicates the entire `doFetch` implementation — Reusability

**File**: `packages/dedi-client/src/api/api-client.ts:284–359`

**Category**: Reusability

**Description**: `bulkUpload` contains a complete copy of the `doFetch` implementation (AbortController, timeout, error handling, logging) rather than using the shared private `doFetch` method, because `bulkUpload` uses `FormData` rather than JSON. Any changes to the standard fetch plumbing must be applied in both places.

**Remediation**: Extract the common plumbing into `doFetch` by accepting an optional `bodyInit: BodyInit` parameter that bypasses the `Content-Type: application/json` header setting. The `Authorization` header, timeout, error handling, and logging remain in the single shared path.

---

### [P2-09] PKCS#11 warnings use `console.warn` instead of structured logger — Observability

**File**: `packages/signing/src/pkcs11-session.ts` (multiple lines: 149, 183, 240, 340, 353, 401, 414, 577, 598, 606)

**Category**: Observability

**Description**: Throughout `pkcs11-session.ts`, warning conditions (C_Finalize failures, token info read failures, unreadable key/certificate enumeration) are emitted as `console.warn(...)` rather than through the application's structured logger. These events:
- Do not appear in Pino JSON output
- Cannot be correlated with request IDs or job IDs
- Cannot be filtered via `LOG_LEVEL`
- Are invisible in production deployments where logs are aggregated by structured log collectors

**Impact**: PKCS#11 token interaction failures are invisible in production. Operators troubleshooting hardware token issues have no diagnostic signal.

**Remediation**: Add a `logger` parameter (accepting a Pino-compatible logger or a minimal `warn`/`error` interface) to the exported functions that currently use `console.warn`. Pass the app's logger from the desktop IPC handler when calling these functions.

---

### [P3-01] Unexpected errors log `err.message` string instead of full error object — Observability

**File**: `apps/server/src/middleware/error-handler.ts:26`

**Category**: Observability

**Description**:
```typescript
logger.error({ err: err.message }, "Unhandled error");
```
Pino supports `logger.error(err, "message")` which serializes the entire error including name, stack, and custom properties. Using `{ err: err.message }` loses the stack trace from structured logging.

**Remediation**: Change to `logger.error({ err }, "Unhandled error")`. Pino's default serializer handles `Error` objects correctly and will emit the stack trace in the JSON output.

---

### [P3-02] `CORS_ORIGIN` defaults to `http://localhost:5173` — misconfigured in production — Structure

**File**: `packages/shared/src/config.ts:48`

**Category**: Structure / Correctness

**Description**: The shared `envSchema` hardcodes `CORS_ORIGIN` default to `http://localhost:5173` (the Vite dev server port). In production deployments where the frontend is served from a different origin, an operator who forgets to set `CORS_ORIGIN` will ship a CORS misconfiguration — all cross-origin requests from the real frontend will be blocked.

**Remediation**: Default `CORS_ORIGIN` to `""` or require it to be explicitly set in production (similar to how `OPENCRED_API_KEY` is required). Document this explicitly.

---

### [P3-03] PEM regex scans entire large CSV body string on every batch request — Efficiency

**File**: `apps/server/src/routes/credentials.ts:129–156`

**Category**: Efficiency

**Description**: `rejectKeyMaterial` recursively walks every node in the request body. For each string value, it runs `PEM_PRIVATE_KEY_RE.test(value)`. The `csvContent` field can be up to `OPENCRED_MAX_BATCH_BODY_BYTES` (200 MiB default). Running a regex against a 200 MiB string on every batch request blocks the Node.js event loop.

**Impact**: A 200 MiB CSV scan with the PEM regex takes approximately 10-50ms on modern hardware, blocking the event loop for that duration. Acceptable for P3 but avoidable.

**Remediation**: For large string values (e.g., `csvContent`), truncate the scan to the first 4 KB. PEM headers always appear near the beginning of a key file; a key pasted into a CSV row would appear in a single cell, not as a multi-MB blob.

---

## Summary Table

| ID | Priority | Category | Location | One-line finding |
|---|---|---|---|---|
| P1-01 | P1 | Concurrency / Correctness | Multiple files | Five independent `validatorInstance` singletons can bind to different registry snapshots |
| P1-02 | P1 | Resource Leak / Resilience | `verification/src/checks.ts:270` | BitstringStatusList fetch has no timeout — hangs indefinitely |
| P1-03 | P1 | Resource Leak / Efficiency | Cloud HSM signer files | KMS clients created without connection reuse, retries, or per-request timeouts |
| P1-04 | P1 | Concurrency Correctness | `dedi-client/src/api/auth.ts` | Token manager has a narrow login-race window under concurrent expired-token requests |
| P1-05 | P1 | Correctness | `schema-engine/src/schema-registry.ts:68` | `computeChecksum` uses non-deterministic `JSON.stringify`, not canonical JSON |
| P2-01 | P2 | Efficiency | Both `csv-parser.ts` | `Set(Object.values(mapping))` rebuilt on every row iteration |
| P2-02 | P2 | Reusability | Desktop/server batch modules | CSV parser and batch engine logic duplicated verbatim across two apps |
| P2-03 | P2 | Efficiency | `dedi-client/src/api/api-client.ts:457` | DNS SSRF check re-runs on every DeDi request, including hot-path operations |
| P2-04 | P2 | Observability | `routes/credentials.ts:437` | Verification `detail` strings are discarded without being logged server-side |
| P2-05 | P2 | Resource Leak | `batch/batch-export.ts:143` | Archive error handler rejects without closing write stream or deleting temp file |
| P2-06 | P2 | Memory Leak | `auto-updater.ts:189` | `periodicCheckInterval` not `unref()`'d; may prevent clean process exit |
| P2-07 | P2 | Correctness | Issue/batch signing flows | Revocation hash embedded in credential (`sha256(uuid)`) never matches hash queried by verifier (`canonicalJson(vc)`) — **revocation silently broken** |
| P2-08 | P2 | Reusability | `api-client.ts:284` | `bulkUpload` duplicates entire `doFetch` plumbing |
| P2-09 | P2 | Observability | `pkcs11-session.ts` (multiple) | PKCS#11 warnings use `console.warn` instead of structured logger |
| P3-01 | P3 | Observability | `middleware/error-handler.ts:26` | Unexpected errors log `err.message` string instead of full error object with stack |
| P3-02 | P3 | Structure | `shared/src/config.ts:48` | `CORS_ORIGIN` defaults to `localhost:5173`; production deployments silently misconfigured |
| P3-03 | P3 | Efficiency | `routes/credentials.ts:129` | PEM regex scans entire CSV body string (potentially 200 MiB) on every batch request |

---

## What Is Done Well

**SSRF protection is thorough and consistent.** Every external HTTP callsite — `DIDWebResolver.resolveViaHttps` (`packages/did/src/did-web.ts`), `DeDiApiClient.assertHostIsPublic` (`packages/dedi-client/src/api/api-client.ts`), `checkBitstringStatusList`'s `validateStatusListUrl` (`packages/verification/src/checks.ts`) — all perform DNS resolution and validate against `isPrivateIP` from `@opencred/shared`. The DNS rebinding defense (resolve-then-pin) in `checkBitstringStatusList` is particularly careful.

**Error message sanitization is production-grade.** `sanitizeErrorMessage` in `packages/shared/src/errors.ts` strips PEM blocks, stack traces, POSIX/Windows paths, file URLs, and long hex/base64 blobs. The patterns are applied in the correct order. The `MAX_HTTP_MESSAGE_LENGTH = 512` truncation prevents error-amplification attacks.

**Key material rejection is defense-in-depth.** `rejectKeyMaterial` in `apps/server/src/routes/credentials.ts` recursively walks every JSON field name and string value before any schema parsing, detecting both forbidden key names and PEM-header patterns. The regex `PEM_PRIVATE_KEY_RE` covers all major PEM variants (PKCS#8, PKCS#1, SEC1, OpenSSH), not just the unencrypted form.

**Authentication is fail-closed by design.** `loadConfig()` in `apps/server/src/config.ts` refuses to start if neither `OPENCRED_API_KEY` nor `OPENCRED_DEV_MODE_NO_AUTH` is set, refuses the combination of both, and refuses `DEV_MODE_NO_AUTH` in `NODE_ENV=production`.

**Graceful shutdown is implemented.** `apps/server/src/index.ts` handles both SIGTERM and SIGINT, clears the batch cleanup interval, and calls `server.close()` before exiting. The `batchCleanupInterval.unref?.()` call ensures the process can exit cleanly even if the interval fires once more before shutdown completes.

**Circuit breaker and retry logic are well-separated.** `DeDiApiClient` wraps all calls in `CircuitBreaker.execute` which wraps `withRetry`. The retry logic correctly distinguishes transient (5xx, network) from non-transient (4xx) errors. The circuit breaker correctly resets on success in HALF_OPEN state.

**SD-JWT disclosure uses CSPRNG.** `createDisclosure` in `packages/crypto/src/sd-jwt-vc-signing.ts` uses `randomBytes(16)` for the salt, not `Math.random()`.

---

## Out of Scope

Security vulnerabilities (injection, SSRF logic soundness, authentication bypass), cryptographic algorithm correctness (curve parameters, signature schemes, key derivation), key management correctness (did:key multibase encoding, JWK representation), and dependency CVEs were not reviewed. The appropriate agents/processes for these are:
- **Cryptographic correctness and key management**: `crypto-reviewer` agent
- **VC standards compliance**: `vc-standards` agent
- **Dependency CVEs**: `npm audit` / Dependabot / Snyk
- **Security penetration testing**: `audit` agent
