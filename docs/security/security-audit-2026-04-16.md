# OpenCred Security Audit Report

**Date**: 2026-04-16
**Auditor**: Claude (automated)
**Scope**: Full codebase — `packages/*`, `apps/*`

---

## Executive Summary

OpenCred demonstrates a strong security posture overall. The most critical CLAUDE.md security invariants are upheld: no `Math.random()` is used in any security-sensitive context; private keys are handled exclusively as Node.js `KeyObject` instances and never serialised or logged; the bundled JSON-LD document loader prevents remote context fetching during signing and verification; SSRF protection via `isPrivateIP` is applied consistently across DID resolution, DeDi client requests, webhook delivery, and schema updates; and error responses are sanitised through the `OpenCredError` hierarchy before reaching callers.

However, six findings of material significance were identified: the server's in-memory batch job store has no TTL/purge mechanism, meaning signed credentials accumulate indefinitely in process memory; the `credentialSubject.id` field (passed as `subjectDid`) is not validated as a DID or URI, allowing injection of arbitrary strings including `javascript:` or `data:` URIs; the PKCS#11 library path is entirely user-controlled with no path-traversal or allowlist guard; a secondary local `isPrivateIP` implementation in `packages/verification/src/checks.ts` diverges from the canonical implementation in `@opencred/shared`; the Electron View menu exposes `toggleDevTools` in production builds; and the server has no HTTP body size limit middleware, making it susceptible to oversized-payload DoS.

---

## Findings

### HIGH-01 — No TTL Purge for In-Memory Batch Job Store

**Severity**: High
**Location**: `apps/server/src/routes/batch.ts:31–213`

**Description**: The `jobs` Map is a module-level global that is populated on every `POST /credentials/batch` call. Completed job objects include the full `BatchEngine` and its `BatchProgress`, which contains every signed `VerifiableCredential` (or compact JWT string) produced during the batch run. There is no periodic cleanup, no TTL enforced at job insertion, and no call to `jobs.delete()` anywhere in `batch.ts`. The `OPENCRED_SESSION_TTL` configuration variable (default 4 hours) is defined in `config.ts` but never actually used to expire or delete job entries.

**Impact**: Signed credentials from completed batch jobs accumulate in process memory for the lifetime of the server process. An attacker who obtains process memory via a heap dump, core file, or a future memory-disclosure vulnerability will find the complete signed credential payloads of every batch ever run since the last restart. This violates CLAUDE.md security invariant 3 ("Session data is ephemeral. Credential payloads, built VCs, and packaged output are purged within TTL (default 4 hours)").

**Remediation**: At job insertion, record `createdAt`. Add a `setInterval` cleanup (run every 5–15 minutes) that calls `jobs.delete(id)` for any job where `Date.now() - new Date(job.createdAt).getTime() > config.OPENCRED_SESSION_TTL * 1000`. Results should be fetched and discarded (or explicitly exported) before TTL expiry. Document the TTL in the API contract so callers know the result window.

---

### HIGH-02 — `credentialSubject.id` / `subjectDid` Accepts Arbitrary Strings Without URI Validation

**Severity**: High
**Location**: `apps/server/src/routes/credentials.ts:187–221`, `apps/desktop/src/main/ipc-handlers.ts:444–446`

**Description**: Both the server (`issueRequestSchema`) and the desktop IPC handler (`BuildAndSignRequest`) accept `subjectDid` as `z.string().optional()` with no validation beyond being a non-empty string. This value is placed directly into `credentialSubject.id` in the built credential:

```typescript
// apps/server/src/routes/credentials.ts:220-221
if (parsed.subjectDid) {
  subject["id"] = parsed.subjectDid;
}
```

There is no check that the value is a valid DID (`did:*`) or HTTPS URI. The `CredentialBuilder.setCredentialSubject()` method in `packages/vc-core/src/credential-builder.ts` does not validate the `id` field of `credentialSubject`. The result is that `credentialSubject.id` can be set to `javascript:alert(1)`, `data:text/html,...`, or any other string, which gets signed and embedded in the final VC.

**Impact**: A client can issue credentials with malformed or injection-capable values in `credentialSubject.id`. Relying-party software that renders credential subject IDs as clickable links (common in VC wallets) could be vulnerable to XSS or phishing depending on their rendering context. The issued credential carries this injected value under a valid cryptographic signature, making it appear authoritative. Additionally, arbitrary strings in the `id` field may cause JSON-LD canonicalization to behave unexpectedly.

**Remediation**: Add a Zod refinement or a dedicated validator function that checks `subjectDid` against the pattern `/^(did:[a-z]+:[^\s]+|https?:\/\/.+)$/i`. The `CredentialBuilder` should also validate `credentialSubject.id` when present, rejecting any value that is not a DID, `urn:uuid:`, or `https://` URI. Mirror the validation already present on `issuer` in `packages/vc-core/src/credential-builder.ts:26-27`.

---

### HIGH-03 — PKCS#11 Library Path Is User-Controlled Without Path Allowlist or Validation

**Severity**: High
**Location**: `apps/desktop/src/main/ipc-handlers.ts:1212–1350`

**Description**: The `handlePkcs11Detect`, `handlePkcs11ListSlots`, `handlePkcs11ListKeys`, and `handlePkcs11Connect` IPC handlers accept a `libraryPath` string from the renderer process and pass it directly to `fs.stat()` and `initializePkcs11(request.libraryPath)` — which calls `p11.load(libraryPath)` on the native `pkcs11js` module. The only validation performed is checking the file extension (`.so`, `.dll`, `.dylib`):

```typescript
// apps/desktop/src/main/ipc-handlers.ts:1224-1231
const ext = request.libraryPath.toLowerCase();
const validExtensions = [".so", ".dll", ".dylib"];
const hasValidExt = validExtensions.some((e) => ext.endsWith(e));
```

There is no absolute-path check, no restriction to approved directories (e.g., `/usr/lib/`, `/usr/local/lib/`), and no check against a list of known-good PKCS#11 library filenames.

**Impact**: The renderer process is an untrusted context (it runs web content). A compromised or malicious renderer could supply a path to any `.so`/`.dylib` file on the system — including application libraries, third-party shared objects, or an attacker-uploaded file — that would be `dlopen`-ed into the main process at native code execution level. This is a potential arbitrary code execution path if the renderer is ever compromised.

**Remediation**: Implement an allowlist of permitted PKCS#11 library directories (configurable, defaulting to platform-standard paths such as `/usr/lib/`, `/usr/local/lib/`, `/Library/OpenSC/lib/`, `C:\Windows\System32\`). Before calling `initializePkcs11`, resolve the path to its realpath and verify it is within an allowed directory. Also verify the file is owned by root/Administrator and not world-writable. Consider requiring explicit user confirmation via a native file dialog (`dialog.showOpenDialog`) rather than accepting a renderer-supplied path string.

---

### MED-01 — Duplicate `isPrivateIP` Implementation in `packages/verification`

**Severity**: Medium
**Location**: `packages/verification/src/checks.ts:92–128`

**Description**: `packages/verification/src/checks.ts` contains a hand-rolled local `isPrivateIP` function that duplicates — but diverges from — the canonical `isPrivateIP` exported by `@opencred/shared`. The local version does not cover `0.0.0.0/8`, CGNAT (`100.64.0.0/10`), benchmarking ranges (`198.18.0.0/15`), multicast (`224.0.0.0/4`), or reserved (`240.0.0.0/4`) IPv4 ranges. The IPv6 handling also has gaps compared to the shared implementation.

**Impact**: An attacker who controls the `credentialStatus.id` URL in a presented credential could supply an HTTPS URL that resolves to an IP in an unchecked private range (e.g., `198.18.0.1`). The `checkBitstringStatusList` function would proceed to fetch from that URL, enabling SSRF within the verification package's status list checking path.

**Remediation**: Remove the local `isPrivateIP` function from `packages/verification/src/checks.ts` and replace it with the import from `@opencred/shared`. The shared implementation is already tested against all required ranges.

---

### MED-02 — No HTTP Request Body Size Limit on Server API

**Severity**: Medium
**Location**: `apps/server/src/index.ts` (entire middleware stack)

**Description**: The Hono server has no request body size limit middleware applied globally. Both `POST /credentials/issue` and `POST /credentials/batch` parse the full request body with `c.req.json()` before any size check. A client can send a multi-gigabyte JSON body that is fully buffered by the Node.js HTTP server before being parsed.

**Impact**: An unauthenticated attacker (if the API key is leaked or in dev mode) — or an authenticated attacker — can exhaust the server's heap memory with a single crafted request, causing an out-of-memory crash.

**Remediation**: Apply Hono's `bodyLimit` middleware globally before the auth middleware:

```typescript
import { bodyLimit } from "hono/body-limit";
app.use("*", bodyLimit({ maxSize: 50 * 1024 * 1024 })); // 50 MB ceiling
```

The batch CSV path additionally needs a separate, tighter limit.

---

### MED-03 — Electron `toggleDevTools` Exposed in Production Build Menu

**Severity**: Medium
**Location**: `apps/desktop/src/main/index.ts:186`

**Description**: The application menu's "View" submenu includes `{ role: "toggleDevTools" }` unconditionally — it is not gated on `IS_DEV`. While CSP, `nodeIntegration: false`, and `contextIsolation: true` provide meaningful isolation, the DevTools expose the renderer's JavaScript context and allow invoking any method exposed on `window.opencred` — including `signCredential`, `buildAndSign`, and `setConfig` — from the DevTools console.

**Remediation**: Gate `toggleDevTools` behind the `IS_DEV` flag:

```typescript
...(IS_DEV ? [{ role: "toggleDevTools" as const }] : []),
```

---

### MED-04 — `schemaFetchUrl` IPC Handler Uses `dns.lookup` Instead of Checking All IPs

**Severity**: Medium
**Location**: `apps/desktop/src/main/ipc-handlers.ts:1585–1589`

**Description**: The `handleSchemaFetchUrl` IPC handler performs an SSRF check using `dns.lookup(hostname)`, which returns only a single address. The canonical DID resolvers use `dns.resolve4` and `dns.resolve6` concurrently and check **all** resolved addresses. A DNS server that returns a public address first and a private address second would pass this check.

**Remediation**: Replace `dns.lookup` with `dns.resolve4` / `dns.resolve6` and check all returned addresses. Use the `resolveDnsForSsrf` helper already exported from `@opencred/shared/ssrf.ts`.

---

### MED-05 — `validUntil` Has No Upper Bound

**Severity**: Medium
**Location**: `packages/vc-core/src/credential-builder.ts:138–146`, `apps/server/src/routes/credentials.ts:184`

**Description**: The `setValidUntil` method validates that `validUntil` is after `validFrom`, but imposes no upper bound. A caller can set `validUntil` to `9999-12-31T23:59:59Z` and receive a cryptographically valid, signed credential that will never expire.

**Impact**: An operator misconfiguration or malicious API caller could issue effectively permanent credentials. If the signing key is ever compromised, permanent credentials cannot be invalidated through natural expiry.

**Remediation**: Enforce a maximum validity period (e.g., 10 years, or a configurable `OPENCRED_MAX_VALIDITY_YEARS` environment variable) at `build()` time in `CredentialBuilder`.

---

### LOW-01 — `handleKeyImport` Returns Raw `err.message` Without Sanitisation

**Severity**: Low
**Location**: `apps/desktop/src/main/ipc-handlers.ts:262–266`

**Description**: The `catch` block in `handleKeyImport` returns the raw error message directly to the renderer. Node.js `fs.readFileSync` and `createPrivateKey` can produce messages containing the full filesystem path. Several other `catch` blocks in `ipc-handlers.ts` have the same pattern.

**Remediation**: Wrap errors through `sanitizeErrorMessage` (already exported from `@opencred/shared`) before returning them in IPC responses, or wrap in a `ValidationError` to get automatic sanitisation via `toJSON()`.

---

### LOW-02 — Schema Update Mechanism Trusts Remote Manifest for `downloadUrl` Without Domain Restriction

**Severity**: Low
**Location**: `packages/schema-engine/src/schema-updater.ts:181–195`

**Description**: The schema update checker fetches a remote manifest and iterates over `manifest.schemas` entries, calling `ssrfSafeFetch(entry.downloadUrl, ...)`. The `downloadUrl` comes from the remote manifest with no requirement that it shares the same domain as the manifest URL. A compromised manifest server could redirect schema downloads to an arbitrary third-party HTTPS host.

**Remediation**: Restrict `downloadUrl` to the same origin as `manifestUrl`, or sign the manifest with a pinned public key and verify the signature before trusting its content.

---

### LOW-03 — `proofCreated` Timestamp Could Be User-Supplied via `ProofOptions.created`

**Severity**: Low
**Location**: `packages/crypto/src/data-integrity.ts:96–97`

**Description**: `buildProofConfig` accepts an optional `options.created` field. If supplied, the proof's `created` timestamp is set to the caller-provided value rather than the current server time. No production call site currently passes this, but the `ProofOptions` type exposes it.

**Remediation**: Remove the `created` field from `ProofOptions` and always use `new Date().toISOString()` in `buildProofConfig`. Gate backdating behind a test-only flag if needed.

---

### LOW-04 — Webhook Secret Falls Back to `OPENCRED_API_KEY`

**Severity**: Low
**Location**: `apps/server/src/routes/batch.ts:127`

**Description**: The webhook HMAC secret is `config.OPENCRED_API_KEY ?? ""`. This reuses the server's authentication credential as the HMAC signing key for webhook deliveries, coupling their lifecycles and leaking information about the API key to webhook receivers.

**Remediation**: Introduce a dedicated `OPENCRED_WEBHOOK_SECRET` environment variable. If unset, either refuse to deliver webhooks or document clearly that webhook authenticity is not verified.

---

### INFO-01 — `credentialHistory` in Desktop Store Persists Full Signed Credential JSON

**Severity**: Informational
**Location**: `apps/desktop/src/main/store.ts:31`

**Description**: The `CredentialHistoryEntry` interface includes `credentialJson: string` (the full signed credential JSON) stored in `electron-store`. The field is marked `@deprecated` with a migration to `recentTemplates` (metadata only) in progress. Full signed VC payloads persisting indefinitely on disk contradicts invariant 3.

**Remediation**: Complete the migration from `credentialHistory` to `recentTemplates`. On startup, null out or delete the `credentialHistory` key after migrating entries.

---

### INFO-02 — `console.log` Statements in Preload Script

**Severity**: Informational
**Location**: `apps/desktop/src/main/preload.ts:18,20,282,284`

**Description**: Four `console.log` startup diagnostics are visible in the renderer's DevTools console in production builds, confirming internal implementation details (`window.opencred`, preload script execution order).

**Remediation**: Gate behind `process.env.NODE_ENV !== 'production'` or remove and forward to the structured main-process logger via `ipcRenderer`.

---

### INFO-03 — DeDi DNS Connectivity Check Uses Hardcoded `dns.google` as Probe Target

**Severity**: Informational
**Location**: `apps/desktop/src/main/revocation-queue.ts:279`

**Description**: The revocation queue's connectivity check resolves `dns.google` before attempting DeDi publication. In privacy-sensitive or enterprise environments where outbound DNS to external resolvers is blocked, this probe always fails, preventing revocation publication even when the DeDi server is reachable.

**Remediation**: Use the DeDi server hostname as the connectivity probe target instead of `dns.google`.

---

### INFO-04 — Hardcoded Bug Report Form URL Modifiable by Renderer

**Severity**: Informational
**Location**: `apps/desktop/src/main/store.ts:154`

**Description**: The default `bugReportFormUrl` is a hardcoded external URL listed in `ALLOWED_CONFIG_KEYS`, meaning the renderer can override it via `setConfig`. A malicious renderer could redirect bug reports (which may include `getRecentLogs` data) to an attacker-controlled URL.

**Remediation**: Validate that `bugReportFormUrl` starts with a known domain when set via `setConfig`, or move it to a read-only configuration the renderer cannot modify.

---

## Checklist Summary

| Category | Check | Result |
|---|---|---|
| **Key Management** | ECDSA P-256 keypairs generated with `generateKeyPairSync` | Pass |
| **Key Management** | `Math.random()` absent from security-sensitive paths | Pass |
| **Key Management** | Private keys never written to disk beyond issuer's own import | Pass |
| **Key Management** | Private keys held as `KeyObject`, not serialised | Pass |
| **Key Management** | Software key files validated for format and P-256 curve | Pass |
| **Key Management** | PKCS#11 library path user-controlled without directory allowlist | **Fail (HIGH-03)** |
| **Signing** | Algorithm restricted to P-256, P-384, Ed25519 | Pass |
| **Signing** | Weak algorithms rejected | Pass |
| **Signing** | `proof.verificationMethod` bound to the actual signing key | Pass |
| **Signing** | Canonicalisation (RDFC-1.0 / URDNA2015) applied before signing | Pass |
| **Signing** | `proof.created` from server clock (overridable via `ProofOptions.created`) | Partial (LOW-03) |
| **Signing** | `proofPurpose` hardcoded to `assertionMethod` | Pass |
| **VC Construction** | Credential payloads validated against JSON Schema before signing | Pass |
| **VC Construction** | `credentialSubject.id` validated as DID or URI | **Fail (HIGH-02)** |
| **VC Construction** | `@context` URLs restricted to bundled set; no remote fetch | Pass |
| **VC Construction** | `validFrom` / `validUntil` validated as ISO 8601 | Pass |
| **VC Construction** | Upper bound on `validUntil` | **Fail (MED-05)** |
| **VC Construction** | Bulk CSV subject to same schema validation as single issuance | Pass |
| **VC Construction** | Row limit enforced on batch CSV input | Pass |
| **JSON-LD Contexts** | Remote context fetching blocked in production | Pass |
| **JSON-LD Contexts** | Bundled document loader used for all `@context` lookups | Pass |
| **JSON-LD Contexts** | JSON-LD safe mode (`safe: true`) enabled by default | Pass |
| **Revocation** | DeDi query response SSRF-protected | Pass |
| **Revocation** | HTTPS enforced for all DeDi queries | Pass |
| **did:web Resolution** | `isPrivateIP` from `@opencred/shared` called before every HTTP request | Pass |
| **did:web Resolution** | All resolved IPs (IPv4 + IPv6) checked | Pass |
| **did:web Resolution** | Redirects disabled (`redirect: "error"`) | Pass |
| **did:web Resolution** | 10-second timeout enforced | Pass |
| **did:web Resolution** | HTTPS only | Pass |
| **SSRF Protection** | Canonical `isPrivateIP` used consistently | Partial (MED-01) |
| **API Security** | API key check applied to all endpoints | Pass |
| **API Security** | Constant-time API key comparison (`timingSafeEqual`) | Pass |
| **API Security** | Request body size limit | **Fail (MED-02)** |
| **API Security** | Structured errors; no internal paths/stack traces in responses | Pass |
| **API Security** | Private key material in request bodies explicitly rejected | Pass |
| **Electron Security** | `contextIsolation: true` | Pass |
| **Electron Security** | `nodeIntegration: false` | Pass |
| **Electron Security** | `sandbox: true` | Pass |
| **Electron Security** | `webSecurity` not disabled | Pass |
| **Electron Security** | IPC handlers validate inputs from renderer | Partial (PKCS#11 path does not — HIGH-03) |
| **Electron Security** | `preload` minimal, `contextBridge` used correctly | Pass |
| **Electron Security** | `toggleDevTools` gated on `IS_DEV` | **Fail (MED-03)** |
| **Electron Security** | Navigation guard prevents renderer from loading external URLs | Pass |
| **Session Data** | TTL purge for server batch jobs | **Fail (HIGH-01)** |
| **Session Data** | Desktop credential history migration from full payloads to metadata | Partial (INFO-01) |
| **Logging** | Redaction hook strips PEM blocks, JWK `d` field, long base64 | Pass |
| **Logging** | Key material never passed to logger directly | Pass |
| **Error Handling** | `OpenCredError` hierarchy used consistently | Pass |
| **Error Handling** | `toJSON()` sanitises paths, PEM blocks, hex/base64 blobs, stack traces | Pass |
| **Error Handling** | Raw `err.message` returned in some IPC handler catch blocks | Partial (LOW-01) |
| **Dependencies** | CSPRNG used for all security randomness | Pass |
| **Auto-Update** | Uses `electron-updater` with signature verification | Pass |
| **Auto-Update** | Updates served over HTTPS from GitHub Releases | Pass |

---

## Recommendations (Priority Order)

1. **HIGH-01 — Implement server batch job TTL purge**
   Add a `setInterval` cleanup in `apps/server/src/routes/batch.ts` that deletes job entries older than `config.OPENCRED_SESSION_TTL` seconds. Wire `OPENCRED_SESSION_TTL` to the actual cleanup interval — the config value is currently defined but never used.

2. **HIGH-02 — Validate `subjectDid` / `credentialSubject.id` as a DID or URI**
   Add a Zod refinement in both the server `issueRequestSchema` and the desktop `BuildAndSignRequest` type to reject any `subjectDid` that is not a `did:*`, `urn:uuid:*`, or `https://` URI. Add the same validation inside `CredentialBuilder.setCredentialSubject()`.

3. **HIGH-03 — Add a PKCS#11 library path allowlist**
   Replace the extension-only check with a directory-prefix allowlist. Use `dialog.showOpenDialog` with explicit file-type and directory filters rather than accepting a renderer-supplied string path.

4. **MED-01 — Consolidate `isPrivateIP` usage to `@opencred/shared`**
   Remove the hand-rolled duplicate in `packages/verification/src/checks.ts` and import the canonical `isPrivateIP` from `@opencred/shared`.

5. **MED-02 — Apply HTTP body size limit middleware**
   Add Hono's `bodyLimit` middleware at the global level before authentication.

6. **MED-03 — Gate `toggleDevTools` on `IS_DEV`**
   One-line change to remove DevTools access from production builds.

7. **MED-04 — Replace `dns.lookup` with `dns.resolve4`/`resolve6` in schema fetch SSRF check**
   Use the `resolveDnsForSsrf` helper from `@opencred/shared/ssrf.ts`.

8. **MED-05 — Add upper bound on `validUntil`**
   Enforce a maximum validity period in `CredentialBuilder.build()`.
