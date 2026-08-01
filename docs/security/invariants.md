# Security Invariants

OpenCred's security model is built on seven invariants. These rules are non-negotiable. Every code path, every PR, and every contributor must respect them. They are documented in [`CLAUDE.md`](../../CLAUDE.md) at the root of the repository as the first thing every contributor reads.

This page explains each invariant: what it says, why it matters, and where it is enforced in code.

## 1. Never touch issuer private keys

> No endpoint, no function, no code path should accept an issuer's private key as input. All signing happens locally on the issuer's machine or within the Docker container.

**Why it matters.** This is the architectural foundation of OpenCred. The product's promise to issuers is "your key never leaves your environment." Any leak of this rule — even a debug-only path that accepts a key — would fundamentally undermine trust in the product. Once trust is gone, it cannot be restored by patching the leak.

**Where it's enforced.**

* **By absence**: there is no HTTP endpoint, IPC handler, or library function that accepts a private key parameter. You can verify this by searching `apps/server/src/routes/*.ts` and `apps/desktop/src/main/ipc-handlers.ts`. The route schemas in `apps/server/src/routes/credentials.ts` (`issueRequestSchema`) accept `issuerDid` (a public identifier) but not key material.
* **In design**: signing is mediated by the abstract `SigningKeyProvider` and `SoftwareSigner` / `Pkcs11Signer` / `OsCertSigner` / Cloud HSM signer interfaces in `packages/signing` and `apps/server/src/signing/`. Each backend loads its key from a *local* source (file path, hardware token, OS cert store, KMS reference) — never from a request body.
* **In tests**: any PR that adds a private-key parameter to a public function should fail review. The PR template explicitly asks reviewers to confirm this invariant.

**Defense in depth**: even if a developer accidentally tried to log or echo a key, [Invariant 2](#2-never-log-key-material) and [Invariant 5](#5-no-secrets-in-error-responses) catch it.

## 2. Never log key material

> No private keys, no signing buffers in `pino` logs, `console.log`, error messages, or stack traces. Log the key *ID* or *fingerprint*, never the key itself.

**Why it matters.** Logs are written to disk, shipped to log aggregators, indexed, archived, and inevitably read by people who shouldn't see secrets. A single leaked log line can compromise a key forever.

**Where it's enforced.**

* **At the source**: the signing call sites in `packages/crypto`, `apps/desktop/src/main/`, and `apps/server/src/routes/credentials.ts` never pass key bytes to a logger. They pass the `signer.id` and `signer.algorithm` if anything.
* **By redaction (Desktop)**: `apps/desktop/src/main/logger.ts` installs an `electron-log` hook that strips:
  * PEM blocks (`-----BEGIN…-----END…-----`) → `[REDACTED-PEM]`
  * JWK `d` (private key) fields → `"d":"[REDACTED]"`
  * Long base64 strings containing `+` (a marker that distinguishes base64 from URLs/IDs) → `[REDACTED]`
  The hook runs before any transport writes, so even rejected log calls cannot leak.
* **By construction (Docker)**: `apps/server/src/logger.ts` is a clean pino instance with no key-touching code paths upstream of it.

The `redact` and `redactValue` helpers in the Desktop logger are exported for unit testing.

## 3. Session data is ephemeral

> Credential payloads, built VCs, and packaged output are purged within TTL (default 4 hours).

**Why it matters.** Even though OpenCred doesn't store keys, it does temporarily hold credential subject data — which often contains PII — in memory while building and signing. A long-running process that retains this data indefinitely becomes a high-value target.

**Where it's enforced.**

* The Docker server holds session state in process memory only. There is no database. The TTL is configured by `OPENCRED_SESSION_TTL` (default 14400 seconds = 4 hours), validated in `apps/server/src/config.ts`.
* The Desktop client's credential history is local and capped at 100 entries (`apps/desktop/src/main/store.ts`).
* Batch results are held in memory by `apps/server/src/batch/` and purged on TTL expiry.

**What this means for callers.** If a credential is built but the caller never retrieves it within the TTL, it is gone forever. Callers must either retrieve and persist the credential themselves, or accept that re-issuance is needed.

## 4. CSPRNG only

> All key generation must use `crypto.randomBytes` or equivalent CSPRNG. Never use `Math.random()` for anything security-related.

**Why it matters.** `Math.random()` is a non-cryptographic PRNG. Its output is predictable to anyone with a few samples. Using it to generate keys, nonces, or tokens makes those values trivially guessable.

**Where it's enforced.**

* Key generation: `LocalSigningKeyProvider` in `packages/crypto/src/signing-key-provider.ts` uses `generateKeyPairSync('ec', { namedCurve: 'P-256' })`, which is backed by OpenSSL's CSPRNG.
* UUID generation: `randomUUID()` from `node:crypto` (CSPRNG-backed) — used in `apps/server/src/routes/credentials.ts` for credential IDs.
* By policy: no `Math.random()` calls exist in any security-relevant code path. The codebase is small enough to grep — `Math.random()` only appears in non-security utilities (e.g., picking a random visual variant for a template card).

## 5. No secrets in error responses

> Error responses must never leak key material, internal paths, or signing buffers. Use the `OpenCredError` hierarchy — it sanitizes by design.

**Why it matters.** Error messages are user-facing. Whatever the developer puts in the message ends up in browser consoles, log aggregators, and bug reports. If a stack trace contains a buffer or a path, it propagates everywhere.

**Where it's enforced.**

* **The error hierarchy**: `packages/shared/src/errors.ts` defines `OpenCredError` and a small set of subclasses (`ValidationError`, `AuthenticationError`, `NotFoundError`, `CryptoError`, `DIDResolutionError`, etc.). Each takes a *string* message and an *opaque* code. The `toJSON()` method emits only `code` and `message` — no stack traces, no internal state.
* **Server error handler**: `apps/server/src/middleware/error-handler.ts` catches every thrown error, distinguishes `OpenCredError` instances (return their JSON form), `ZodError` instances (return validation details only), and unknown errors (return a generic 500 with no detail).
* **Convention**: when constructing an `OpenCredError`, the message must be safe to expose to a caller. Avoid string-interpolating buffers, paths, or secrets. The DID resolver, for example, says `"SSRF protection: DID document host resolves to a private IP"` — informative without leaking the actual IP.

If you find an error message that leaks a path or a buffer, that's a bug — file an issue.

## 6. JSON-LD contexts are bundled

> Never fetch remote contexts at runtime in production — use the bundled document loader. Remote fetch is a supply-chain attack vector.

**Why it matters.** JSON-LD processing requires resolving `@context` URLs to context documents. If those documents are fetched from the network at verification time, an attacker who controls the network or the context host can change the document and alter the meaning of every credential being verified. This is a classic supply-chain attack vector against signed JSON-LD systems.

**Where it's enforced.**

* `packages/vc-core/src/document-loader.ts` defines `createDocumentLoader()`, which serves contexts from a static `BUNDLED_CONTEXTS` map. The map includes:
  * `https://www.w3.org/ns/credentials/v2`
  * `https://w3id.org/security/data-integrity/v1`
  * `https://schema.nfh.global/contexts/{education,employment,identity,health,business}/v1`
* Any URL not in the map throws `ContextNotFoundError` — there is no HTTP fallback.
* Build-time embedding: `packages/vc-core/scripts/embed-contexts.cjs` runs as part of `pnpm build` and copies the JSON files into the dist output. The exact bytes that ship are version-controlled.

Adding a new context means adding it to the bundled set. There is no way to "just fetch this one URL" — that path does not exist.

## 7. did:web resolution requires SSRF protection

> When fetching DID documents for `did:web` verification, always validate that resolved IPs are public (use `isPrivateIP` from `@opencred/shared`). HTTPS only, no redirects, 10-second timeout.

**Why it matters.** `did:web` resolution converts a DID to an HTTPS URL on a third-party domain and fetches it. Without protection, an attacker who can submit a DID for verification can use that as a primitive for Server-Side Request Forgery: request `did:web:internal.corp.example`, OpenCred fetches `https://internal.corp.example/.well-known/did.json`, leaking the response back through the verification result. Cloud metadata endpoints (e.g., `169.254.169.254`) are particularly attractive targets.

**Where it's enforced.**

`packages/did/src/did-web.ts` (`DIDWebResolver.resolveViaHttps`):

1. **HTTPS only** — `didWebToUrl` always returns an `https://` URL. The spec requires it.
2. **DNS resolution before fetch** — `resolveDnsForSsrf` (from `packages/shared/src/ssrf.ts`) resolves both A and AAAA records and passes **all** returned addresses to `isPrivateIP`. If **any** address is private, the request is rejected with `"SSRF protection: DID document host resolves to a private IP"`. Non-benign DNS errors fail closed.
3. **Connection pinned to the validated addresses (DNS-rebinding / TOCTOU prevention)** — the fetch goes through `fetchWithPinnedIp` (`packages/shared/src/pinned-fetch.ts`), which overrides the socket-level DNS `lookup` on a fresh non-keep-alive agent so the connection can only reach the addresses that passed step 2. DNS is never re-consulted between check and connect, so a rebinding DNS server has nothing to poison. The URL keeps the original hostname, so TLS SNI and certificate validation still run against the hostname. (Never "pin" by putting the IP in the URL with a `Host` header — that breaks TLS certificate validation with `ERR_TLS_CERT_ALTNAME_INVALID`.)
4. **No redirects** — `fetchWithPinnedIp` never follows redirects (`https.request` has no redirect-following); a 3xx surfaces as an HTTP error. A 302 to an internal address is never chased.
5. **10-second timeout** — `AbortController` with `setTimeout(controller.abort, 10_000)`.
6. **Document ID match** — the resolved document's `id` field MUST equal the requested DID. If not, resolution fails.
7. **Fallback resolvers don't get a free pass** — if a DeDi fallback resolver is configured, it is **not** tried when the primary fetch fails with an SSRF error. SSRF errors are security boundaries, not transient network issues.

**Everywhere else the same pattern applies.** `did:web` is the canonical case, but every outbound fetch of a semi-trusted URL uses the same validate-then-pin sequence: the status-list fetch (`packages/verification/src/checks.ts`), the schema-update fetch (`packages/schema-engine/src/schema-updater.ts`), the desktop `SCHEMA_FETCH_URL` IPC handler (`apps/desktop/src/main/ipc-handlers.ts`), batch webhook delivery to the operator-supplied `webhookUrl` (`apps/server/src/batch/webhook.ts`), and every DeDi API request (`packages/dedi-client/src/api/api-client.ts`). The DeDi token/registration calls in `packages/dedi-client/src/api/auth.ts` are the one remaining gap.

The `isPrivateIP` helper covers:

| Range | Type |
|---|---|
| `10.0.0.0/8` | RFC 1918 private |
| `127.0.0.0/8` | Loopback |
| `0.0.0.0/8` | Reserved |
| `169.254.0.0/16` | Link-local (includes cloud metadata) |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `::1` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |
| `::ffff:<ipv4>` (dotted) | IPv4-mapped IPv6 — recursively checks the IPv4 |
| `::ffff:<hex>:<hex>` | IPv4-mapped IPv6 in hex form — same recursive check |

The IPv4-mapped IPv6 cases were specifically added (PR #277) to close a bypass where an attacker could specify `192.168.1.1` as `::ffff:c0a8:0101` and slip past a naive IPv4-only check.

## How to verify the invariants in a PR

When reviewing any change that touches signing, logging, errors, or network code, ask:

1. **Invariant 1**: Does this PR add a path that accepts a private key, even indirectly?
2. **Invariant 2**: Does any new log call contain key material? Does any new test assert on a log line containing a key?
3. **Invariant 3**: Does this PR introduce persistent storage of credential payloads, or extend retention beyond the configured TTL?
4. **Invariant 4**: Does this PR use `Math.random()` for anything other than cosmetic randomness?
5. **Invariant 5**: Do new error messages contain paths, buffers, or secrets? Are new errors thrown as `OpenCredError` subclasses?
6. **Invariant 6**: Does this PR fetch a JSON-LD context from the network? If so, why?
7. **Invariant 7**: Does this PR introduce a network fetch from a user-supplied URL? If so, does it go through the SSRF-checked path?

If the answer to any of these is "yes" — and the PR doesn't have a clear, reviewed justification — the PR should not merge.
