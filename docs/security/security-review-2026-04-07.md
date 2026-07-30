# OpenCred Security Review — 2026-04-07

Reviewer: Team C (read-only audit)
Branch reviewed: `new-opencred-dev` (HEAD `9aa8e17e` plus tracked changes)
Issue: nfh-trust-labs/opencred#302

## Summary

15 findings — 2 critical, 4 high, 6 medium, 3 low.

| ID | Severity | Title |
|---|---|---|
| CRITICAL-1 | Critical | Data Integrity verifier accepts attacker-controlled JWK from `verificationMethod` fragment, bypassing DID trust |
| CRITICAL-2 | Critical | Server `/credentials/issue` ships with auth disabled by default |
| HIGH-1 | High | did:web resolver is vulnerable to DNS rebinding (TOCTOU between DNS check and `fetch`) |
| HIGH-2 | High | `SCHEMA_FETCH_URL` IPC handler uses single-address `dns.lookup` and unpinned fetch — incomplete SSRF protection |
| HIGH-3 | High | SVG template renderer fails to escape `credentialTitle`, `issuerName`, and `logoDataUri`, enabling XSS in distributed credentials |
| HIGH-4 | High | X.509 chain check has no trust anchor and silently passes when DID resolution fails |
| MEDIUM-1 | Medium | `windows-cng.cpp` `FindCertByThumbprint` uses unchecked `sscanf` with no hex validation, leaking uninitialised stack bytes |
| MEDIUM-2 | Medium | `verifyJwsProof` does not pass `algorithms` allowlist to `compactVerify` |
| MEDIUM-3 | Medium | `isPrivateIP` in `@opencred/shared` is missing several reserved IPv4/IPv6 ranges (CGNAT, multicast, reserved, IPv6 multicast/unspecified, partial fe80::/10) |
| MEDIUM-4 | Medium | Logger redaction misses base64url-encoded keys (`LONG_BASE64_RE` requires `+` character) |
| MEDIUM-5 | Medium | `getConfig`/`setConfig` IPC handlers expose any electron-store key to the renderer, including the encrypted DeDi credential blob |
| MEDIUM-6 | Medium | DeDi HTTPS enforcement bypassed when `NODE_ENV=development` or `test`; no SSRF check on user-supplied baseUrl |
| LOW-1 | Low | `BrowserWindow` runs with `sandbox: false`; no CSP, navigation, or window-open handlers |
| LOW-2 | Low | `forceCodeSigning: false` in electron-builder config |
| LOW-3 | Low | `OpenCredError` does not actually sanitize messages — `CLAUDE.md` claim is documentation-only |

## Methodology

This review covered the surfaces called out in issue #302:

1. **Crypto / signing** — `packages/crypto`, `packages/signing` (TS), the two N-API addons (`packages/signing/native/macos/macos-keychain.mm` and `packages/signing/native/windows/windows-cng.cpp`), PFX parser, PKCS#11 paths.
2. **Verification + did:web** — `packages/verification` (data-integrity, jws-proof, vc-jwt, sd-jwt-vc, x509-chain-check, checks), `packages/did/src/did-web.ts`, SSRF helpers in `packages/shared/src/ssrf.ts`.
3. **vc-core document loader** — `packages/vc-core/src/document-loader.ts`.
4. **Desktop IPC** — `apps/desktop/src/main/ipc-handlers.ts`, `preload.ts`, `index.ts` (`BrowserWindow` config).
5. **DeDi integration** — `packages/dedi-client` and the IPC handlers (`handleDeDi*`).
6. **Logging hygiene** — `apps/desktop/src/main/logger.ts`, grep for `console.log`, `pino`, `private`, `signing buffer` near key paths.
7. **Error responses** — `packages/shared/src/errors.ts` and consumer call sites.
8. **CSPRNG** — grep for `Math.random` across the entire repo.
9. **Dependency surface** — `package.json` files for unusual or known-bad packages.
10. **JSON-LD contexts** — bundled context loader and call sites.
11. **Server (Phase 6)** — `apps/server/src/index.ts`, `routes/credentials.ts`, `middleware/auth.ts`, `signing/cloud-hsm/factory.ts`.

I also traced the issue/verify flow end-to-end (build → sign → package → distribute → verify) and read the two native addons line-by-line for memory safety, bounds checks, and error-path key zeroisation.

For each finding I identify the file and line(s); I do not raise issues without a concrete code reference.

---

## Findings

### CRITICAL-1: Data Integrity verifier accepts attacker-controlled JWK in verificationMethod fragment

- **Severity**: Critical
- **Location**: `packages/verification/src/data-integrity.ts:103-119`
- **Introduced by**: commit `622f7766` "fix(verification): resolve JWK-fragment verificationMethod in Data Integrity proof"
- **Description**: `resolvePublicKeyFromVerificationMethod` is supposed to find the verification method in the resolved DID document. When `vms.find(...)` does not return a hit, the code falls back to decoding the URL fragment as a base64url-encoded JWK and uses that JWK as the trusted public key:

  ```ts
  if (!vm && fragmentId) {
    try {
      const decoded = fragmentId.slice(1);
      const jwkJson = JSON.parse(atob(decoded.replace(/-/g, "+").replace(/_/g, "/")));
      if (jwkJson.kty) {
        return createPublicKey({ key: jwkJson, format: "jwk" });
      }
    } catch { /* fall through */ }
    ...
  }
  ```

  The DID is never re-checked against the JWK. Any DID method whose document does not contain a VM whose `id` matches the supplied `verificationMethod` triggers this fallback — including `did:web`.
- **Impact**: Complete signature-verification bypass for Data Integrity (`ecdsa-rdfc-2019` and `eddsa-rdfc-2022`) credentials. An attacker who picks any legitimate `did:web:victim.example` with a published `did.json` can:
  1. Generate their own ECDSA P-256 key pair `(p_attacker, P_attacker)`.
  2. Build a credential with `issuer: "did:web:victim.example"` and `proof.verificationMethod: "did:web:victim.example#" + base64url(JSON.stringify(jwkOf(P_attacker)))`.
  3. Sign with `p_attacker`.
  Verification then runs the following: resolve `did:web:victim.example` (succeeds), look up VM by id (fails — fragment is the attacker's blob, not `key-0`), fall through, base64url-decode the fragment as JWK, return `P_attacker`, and `verifier.verify(...)` passes because the signature was made with `p_attacker`. The recipient sees `verified: true` for a credential the legitimate issuer never signed.
- **PoC**: Apply the bypass against any `did:web` issuer in your test fixtures (tests in `packages/verification/src/__tests__/data-integrity.test.ts` exercise resolvers but never test this fallback path; adding a test that mocks `resolver.resolve(...)` to return a doc whose VM ids do not match, then signs with an unrelated key, will pass verification today).
- **Recommendation**:
  1. Remove the JWK-fragment fallback entirely. The original use case (per the commit message) was a UI artifact for `did:key:...#<base64url(jwk)>`. Fix the UI to emit `did:jwk:...` (which is the spec-defined way to embed a JWK in a DID) or to use the multibase fragment that `DIDKeyResolver` already produces.
  2. If a fallback is required for `did:key`, gate it on `did.startsWith("did:key:")` AND on the decoded JWK matching the multicodec already encoded in the DID itself.
  3. Add a regression test that constructs the "wrong fragment + DID resolves to a different key" case and asserts verification **fails**.

### CRITICAL-2: Server `/credentials/issue` defaults to no authentication

- **Severity**: Critical
- **Location**: `apps/server/src/middleware/auth.ts:21-24`, `apps/server/src/config.ts:14-15`
- **Description**: `OPENCRED_API_KEY` is declared `z.string().optional()`, and `authMiddleware` short-circuits with `await next(); return;` whenever the key is unset. Since `apps/server/src/index.ts` mounts the credential issuance routes behind this middleware, **a Docker deployment that ships without explicitly setting `OPENCRED_API_KEY` exposes `POST /credentials/issue` and `POST /credentials/verify` to anyone with network access**, and the server happily signs arbitrary credentials with the loaded key.
- **Impact**: Unauthenticated remote credential issuance. An attacker who reaches the server (e.g., via exposed Kubernetes service, mis-configured ingress, dev tunnel) can mint signed credentials as the operator. This violates the `CLAUDE.md` invariant in spirit even if "the issuer key never leaves the controlled environment" — the *signing oracle* leaves the trust boundary.
- **Recommendation**:
  1. Make `OPENCRED_API_KEY` (or some auth method) **required** at config-load time. Fail fast in `loadConfig()` with a clear error message.
  2. If a "no auth" mode is genuinely needed for local dev, gate it behind an explicit `OPENCRED_AUTH_DISABLED=true` plus a startup-time `logger.warn` and refuse to accept the flag when `NODE_ENV=production`.
  3. Document the requirement in the server README.
  4. Optionally: refuse to bind to `0.0.0.0` when auth is disabled.

---

### HIGH-1: did:web resolver is vulnerable to DNS rebinding

- **Severity**: High
- **Location**: `packages/did/src/did-web.ts:181-220`
- **Description**: `DIDWebResolver.resolveViaHttps` (a) calls `dns.resolve4` / `dns.resolve6` for the hostname, (b) checks each resolved IP against `isPrivateIP`, then (c) calls `fetch(url, ...)` with the **original hostname**. Step (c) re-resolves DNS independently of step (a). A DNS rebinding attacker (or simply an attacker controlling the authoritative DNS for a domain that returns a public IP and then a private IP on the second query, or one that returns a multi-record set) can pass step (b) and have step (c) hit a private endpoint (e.g., `169.254.169.254`, internal admin services, localhost). Compare with `packages/verification/src/checks.ts:289-300`, which correctly **pins the resolved IP** in the URL and sets a `Host` header — that pattern should be applied here too.
- **Impact**: SSRF against internal services through forged `did:web` documents. Combined with CRITICAL-1 above, an attacker can also use this to point at attacker-controlled internal infra to make verification appear to succeed.
- **Recommendation**:
  1. After validating that all addresses are public, replace the URL hostname with one of the resolved IPs (with `[ipv6]` brackets when needed) and set `headers.Host` to the original hostname, mirroring `checkBitstringStatusList`.
  2. Add a test that mocks DNS to alternate between a public IP (first resolve) and a private IP (second resolve) and asserts the fetch never reaches the private IP.

> **Remediated (2026-07-30).** The resolver now pins the connection to the DNS-validated addresses via `fetchWithPinnedIp` (`packages/shared/src/pinned-fetch.ts`); a dedicated rebinding test suite lives in `packages/did/src/__tests__/did-web.test.ts`. Note: the recommended IP-in-URL + `Host`-header pattern turned out to be **TLS-broken** — Node validates the certificate against the URL host, so `fetch("https://<ip>/", { headers: { Host: hostname } })` fails with `ERR_TLS_CERT_ALTNAME_INVALID` for any host without an IP SAN (verified empirically). The `checkBitstringStatusList` code this finding cited as the correct pattern was therefore itself broken (every hostname-based status-list fetch failed TLS validation) and has been fixed the same way. The actual pin overrides the socket-level DNS `lookup` on a fresh non-keep-alive agent while the URL keeps the hostname, so SNI + certificate validation stay correct.

### HIGH-2: `SCHEMA_FETCH_URL` IPC handler uses `dns.lookup` and unpinned fetch

- **Severity**: High
- **Location**: `apps/desktop/src/main/ipc-handlers.ts:1355-1409`
- **Description**: The handler calls `dnsPromises.lookup(hostname)` which returns a single address from `getaddrinfo` (typically the first that resolves), checks it against `isPrivateIP`, then calls `fetch(url, ...)` with the original hostname. Two problems compound here:
  1. `dns.lookup` is not the same as `resolve4`/`resolve6`; for a hostname with multiple A records (e.g. `[1.2.3.4, 127.0.0.1]`) it may return only the first, leaving the second unchecked. The fetch then re-resolves and may hit the unchecked record.
  2. Same TOCTOU as HIGH-1 — DNS rebinding will bypass the check.

  Additionally, the handler depends on `isPrivateIP` from `@opencred/shared`, which is missing several reserved ranges (see MEDIUM-3).
- **Impact**: SSRF against the host's private network from the desktop main process. The renderer can call this IPC channel directly, so any future XSS path in the renderer (e.g. via the SVG injection in HIGH-3) lets a remote attacker drive the SSRF.
- **Recommendation**:
  1. Use `dns.resolve4` + `dns.resolve6` (matching `checks.ts` and `did-web.ts`).
  2. Pin the resolved IP into the fetch URL with a `Host` header.
  3. Switch to the more thorough `isPrivateIP` from `verification/src/checks.ts` (or merge that logic into `@opencred/shared`).
  4. Add a hard 1 MB cap on response size — currently the handler reads `await response.json()` with no size cap.

> **Remediated (2026-07-30).** Items 1 and 3 were fixed earlier (`resolveDnsForSsrf` with the merged `isPrivateIP`). The remaining TOCTOU is now closed: the handler fetches through `fetchWithPinnedIp` (socket pinned to the validated addresses — see the HIGH-1 note on why the `Host`-header approach in item 2 was not used), and the response body is streamed through `readBodyWithSizeLimit` with a 1 MiB cap (item 4). Tests: `apps/desktop/src/__tests__/schema-fetch-ssrf.test.ts`.

### HIGH-3: SVG template renderer leaves injection paths via credential-derived strings

- **Severity**: High
- **Location**: `packages/templates/src/renderer.ts:25-46`, plus `packages/templates/src/templates/default.svg` and the other bundled templates.
- **Description**: `renderSvg` populates a placeholder lookup map. Most credential-derived values are inserted **without escaping**:
  - `lookup.set("issuerName", values.issuerName)` — line 25, no escape.
  - `lookup.set("credentialTitle", values.credentialTitle)` — line 26, no escape. `credentialTitle` is `extractCredentialTitle(credential)` which reads from `credential.type[]` (caller-controlled).
  - `lookup.set("logoDataUri", customization.logoDataUri)` — line 45, no escape. Inserted in attribute context: `<image href="{{logoDataUri}}" />`.
  - `lookup.set("primaryColor", escapeXml(primaryColor))` — line 42 escapes XML chars only. The value lands inside a CSS rule (`<style>.header { fill: {{primaryColor}}; }</style>`); XML escape does not protect against CSS injection (e.g., `red; } body { background: url(javascript:...) } /*`).

  Subject fields (`subject.${key}`) and the customization-only `issuerDisplayName` ARE escaped via `escapeXml`. The credential-derived issuer name is not.
- **Impact**: A signed credential where `type[1]` or `issuer.name` contains active SVG markup will produce an SVG that, when opened by the recipient in any SVG viewer that executes script (every modern browser), runs attacker JavaScript in the recipient's context. SVGs are routinely shared as the "shareable" form of a credential and opened via drag-and-drop, downloads, and inline rendering. The signature does not protect against this — the issuer cooperates with the attacker (or the issuer's UI is compromised) and produces a self-signed SVG that runs script content for whoever opens it.
- **Recommendation**:
  1. Apply `escapeXml` to `issuerName` and `credentialTitle` before insertion.
  2. Validate `logoDataUri` is exactly a `data:image/...` URL (regex match) and refuse anything else; then escape XML attribute chars.
  3. Replace XML escape with a context-aware escape for CSS placeholders (allow only `#[0-9a-fA-F]{3,8}` and a small palette of named colors for `primaryColor`).
  4. Add tests that pass an injection payload through `issuerName` / `credentialTitle` / `logoDataUri` / `primaryColor` and assert the rendered SVG does not contain executable script.

### HIGH-4: X.509 chain check has no trust anchor and silently passes when DID resolution fails

- **Severity**: High
- **Location**: `packages/verification/src/x509-chain-check.ts:149-230`
- **Description**: `checkX509Chain` performs three checks: (1) leaf cert public key matches the DID's public key, (2) each cert is `checkIssued` and `verify`'d against the next, (3) all certs are within validity at proof.created time. It does **not** verify that the chain terminates in a trusted root (no CSCA list, no `verifyPeerCertificate`-style anchor check). It also explicitly skips check (1) when DID resolution returns nothing (`if (didPubKey) {...} // If DID can't be resolved, skip key binding check`). Combined with CRITICAL-1, an attacker can present a self-signed `x5c` chain plus a forged `verificationMethod`, and the credential will be reported as `code: "VALID"` with `x509-chain` passed.
- **Impact**: The x509-chain check provides a false sense of security. Credentials with arbitrary self-signed chains pass — there is no way to actually validate that a cert is a real DSC issued by a CSCA.
- **Recommendation**:
  1. Add a configurable trust anchor list (PEM bundle of CSCA roots). Refuse to "pass" the check unless the chain terminates in one of them.
  2. When the DID public key cannot be resolved, return a `passed: false` with detail "Unable to confirm leaf certificate matches credential issuer" instead of skipping silently.
  3. Verify the leaf cert's `keyUsage`/`extKeyUsage` allows `digitalSignature` for credential signing.

---

### MEDIUM-1: Windows CNG addon parses thumbprint hex with unchecked `sscanf`

- **Severity**: Medium
- **Location**: `packages/signing/native/windows/windows-cng.cpp:174-191` (`FindCertByThumbprint`)
- **Description**:
  ```cpp
  if (thumbprint.size() != 64) return nullptr;
  BYTE hashBytes[32];
  for (int i = 0; i < 32; i++) {
      unsigned int byte;
      sscanf(thumbprint.c_str() + i * 2, "%02x", &byte);
      hashBytes[i] = (BYTE)byte;
  }
  ```
  `sscanf` with `%02x` does not validate that the input characters are hex; on a non-hex input (e.g. an embedded NUL or a non-ASCII byte) `byte` is left **uninitialised** and the resulting `hashBytes[i]` reads stack memory. Length is checked but the character set is not.
- **Impact**: Information disclosure (small): the search blob handed to `CertFindCertificateInStore` may contain stack data. Because the search uses an exact-match against SHA-256 hashes, the practical impact is "search returns nothing" plus a tiny info leak in any subsequent log/error path that surfaces the blob. Defence-in-depth — should still be fixed.
- **Recommendation**: Validate `[0-9a-fA-F]` per character before parsing, and use `strtoul` with explicit length and error checking instead of `sscanf`. Also memset `hashBytes` to zero before the loop.

### MEDIUM-2: `verifyJwsProof` does not pass the algorithms allowlist to `compactVerify`

- **Severity**: Medium
- **Location**: `packages/verification/src/jws-proof.ts:76-78`
- **Description**: Both `vc-jwt.ts` and `sd-jwt-vc.ts` correctly pass `algorithms: ALLOWED_ALGORITHMS` to `jose.jwtVerify`. `jws-proof.ts` does not — it calls `await compactVerify(jwsString, publicKey)` with no options. jose v5 rejects `alg: none` by default, and `importJWK(publicKey, alg)` constrains the alg by key type, so the obvious "alg: HS256 with public key as secret" attack does not work in this code path. However, the explicit allowlist is cheap defence-in-depth; without it, future jose updates or refactors can quietly relax algorithm choice.
- **Impact**: Defence-in-depth gap.
- **Recommendation**: Add `algorithms: ["ES256", "ES384", "ES512", "EdDSA"]` to the `compactVerify` call.

### MEDIUM-3: `isPrivateIP` in `@opencred/shared` is missing several reserved ranges

- **Severity**: Medium
- **Location**: `packages/shared/src/ssrf.ts:25-89`
- **Description**: The shared `isPrivateIP` is the SSRF guard for `did:web` and `SCHEMA_FETCH_URL`. It misses:
  - **IPv4**: `100.64.0.0/10` (CGNAT, RFC 6598), `198.18.0.0/15` (benchmark), `192.0.0.0/24`, `192.0.2.0/24`/`198.51.100.0/24`/`203.0.113.0/24` (TEST-NET), `224.0.0.0/4` (multicast), `240.0.0.0/4` (reserved), `255.255.255.255`.
  - **IPv6**: `::` (unspecified), `ff00::/8` (multicast), `64:ff9b::/96` (NAT64 well-known prefix), most of `fe80::/10` — the code only checks `fe80:`, missing `fe81:`–`febf:`.
  - **IPv4-mapped IPv6 hex form** with compression (e.g. `::ffff:0:1`, `::ffff:7f00:1` without zero-padding) is partially handled but the regex `/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/` does not match the uncompressed form `0:0:0:0:0:ffff:c0a8:0101` or compressed-with-zero-groups variants.

  Compare with `packages/verification/src/checks.ts:92-128` which is more thorough — that file has its own duplicate `isPrivateIP` with most of the missing ranges.
- **Impact**: SSRF guards relying on the shared helper can be bypassed by addresses in CGNAT, multicast, or partial fe80::/10 space. Whether any of these is reachable depends on the host's network, but on cloud VMs CGNAT and TEST-NET ranges sometimes are.
- **Recommendation**:
  1. Consolidate the two `isPrivateIP` implementations into `@opencred/shared` and have `checks.ts` import it.
  2. Add the missing ranges (CGNAT, multicast, reserved, IPv6 unspecified, IPv6 multicast, full fe80::/10, NAT64 well-known prefix).
  3. For IPv6, normalise via `node:net.isIPv6` or expand the address with a small parser before string-matching.
  4. Fuzz-test the helper against `[0.0.0.0, 255.255.255.255, 169.254.169.254, 100.64.0.1, 224.0.0.1, fe9f::1, ::, ::ffff:7f00:1, 0:0:0:0:0:ffff:7f00:1, 64:ff9b::1.2.3.4]`.

### MEDIUM-4: Logger redaction misses base64url-encoded keys

- **Severity**: Medium
- **Location**: `apps/desktop/src/main/logger.ts:34-45`
- **Description**:
  ```ts
  const LONG_BASE64_RE = /(?=[A-Za-z0-9+/]*\+)[A-Za-z0-9+/]{40,}={0,3}/g;
  ```
  The regex requires `+` to be present, ostensibly to distinguish base64 from "URLs/paths/IDs". JWK private keys (`d` field) and most private-key serialisations encountered in practice use **base64url** (`-` and `_`, never `+`). A long base64url blob never matches this regex and is logged verbatim. The fallback `JWK_D_FIELD_RE` only catches the literal `"d":"..."` substring inside JSON; any wrapper format that quotes differently (e.g. `'d': '...'`, or `d=...` URL-encoded) is missed.
- **Impact**: Defence-in-depth gap. Today the desktop code does not log raw key material, but if a future change passes an `error.message` from `loadFromPem` (line 216 of `packages/crypto/src/signing-key-provider.ts` already does this) and the underlying error includes a base64url chunk, that chunk would not be redacted.
- **Recommendation**:
  1. Replace the `+`-anchored regex with a base64url-aware pattern (`/[A-Za-z0-9_-]{40,}={0,3}/g`) and apply it conservatively (perhaps only inside JSON-string contexts to avoid mauling URLs).
  2. Add a `redactBuffer` path so that `Buffer`/`Uint8Array` log values get redacted to `[BUFFER len]`.
  3. Add explicit unit tests for `redact` against PEM-stripped keys, JWK `d` fields, and base64url private key blobs.

### MEDIUM-5: `getConfig`/`setConfig` IPC handlers expose any electron-store key to the renderer

- **Severity**: Medium
- **Location**: `apps/desktop/src/main/ipc-handlers.ts:823-839`, `apps/desktop/src/main/preload.ts:258-262`
- **Description**: `handleGetConfig` and `handleSetConfig` accept arbitrary key names from the renderer and read/write the electron-store directly. The renderer can therefore read `preferences.dediCredentialEncrypted` (the safeStorage-encrypted DeDi credential blob) and overwrite any persisted preference, including the persisted importedKeyPaths used by `reloadPersistedSigners`. The encrypted DeDi blob cannot be decrypted in the renderer (decryption needs `safeStorage` in the main process), but exfiltrating it provides a foothold if an attacker later compromises the main process or the OS keychain.
- **Impact**: A renderer-side compromise (from any future injection path, e.g. HIGH-3) gives the attacker:
  1. Read access to the encrypted DeDi credential blob (cannot decrypt locally, but valuable for offline attacks).
  2. Write access to **any** preference key, including the ability to plant a malicious `importedKeyPaths.<id> = { path: "/tmp/evil.pem" }` that will be loaded as a signing key on the next app start.
- **Recommendation**:
  1. Replace the generic getter/setter with a *closed-set* of allowed keys, validated server-side. Keys like `preferences.dediCredentialEncrypted`, `customSchemas`, `dediConfig`, and `preferences.importedKeyPaths` should not be writable from the renderer.
  2. Audit every renderer call site of `getConfig`/`setConfig` and replace with a typed channel per setting.

### MEDIUM-6: DeDi HTTPS enforcement and SSRF coverage

- **Severity**: Medium
- **Location**: `packages/dedi-client/src/api/api-client.ts:51-58`
- **Description**: HTTPS enforcement is `if (url.protocol !== "https:" && process.env.NODE_ENV !== "development" && process.env.NODE_ENV !== "test")`. In a packaged Electron app, `NODE_ENV` is sometimes `development` (e.g., when launched via dev tooling) or unset, but if a user (or attacker who sets the env var) launches the binary with `NODE_ENV=development`, plain `http://` DeDi URLs are silently allowed and credentials transit in cleartext. There is also no SSRF check on the user-supplied `baseUrl` — the DeDi client will happily target `https://169.254.169.254/` if the user enters it. The user explicitly configures DeDi in Settings, so this is partially intentional, but the env-var bypass turns it into a real footgun.
- **Impact**: Credential theft for users tricked or coerced into running with `NODE_ENV=development`.
- **Recommendation**:
  1. Drop the env-var bypass entirely — tests and dev should use a different code path or wire HTTPS endpoints.
  2. Validate `baseUrl` host against the public-IP/SSRF check used elsewhere, at minimum at `dediSetConfig` time. Show the user a clear warning and refuse to save if the URL points to private/loopback space.

---

### LOW-1: BrowserWindow `sandbox: false`, no CSP/navigation handlers

- **Severity**: Low
- **Location**: `apps/desktop/src/main/index.ts:54-67`
- **Description**: `webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: false }`. Electron's recommended baseline is `sandbox: true`. There is also no `mainWindow.webContents.setWindowOpenHandler(...)` to deny `window.open`, no `will-navigate` handler, and no Content-Security-Policy header injected when loading the renderer index. The renderer is loaded from disk so the immediate injection surface is small, but any rendered third-party content (markdown, credential SVG previews) widens this.
- **Recommendation**:
  - Set `sandbox: true` and verify the app still functions.
  - Add `mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }))`.
  - Reject navigation away from the loaded `index.html` via `will-navigate`.
  - Inject a strict CSP via response headers (the renderer is local; `default-src 'self'; script-src 'self'; img-src 'self' data:` is achievable).

### LOW-2: `forceCodeSigning: false` in electron-builder config

- **Severity**: Low
- **Location**: `apps/desktop/package.json:77`
- **Description**: `"forceCodeSigning": false` lets release artifacts ship unsigned. Auto-updater still verifies signatures from GitHub Releases at install time, so the *release pipeline* must produce signed builds for the integrity guarantee to hold. If a release ever ships unsigned, the auto-updater path silently degrades.
- **Recommendation**: Flip to `true` and require code signing in CI before any artifact is uploaded.

### LOW-3: `OpenCredError` does not actually sanitize messages

- **Severity**: Low
- **Location**: `packages/shared/src/errors.ts:1-21`
- **Description**: `CLAUDE.md` claims "Use the `OpenCredError` hierarchy — it sanitizes by design." The class is a thin wrapper that stores the constructor-supplied `message` verbatim and exposes it via `toJSON()`. There is no scrubbing of paths, key material, or internal stack traces. Sanitisation depends entirely on the caller. Several call sites build messages from raw `error.message` strings (e.g. `signing-key-provider.ts:215-217`, `data-integrity.ts:325-327`, `verifier.ts` failure messages) which would propagate any leaked content.
- **Recommendation**: Either implement actual sanitisation in the hierarchy (regex out PEM blocks, base64 blobs, absolute filesystem paths) or update `CLAUDE.md` to remove the false claim and instead document a "wrapping pattern" each caller must follow.

---

## Invariant compliance summary

| Invariant | Status | Notes |
|---|---|---|
| 1. Never touch issuer private keys | Upheld | No code path accepts a private key over the wire. PFX/PEM import is local to the desktop main process; OS cert and PKCS#11 paths delegate signing to OS/HSM. The server reads `OPENCRED_KEY_PATH` from local disk only. |
| 2. No key material in logs | Mostly upheld | Logger has a redaction hook, but it misses base64url-encoded private keys (MEDIUM-4). No call site logs raw key bytes today. |
| 3. Session data ephemeral (TTL 4h) | Upheld in server (`OPENCRED_SESSION_TTL` default 14400s). Desktop has no equivalent — credentials persist in `customSchemas`/`recentTemplates`/`credentialHistory` until the user deletes them. The CLAUDE.md invariant is server-focused, so this is consistent. |
| 4. CSPRNG only — no `Math.random` | Upheld | No `Math.random` anywhere in `packages/` or `apps/`. All random uses go through `crypto.randomBytes`/`randomUUID`. |
| 5. No secrets in error responses | Mostly upheld | `OpenCredError` does not auto-sanitize (LOW-3), but call sites generally produce generic messages. Desktop IPC handlers return `err.message` verbatim in several places, which could leak filesystem paths from `fs` errors but no key material. |
| 6. JSON-LD contexts bundled | Upheld | `packages/vc-core/src/document-loader.ts` strictly serves bundled contexts and throws `ContextNotFoundError` on anything else. No remote fetching in production. |
| 7. did:web requires SSRF protection | Partially upheld | The hostname is checked via `isPrivateIP` before fetch, but the check uses an incomplete IP list (MEDIUM-3) and is vulnerable to TOCTOU/DNS-rebinding (HIGH-1). HTTPS-only and `redirect: "error"` are correctly enforced. *(2026-07-30: both gaps since remediated — see the HIGH-1 note.)* |

## Out of scope / not reviewed

- **PixelPass / @mosip/pixelpass internals** — only verified that the OpenCred wrapper passes credential JSON through safely.
- **electron-updater signature verification** — relies on the upstream library; not reviewed in depth.
- **Cloud HSM SDKs** (AWS KMS, Azure KV, GCP KMS) — only the OpenCred wrapper code reviewed; SDK trust is assumed.
- **DeDi server itself** — only the client side was in scope.
- **Renderer React components** — confirmed no use of dangerous innerHTML setters. Did not exhaustively audit for DOM-based injection paths.
- **CI/CD pipelines** (`.github/workflows`) — not in scope per the issue.
- **Code-signing certificates and notarisation pipeline** — assumed correct; only flagged the `forceCodeSigning: false` config (LOW-2).
- **Schema engine validator (ajv)** — surface-level review only; assumed ajv is configured safely.
