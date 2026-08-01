# Threat Model

This page describes what OpenCred protects against, what it deliberately does not protect against, and the assumptions it makes about the environment it runs in.

## Assets

The assets OpenCred handles are:

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Issuer private key | **Critical** — direct credential forgery | Issuer's machine (Desktop) or container filesystem (Docker). Never on disk in OpenCred-controlled storage. |
| Credential payload (subject data) | High — may include PII | In-process memory, ephemeral. Purged within session TTL. |
| Built and signed credential | High — issuer-attributed | In-process memory until returned to caller. Then the caller's responsibility. |
| Issuer DSC public key + cert metadata | Low — public information | Stored alongside key references in the Desktop config file (chmod 0600). |
| DeDi auth credentials (when revoking) | High | Held in memory for the duration of the publish call. Not persisted. |

## Adversaries

OpenCred's threat model considers three classes of adversary:

### A1 — Network attacker

Can observe and manipulate network traffic between OpenCred and other parties (DeDi, did:web hosts, Cloud HSMs, the holder downloading a credential).

### A2 — Local unprivileged attacker

A user account on the same machine that does **not** own the issuer's key file. The Desktop client is installed under the user's home directory; the Docker container runs as `node`, not root.

### A3 — Compromised dependency

A supply-chain attacker who manages to ship a malicious npm package or alter a remote JSON-LD context.

We do **not** model adversaries with root on the issuer machine, physical access to the device, or the ability to alter OpenCred's binaries before launch — those are out of scope and rely on the operating system, secure boot, and code signing.

## Threats and Mitigations

### T1 — Theft of the issuer's private key

| Vector | Mitigation |
|---|---|
| OpenCred uploads the key to a remote service | **Architectural elimination.** No code path accepts an issuer private key as input ([Invariant 1](invariants.md#1-never-touch-issuer-private-keys)). The key never leaves the issuer's environment. |
| Logs leak the key | A redaction hook on `electron-log` strips PEM blocks, JWK `d` fields, and long base64 strings before any transport writes ([Invariant 2](invariants.md#2-never-log-key-material), `apps/desktop/src/main/logger.ts`). The Docker server's pino logger never logs key material in the first place. |
| Error responses leak the key | All errors flow through the `OpenCredError` hierarchy, which only exposes a stable error code and a sanitized message ([Invariant 5](invariants.md#5-no-secrets-in-error-responses), `packages/shared/src/errors.ts`). |
| Key file readable by other users on disk | The Desktop config file is set to `0600`. The Docker image expects the key to be mounted read-only and protected on the host. |

**Residual risk**: a local unprivileged attacker who can read the key file directly (e.g., wrong file permissions on the host) or attach a debugger to the OpenCred process can read the key. This is out of OpenCred's scope; rely on OS-level access control.

### T2 — Forgery of credentials

An attacker who does not hold the issuer's private key cannot produce a credential that verifies as the issuer. The signature itself is a cryptographic proof of possession of the key, so this threat reduces to T1 (theft of the key).

A weaker form: an attacker tricks OpenCred into signing a credential they crafted. The Desktop UI's signing flow is gated on user interaction (the user must click **Build & Sign**). The Docker server's `POST /credentials/issue` endpoint is gated on the optional Bearer token (`OPENCRED_API_KEY`).

| Mitigation | Where |
|---|---|
| Bearer token auth on issue endpoint | `apps/server/src/middleware/auth.ts` |
| Schema validation before signing | `packages/schema-engine` (`Validator.validateOrThrow`) |
| Signing key loaded once at startup, not per-request | `apps/server/src/signing/key-manager.ts` (`requireSigner`) |
| User confirmation in Desktop UI | `apps/desktop/src/renderer/components/IssuePage.tsx` |

**Residual risk**: anyone with valid API access can sign anything that passes schema validation. Use a strong API key and rotate it.

### T3 — Theft of credential subject data (PII)

Credential payloads often contain personal information. OpenCred limits exposure by being **stateless**:

| Mitigation | Where |
|---|---|
| Session data is ephemeral, purged within TTL (default 4h) | [Invariant 3](invariants.md#3-session-data-is-ephemeral); `OPENCRED_SESSION_TTL` |
| No persistent credential storage in the Docker server | The server has no database |
| Desktop credential history is local-only and capped at 100 entries | `apps/desktop/src/main/store.ts` |
| Logs do not include credential bodies | pino logger structure |
| Error responses do not echo request bodies | Sanitized via `OpenCredError` |

**Residual risk**: while a credential is being built and signed it lives in process memory. A core dump or memory inspection tool could expose it. Run OpenCred with `ulimit -c 0` and disable kernel core dumps in production.

### T4 — Server-Side Request Forgery (SSRF)

A user-supplied URL (e.g., a `did:web` identifier) tricks OpenCred into fetching from internal infrastructure (cloud metadata, other internal services).

| Mitigation | Where |
|---|---|
| `did:web` resolver enforces HTTPS only | `packages/did/src/did-web.ts` (`resolveViaHttps`) |
| Redirects never followed | `packages/shared/src/pinned-fetch.ts` (`https.request` has no redirect-following; a 3xx surfaces as an HTTP error) |
| 10-second timeout | `packages/did/src/did-web.ts` (`AbortController`) |
| DNS resolution + private-IP rejection | `packages/shared/src/ssrf.ts` (`resolveDnsForSsrf` / `isPrivateIP`) — covers IPv4 ranges (10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 0/8, CGNAT, benchmarking, multicast, reserved), IPv6 (`::1`, `fc00::/7`, `fe80::/10`, multicast, discard), and IPv4-mapped IPv6 (`::ffff:` in dotted and hex forms) |
| DNS-rebinding (TOCTOU) prevention — the connection is **pinned** to the validated addresses; DNS is never re-consulted between check and connect | `packages/shared/src/pinned-fetch.ts` (`fetchWithPinnedIp`: socket-level `lookup` override on a fresh non-keep-alive agent; the URL keeps the hostname so TLS SNI + certificate validation still run against it) |
| Document ID must match requested DID | `packages/did/src/did-web.ts` (`resolveViaHttps`) |

This mitigation is enforced at the boundary of every did:web fetch and is non-bypassable. The fallback resolver path is **not** tried on SSRF errors. The same validate-then-pin pattern protects every other outbound fetch of a semi-trusted URL: the status-list fetch (`packages/verification/src/checks.ts`), the schema-update fetch (`packages/schema-engine/src/schema-updater.ts`), and the desktop `SCHEMA_FETCH_URL` IPC handler (`apps/desktop/src/main/ipc-handlers.ts`).

**Residual risk**: a sophisticated attacker who controls a public DNS zone can set its A record to a public IP they also control, then have that public IP serve a malicious DID document. Mitigation is the document-ID match, the validity check, and the verifier's overall trust chain.

### T5 — Supply chain (malicious dependency or context)

| Vector | Mitigation |
|---|---|
| Remote JSON-LD context is replaced or compromised | All JSON-LD contexts are bundled at build time. The custom document loader rejects any URL not in the bundled set ([Invariant 6](invariants.md#6-json-ld-contexts-are-bundled), `packages/vc-core/src/document-loader.ts`). |
| Malicious npm package | `pnpm install --frozen-lockfile` in CI; `pnpm audit` for advisories. Pinned base image digests in Dockerfiles for reproducible builds. |
| Compromised native addon (`pkcs11js`, OS cert addons) | Loaded only on demand, not at startup. Native addons are built locally during `pnpm install` and rebuilt against the Electron ABI via `electron-rebuild`. |

### T6 — Denial of service

| Vector | Mitigation |
|---|---|
| Very large request body | Hono's default body size limit (configurable). The request handler is async and back-pressured. |
| Very large CSV upload | `OPENCRED_BATCH_ROW_LIMIT` (default 1000) caps batch size; the parser rejects larger inputs before doing work. |
| Slow `did:web` fetch | 10-second timeout via `AbortController` |
| Cloud HSM rate limits | Caller must handle. The signer surfaces errors via `CryptoError`. |

OpenCred deliberately does not implement application-level rate limiting. Run it behind a reverse proxy (nginx, Caddy, Envoy) that does.

### T7 — Time-based attacks on PIN comparison (OID4VCI)

The legacy OID4VCI module compares pre-authorized code PINs in constant time to prevent timing oracles. See `apps/server/src/oid4vci/` (legacy/optional).

## Out of Scope

OpenCred deliberately does **not** protect against:

* **Compromised host OS** — if the attacker has root or kernel access on the issuer machine, no application-layer measures help.
* **Rubber-hose cryptanalysis** — coercing the issuer to sign credentials.
* **Credential theft after issuance** — once a signed credential leaves OpenCred, it is the holder's responsibility to protect.
* **Domain takeover** — for `did:web`, if the issuer's domain is compromised at the DNS or TLS level, anyone controlling the domain can publish a new DID document. See [Trust chains](../concepts/trust-chains.md) for the tradeoffs.
* **Holder deception** — OpenCred has no holder app and no role in credential delivery to subjects. Phishing the holder is out of scope.
* **Privacy of the verifier** — OpenCred's verifier may make network calls (did:web resolution, DeDi lookup) which expose the verifier's identity to those services.

## Trust Boundaries

```
+----------------------------+              +-----------------------------+
|                            |              |                             |
|  Issuer's Environment      |              |  Verifier's Environment     |
|  (Desktop or Docker)       |              |  (Wallet, browser, server)  |
|                            |              |                             |
|   +--------------------+   |   network    |   +---------------------+   |
|   |                    |   |  (untrusted) |   |                     |   |
|   |   OpenCred         | <-+--------------+-> |   Verification      |   |
|   |   - keys (local)   |   |              |   |   - public key      |   |
|   |   - signing        |   |              |   |   - DID resolution  |   |
|   |   - schema check   |   |              |   |   - status check    |   |
|   |                    |   |              |   |                     |   |
|   +--------------------+   |              |   +---------------------+   |
|                            |              |                             |
+----------------------------+              +-----------------------------+

  Trust boundary: the issuer's environment.
  Everything inside that box is trusted.
  Everything outside is treated as adversarial.
```

OpenCred's job is to ensure that nothing leaves the trust boundary except the credential bytes the issuer chose to release.
