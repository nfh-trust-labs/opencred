# Security Model

This section documents the security guarantees OpenCred makes — and the boundaries of those guarantees. If you operate OpenCred in production, or you're auditing it before adoption, start here.

## The Single Most Important Rule

**OpenCred never receives, handles, or stores issuer private keys.**

All cryptographic signing happens **locally**: on the issuer's Desktop machine, or inside the issuer-operated Docker container. There is no code path — no endpoint, no function, no IPC handler — that accepts an issuer's private key as input. There is no hosted OpenCred service. NFH Trust Labs operates no servers that touch issuer credentials.

This rule is non-negotiable. It is enforced by [Invariant 1](invariants.md#1-never-touch-issuer-private-keys) and underpins the entire security model.

## Pages in this section

* [Threat model](threat-model.md) — what OpenCred protects against, and what it does not
* [Key handling](key-handling.md) — how issuer keys are loaded, used, and never persisted
* [Invariants](invariants.md) — the seven mandatory rules and where each one is enforced

## At a glance

| Area | Guarantee |
|---|---|
| Issuer keys | Never received by OpenCred. Always loaded locally and held in memory as opaque KeyObject instances. |
| Key generation | Always uses CSPRNG (`crypto.generateKeyPairSync`, `crypto.randomBytes`). `Math.random()` is forbidden. |
| Logging | Key material is stripped from log records by a redaction hook before reaching disk. |
| Error responses | Use the `OpenCredError` hierarchy, which sanitizes by design. No internal paths or buffers leak in error JSON. |
| Session data | Credential payloads, packaged outputs, and batch results are purged within `OPENCRED_SESSION_TTL` (default 4 hours). |
| JSON-LD contexts | Bundled at build time. Never fetched from the network at runtime. |
| `did:web` resolution | HTTPS only, no redirects, 10-second timeout, DNS-resolved IPs validated as public before fetch. |

## Reporting a vulnerability

If you find a security issue, please **do not** open a public GitHub issue. Email the NFH Trust Labs security contact (listed in the repository's `SECURITY.md`, or in the project README), or open a private security advisory through GitHub's vulnerability disclosure flow.

## Related documentation

* [Concepts: Trust chains](../concepts/trust-chains.md)
* [Concepts: DIDs](../concepts/dids.md) — `did:web` SSRF protection
* [Concepts: Revocation](../concepts/revocation.md)
* [Docker observability](../docker/observability.md) — what is and is not logged
