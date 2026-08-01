# Security Policy

OpenCred is trust infrastructure — we take vulnerability reports seriously
and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Preferred: use GitHub's private vulnerability reporting —
[Security → Report a vulnerability](https://github.com/nfh-trust-labs/opencred-releases/security/advisories/new)
on this repository.

Alternatively, email **dev@nfh-trust-labs.org** with subject line
`[SECURITY] <short summary>`. Include reproduction steps, affected versions,
and impact assessment if you can.

You will get an acknowledgement within **3 business days** and a triage
verdict within **10 business days**. We'll keep you informed through the fix
and credit you in the release notes unless you prefer otherwise.

## Scope

In scope: the desktop app, the Docker server, all `@opencred/*` packages in
this repository, the release pipeline, and the published container images.

Of particular interest — violations of the project's
[security invariants](docs/security/invariants.md):

- any code path that receives, transmits, stores, or logs issuer private
  key material;
- key material or secrets leaking into logs, error responses, or crash
  reports;
- SSRF in `did:web` resolution; JSON-LD remote-context fetching at runtime;
- session/credential data outliving its TTL;
- signature or verification bypasses in any supported proof format.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor release (see [Releases](https://github.com/nfh-trust-labs/opencred-releases/releases)) | ✅ |
| Older releases | ❌ — please upgrade; the desktop app self-updates |
