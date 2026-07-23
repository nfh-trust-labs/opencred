# Review Criteria — OpenCred

Read by automated review alongside CLAUDE.md. CLAUDE.md says how to write
code here; this file says what to block. Style/formatting is out of scope —
prettier and eslint own it; don't comment on what a linter would catch.

## Blocking — reject the PR

- Any path where issuer private key material is received, stored, logged,
  or serialized by a service. All signing is local — no exceptions.
- `KeyObject` serialized or logged (log key ID/fingerprint only).
- `Math.random()` anywhere security-relevant — CSPRNG only
  (`crypto.randomBytes` or equivalent).
- A did:web / remote fetch not routed through the SSRF guard
  (`isPrivateIP` from `@opencred/shared`, `packages/shared/src/ssrf.ts`:
  HTTPS only, no redirects, 10s timeout).
- JSON-LD context fetched at runtime instead of bundled in
  `vc-core/src/contexts/`.
- Secrets, key material, or internal paths in error responses or logs
  (use the `OpenCredError` hierarchy).
- **Breaking change to any public contract without a versioned migration
  note**: `/v1/*` request/response shapes, env vars and their defaults,
  VC/JWT/PDF output formats, on-disk DID/key formats, DeDi record shapes,
  desktop settings, Docker env/volumes. Credentials issued by version N
  must verify under N+1. Prefer additive evolution.
- A failing test weakened or deleted to get green; a CI check disabled
  or skipped.

## High priority

- New endpoint or logic without failure-path tests.
- New external call without timeout + bounded retries (follow
  `packages/dedi-client` patterns: `circuit-breaker.ts`, `retry.ts`).
- Behavior change without the docs sweep — grep all referencing docs +
  SDK READMEs; see CLAUDE.md "Documentation — MANDATORY". Don't guess.
- Any `react-hooks/*` eslint directive (the plugin is not loaded — these
  directives themselves error).

## Review lenses by area

- `packages/crypto`, `packages/signing`, `apps/server/src/signing` — key
  lifecycle: rotation safety, no key material crossing process or service
  boundaries
- `packages/did` — resolution trust: verification methods checked before
  keys are trusted
- `packages/verification`, `packages/verify-sdk` — verification
  completeness: is revocation status actually checked on every verify path?
- `packages/dedi-client` — record shape (payload at `data.details`),
  revocation via `tag:"revoke"`, 200/409 sync vs 202+background semantics

## Never comment on

- Formatting/style — prettier/eslint territory
- `CHANGELOG.md` contents — release-please owns it (CI guard enforces)
