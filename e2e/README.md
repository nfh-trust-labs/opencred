# @opencred/e2e-matrix

Credential-matrix E2E harness. Proves every valid `{algorithm × proof format}` cell issues and verifies against the **real Docker image**, through both verifiers (the public `@opencred/verify` SDK and the server's `/v1/credentials/verify`), with tamper rejection, PDF/JSON export round-trips, the documented exclusions, and — when a staging namespace is configured — the full DeDi key lifecycle (publish → issue → verify → rotate → revoke credential → revoke key).

Not part of the unit-test run (`vitest.workspace.ts` deliberately excludes it). CI runs it as a release gate — on every `v*` tag, plus on demand via `workflow_dispatch` — through `.github/workflows/e2e-matrix.yml`. A red run means the release must not be announced (and `:latest` not advanced) until fixed.

## Running locally

```bash
# 1. Build the workspace (the SDK is consumed from its dist) and the image
pnpm build
docker build -f apps/server/Dockerfile -t opencred-server:e2e .

# 2. Offline cells (matrix + exports + exclusions)
OPENCRED_E2E_IMAGE=opencred-server:e2e pnpm --filter @opencred/e2e-matrix e2e

# 3. + DeDi lifecycle cells (optional — requires a staging namespace)
OPENCRED_E2E_IMAGE=opencred-server:e2e \
OPENCRED_E2E_DEDI_BASE_URL=https://your-dedi-staging.example.org \
OPENCRED_E2E_DEDI_NAMESPACE=your-verified-namespace \
OPENCRED_E2E_DEDI_API_KEY=... \
pnpm --filter @opencred/e2e-matrix e2e
```

Suites skip loudly (console warning) when their env is missing — a skipped cell never silently reads as covered.

## The matrix

| Algorithm | vc-jwt | data-integrity | sd-jwt-vc |
|---|---|---|---|
| P-256 | ✅ | ✅ | ✅ |
| P-384 | ✅ | ✅ | ✅ |
| Ed25519 | ✅ | ✅ | ✅ |
| RSA-2048 | ✅ (PS256) | ❌ excluded by design (suite restriction) | ✅ (PS256) |

Each cell: issue → SDK verify VALID → server verify VALID → tampered copy INVALID. Per-algorithm: expired-credential cell (EXPIRED). Once per run: PDF + JSON export round-trips, RSA×DI rejection, DeDi lifecycle (env-gated).

## Why no local mock DeDi

The dedi-client's SSRF guard refuses private/loopback IPs **by design** (security invariant). DeDi cells therefore run against a real staging namespace; everything else runs fully offline.
