# Docker API Reference

> **Status: Coming with Phase 6 (#301).** The OpenCred Docker server endpoints are being finalised in parallel under [issue #301 — final sprint: build and test Docker container (Phase 6 + 7)](https://github.com/nfh-trust-labs/opencred/issues/301). The endpoints listed below are stable enough to call today, but the canonical, fully-versioned reference will land alongside that issue.
>
> **For the current endpoint contract**, see the legacy reference at [`docs/self-hosted/api-reference.md`](../self-hosted/api-reference.md). The legacy doc is kept up to date with `apps/server/src/routes/*.ts` and is the source of truth until #301 is merged.

## What this page will contain

When #301 lands, this page will be the canonical, version-stamped HTTP API reference for the OpenCred Docker image. It will include:

- [ ] Authentication model and Bearer token configuration
- [ ] Standard error format (`OpenCredError` JSON shape)
- [ ] Per-endpoint sections, in route file order:
  - `GET /health`
  - `GET /schemas`
  - `GET /schemas/:id`
  - `POST /credentials/issue`
  - `POST /credentials/verify`
  - `POST /credentials/batch`
  - `GET /credentials/batch/:jobId`
  - `GET /credentials/batch/:jobId/results`
  - `POST /credentials/revocation-hash`
  - `POST /credentials/revocation-hash/batch`
  - `POST /credentials/package`
  - any new endpoints added under #301
- [ ] Request and response schemas with field-by-field tables
- [ ] Status codes, including `409` for in-progress batch jobs and `410` for expired sessions
- [ ] curl examples for every endpoint
- [ ] At least one SDK snippet — likely TypeScript using the same `@opencred/*` packages used internally
- [ ] Notes on proof formats supported per endpoint, RSA limitations on `data-integrity`, and SD-JWT VC compact-token responses
- [ ] Notes on rate limiting, payload size limits, and batch row caps (controlled by `OPENCRED_BATCH_ROW_LIMIT`)

## Why a stub

This documentation pass (#304) is running in parallel with the Docker server work (#301). Writing endpoint docs from a moving target would create duplicate work and likely drift from the real implementation. The structural placeholder lets us land the rest of the documentation now while #301 finalises the endpoint surface.

When #301 merges:

1. The implementer of #301 — or the documentation author closing #304 — will copy the validated endpoint contract from `apps/server/src/routes/*.ts` into this page.
2. The legacy `docs/self-hosted/api-reference.md` will be cross-linked and (eventually) deprecated.
3. This stub will be removed.

## Quick reference (current legacy contract)

For now, the most useful starting points are:

| You want to... | See |
|---|---|
| Issue a credential via HTTP | [`self-hosted/api-reference.md → POST /credentials/issue`](../self-hosted/api-reference.md#post-credentialsissue) |
| Verify a credential via HTTP | [`self-hosted/api-reference.md → POST /credentials/verify`](../self-hosted/api-reference.md#post-credentialsverify) |
| Submit a CSV batch | [`self-hosted/api-reference.md → POST /credentials/batch`](../self-hosted/api-reference.md#post-credentialsbatch) |
| Compute a revocation hash | [`self-hosted/api-reference.md → POST /credentials/revocation-hash`](../self-hosted/api-reference.md#post-credentialsrevocation-hash) |
| Package a credential into PDF/QR | [`self-hosted/api-reference.md → POST /credentials/package`](../self-hosted/api-reference.md#post-credentialspackage) |
| Configure environment variables | [Deployment](deployment.md#environment-variables) |
| Use the CLI instead | [`self-hosted/cli-reference.md`](../self-hosted/cli-reference.md) |

## Related

* [Deployment](deployment.md) — running the image, environment variables, persistence
* [Observability](observability.md) — logging, metrics, health checks
* [Security model](../security/README.md) — what the server protects against
* [Issue #301](https://github.com/nfh-trust-labs/opencred/issues/301) — Phase 6 + 7 Docker server work
* [Issue #304](https://github.com/nfh-trust-labs/opencred/issues/304) — this documentation effort
