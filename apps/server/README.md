# @opencred/server

Headless OpenCred — the Docker image. A Hono-based HTTP server wrapping
the same `@opencred/crypto`, `@opencred/vc-core`, `@opencred/schema-engine`,
`@opencred/signing`, and `@opencred/verification` packages that the
Electron desktop client uses. Issuers running cloud infrastructure
deploy this container instead of (or alongside) the desktop app.

This README is the contributor view — what's in this package and how to
work on it locally. **Operator documentation lives in
[`docs/docker/`](../../docs/docker/README.md)**: env-var tables, the
full API reference, the CLI, observability, Cloud HSM, deployment
patterns. Don't duplicate it here.

## Security invariants

Enforced by code, not convention:

1. **The HTTP API never accepts a private key.** The signer is loaded
   once at startup from `OPENCRED_KEY_PATH` (or a Cloud HSM provider).
   `rejectKeyMaterial()` in `src/routes/credentials.ts` rejects any
   request body containing a `privateKey` field or a PEM private-key
   block with `400 VALIDATION_ERROR`.
2. **Authentication is required by default.** The server refuses to
   start if `OPENCRED_API_KEY` is unset. The only escape hatch is
   `OPENCRED_DEV_MODE_NO_AUTH=true`, which logs a loud warning and is
   refused when `NODE_ENV=production`.
3. **Key material is never logged.** Pino emits only key id,
   fingerprint, algorithm, and source.
4. **JSON-LD contexts are bundled.** `@opencred/vc-core`'s document
   loader serves contexts from in-memory JSON — no runtime network
   fetches.
5. **Errors are sanitized.** All thrown errors flow through the
   `OpenCredError` hierarchy in `@opencred/shared`.
6. **No server-side session.** Issue / verify are pure request /
   response. Batch jobs live in a pluggable backing store (in-memory
   or Redis) with bounded TTL.

## Operational surfaces

Where to read about each one:

| Feature | Docs |
|---|---|
| HTTP endpoints | [docs/docker/api-reference.md](../../docs/docker/api-reference.md) |
| `opencred` CLI (issue, verify, hash, batch, config validate, identity show) | [docs/docker/cli-reference.md](../../docs/docker/cli-reference.md) |
| Env-var reference (every `OPENCRED_*`) | [docs/docker/api-reference.md#environment-variables](../../docs/docker/api-reference.md#environment-variables) |
| Cloud HSM (AWS KMS / Azure Key Vault / GCP Cloud KMS) | [docs/docker/cloud-hsm.md](../../docs/docker/cloud-hsm.md) |
| Horizontal scale (Redis job store, multi-replica) | [docs/docker/deployment.md#horizontal-scale](../../docs/docker/deployment.md#horizontal-scale) |
| Queue dispatch (BullMQ worker fleet, webhooks) | [docs/docker/deployment.md#queue-dispatch-worker-fleet--opencred_batch_dispatchqueue](../../docs/docker/deployment.md#queue-dispatch-worker-fleet--opencred_batch_dispatchqueue) |
| Read-only verify tier | [docs/docker/deployment.md#read-tier-deployment](../../docs/docker/deployment.md#read-tier-deployment) |
| OTel critical-path spans | [docs/docker/observability.md#tracing](../../docs/docker/observability.md#tracing) |
| Rate limits | [docs/docker/api-reference.md#rate-limits](../../docs/docker/api-reference.md#rate-limits) |
| DeDi per-key registry (`opencred-key-registry`): publish / rotate / revoke / resolve | [docs/docker/api-reference.md — Per-key registry endpoints](../../docs/docker/api-reference.md#per-key-registry-opencred-key-registry-endpoints), [docs/docker/deployment.md — Key lifecycle](../../docs/docker/deployment.md#key-lifecycle--publish-rotate-revoke) |
| DeDi integration (revocation, did:web fallback) | [docs/concepts/dids.md](../../docs/concepts/dids.md), [docs/concepts/revocation.md](../../docs/concepts/revocation.md) |

## Package layout

```
apps/server/
├── Dockerfile           # multi-stage build (builder + alpine runtime)
├── package.json
├── README.md            # this file
├── tsconfig.json
├── vitest.config.ts
└── src/
    ├── index.ts             # entrypoint — wires config, logger, signer, routes, middleware, tracing
    ├── worker.ts            # BullMQ worker process (started when OPENCRED_BATCH_DISPATCH=queue)
    ├── config.ts            # Zod-validated env var schema; enforces auth fail-closed
    ├── logger.ts            # pino logger (key material never logged)
    ├── tracing.ts           # OTel NodeTracerProvider setup (no-op when OPENCRED_OTEL_ENABLED=false)
    ├── cli.ts               # operator CLI (commander)
    ├── middleware/
    │   ├── auth.ts              # Bearer token auth (constant-time compare)
    │   ├── rate-limit.ts        # per-route rate limiter
    │   ├── body-limit.ts        # OPENCRED_MAX_BODY_BYTES / OPENCRED_MAX_BATCH_BODY_BYTES
    │   ├── read-only.ts         # OPENCRED_READ_ONLY=true denylist
    │   ├── cache-control.ts     # response cache headers
    │   ├── tracing.ts           # request-span middleware
    │   └── error-handler.ts     # OpenCredError → JSON response
    ├── observability/
    │   ├── signer-span.ts       # wrapSignerWithTracing
    │   ├── verify-span.ts       # verify.* span helpers
    │   ├── dedi-span.ts         # dedi.* span helpers
    │   └── span-helpers.ts
    ├── routes/
    │   ├── health.ts            # GET /health, GET /v1/health (public)
    │   ├── keys.ts              # GET /v1/keys, GET /v1/keys/did-document, POST /v1/keys/publish, POST /v1/keys/rotate, POST /v1/keys/revoke, POST /v1/keys/resolve
    │   ├── credentials.ts       # POST /v1/credentials/issue, /verify (incl. PDF), /package, /revoke, /revocation-status
    │   ├── schemas.ts           # GET /v1/schemas, POST /v1/schemas/generate
    │   ├── batch.ts             # POST /v1/credentials/batch + GET /:jobId(/results) + cancel
    │   ├── revocation.ts        # POST /v1/credentials/revocation-hash(/batch)
    │   ├── dedi.ts              # POST /v1/dedi/namespace/ensure
    │   └── packaging.ts         # PDF / QR / JSON packaging
    ├── signing/
    │   ├── key-manager.ts       # software key loader
    │   └── cloud-hsm/           # AWS / Azure / GCP factories
    ├── batch/
    │   ├── batch-engine.ts      # streaming engine
    │   ├── csv-parser.ts        # delegates to @opencred/batch-core
    │   ├── queue.ts             # BullMQ queue dispatch
    │   ├── webhook-queue.ts     # webhook delivery queue
    │   └── job-store/           # memory + redis implementations + factory
    ├── packaging/               # PDF/QR generators
    └── __tests__/               # vitest suites — boot the server in-memory and exercise every endpoint
```

## Running locally

From the repo root:

```sh
pnpm install
pnpm --filter @opencred/server... build

# Throwaway dev key and API token
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/dev-key.pem
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

OPENCRED_KEY_PATH=/tmp/dev-key.pem \
  OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  pnpm --filter @opencred/server dev
```

For the truly throwaway case (loud warning banner appears):

```sh
OPENCRED_KEY_PATH=/tmp/dev-key.pem \
  OPENCRED_DEV_MODE_NO_AUTH=true \
  pnpm --filter @opencred/server dev
```

## Running tests

```sh
pnpm --filter @opencred/server test
```

## Building the Docker image

```sh
# Build context must be the repo root, not apps/server/
docker build -f apps/server/Dockerfile -t opencred/server:dev .
```

The container's `HEALTHCHECK` probes `/v1/health` (public) every 30
seconds. The container runs as the non-root `node` user. See
[docs/docker/deployment.md](../../docs/docker/deployment.md) for the
production `docker run` / `docker compose` recipes.
