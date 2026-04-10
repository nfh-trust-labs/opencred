# OpenCred Docker Operator Guide

The OpenCred Docker image is the headless variant of the Desktop Client. It exposes an HTTP API for issuing and verifying W3C Verifiable Credentials and is intended for cloud deployments, on-prem servers, automation pipelines, and CI/CD integration.

## Important: OpenCred is not a hosted service

OpenCred is **not** a SaaS. There is no `api.opencred.com` to call. You deploy the Docker image into **your** infrastructure, you manage the signing key, and the credentials are produced inside your environment. NFH Trust Labs operates no hosted endpoints and never receives your credential data or your keys.

## Pages in this section

* [Deployment](deployment.md) — `docker run`, `docker compose`, environment variables, volumes, persistent state
* [API reference](api-reference.md) — HTTP endpoints exposed by your deployment (final endpoint set under #301; legacy reference at [`docs/self-hosted/api-reference.md`](../self-hosted/api-reference.md))
* [Observability](observability.md) — logging, metrics, health checks, structured output

## Quick start

```bash
# 1. Build the image (from the repo root)
docker build -f apps/server/Dockerfile -t opencred:latest .

# 2. Run with a mounted signing key
docker run -p 3100:3100 \
  -e OPENCRED_PORT=3100 \
  -e OPENCRED_API_KEY=your-secret-token \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -v /path/to/your/key.pem:/secrets/issuer-key.pem:ro \
  opencred:latest

# 3. Verify it's running
curl http://localhost:3100/health
```

A successful health check returns:

```json
{
  "status": "ok",
  "signingKeyLoaded": true,
  "timestamp": "2026-04-07T10:00:00.000Z"
}
```

If `signingKeyLoaded` is `false`, the server started but no signing key was configured — see the [Deployment guide](deployment.md) for the supported key sources.

## Architecture

The Docker image is built from `apps/server/Dockerfile` and runs `apps/server/dist/index.js`:

| Component | Path | Responsibility |
|---|---|---|
| HTTP server | `apps/server/src/index.ts` | Hono app, route registration, error handler |
| Configuration | `apps/server/src/config.ts` | Zod-validated environment variables |
| Logger | `apps/server/src/logger.ts` | pino structured logging to stdout |
| Auth middleware | `apps/server/src/middleware/auth.ts` | Optional Bearer token check |
| Routes | `apps/server/src/routes/*.ts` | `/health`, `/schemas`, `/credentials/*`, `/credentials/batch/*` |
| Signer | `apps/server/src/signing/key-manager.ts` | Loads the active signer from a file or Cloud HSM |
| CLI | `apps/server/src/cli.ts` | `opencred` command for one-off operations |

The server consumes the same `@opencred/*` packages used by the Desktop Client, so issuance and verification logic are shared.

## Security defaults

The Docker image is built and configured with security defaults that follow the [seven OpenCred invariants](../security/invariants.md):

* Runs as the non-root `node` user
* Multi-stage build with pinned base image digests for reproducibility
* No secrets baked into image layers — keys and tokens are mounted at runtime
* `docker-compose.yml` enables `read_only: true`, drops all capabilities, and adds only `NET_BIND_SERVICE`
* JSON-LD contexts are bundled at build time and never fetched at runtime
* The pino logger writes to stdout in JSON; key material is never logged

See [Security](../security/README.md) for the full model.

## Related documentation

* [Deployment](deployment.md)
* [Observability](observability.md)
* [Security model](../security/README.md)
* [Concepts: Verifiable Credentials](../concepts/verifiable-credentials.md)
* Legacy: [`self-hosted/getting-started.md`](../self-hosted/getting-started.md), [`self-hosted/configuration.md`](../self-hosted/configuration.md), [`self-hosted/api-reference.md`](../self-hosted/api-reference.md)
