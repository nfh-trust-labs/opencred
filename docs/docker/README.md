# OpenCred Docker Image

The OpenCred Docker image is the headless variant of the Desktop Client. It exposes an HTTP API for issuing and verifying W3C Verifiable Credentials and is intended for cloud deployments, on-prem servers, automation pipelines, and CI/CD integration.

## Important: OpenCred is not a hosted service

OpenCred is **not** a SaaS. There is no `api.opencred.com` to call. You deploy the Docker image into **your** infrastructure, you manage the signing key, and the credentials are produced inside your environment. NFH Trust Labs operates no hosted endpoints and never receives your credential data or your keys.

## Pages in this section

* [Deployment](deployment.md) — `docker run`, `docker compose`, environment variables, volumes, persistent state
* [API reference](api-reference.md) — HTTP endpoints exposed by your deployment
* [CLI reference](cli-reference.md) — `opencred` command-line tool for offline operations
* [Cloud HSM](cloud-hsm.md) — AWS KMS, Azure Key Vault, GCP Cloud KMS setup
* [Observability](observability.md) — logging, metrics, health checks, structured output
* [OID4VCI](oid4vci.md) — OpenID for Verifiable Credential Issuance (planned)

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
curl http://localhost:3100/v1/health
```

A successful health check returns `200 OK`:

```json
{
  "status": "ok",
  "ready": true,
  "signingKeyLoaded": true,
  "dediConfigured": false,
  "timestamp": "2026-04-07T10:00:00.000Z"
}
```

If `signingKeyLoaded` is `false`, the server returns `503` and cannot issue credentials — see the [Deployment guide](deployment.md) for the supported key sources.

## Providing a signing key

Your signing key stays in your infrastructure — it is loaded at startup and never transmitted.

**File-based** (default): Set `OPENCRED_KEY_PATH` to a PEM, JWK, PKCS#8, or PFX file. For PFX, also set `OPENCRED_KEY_PASSWORD`.

**Cloud HSM**: Set `OPENCRED_KMS_PROVIDER` to `aws`, `azure`, or `gcp` with the provider-specific variables. See [Cloud HSM](cloud-hsm.md).

## Local development

```bash
# From the repo root
pnpm install
pnpm build

# Set environment variables
export OPENCRED_PORT=3100
export OPENCRED_KEY_PATH=/path/to/your/key.pem
export OPENCRED_DEV_MODE_NO_AUTH=true  # local dev only; never use in production

# Start the dev server
cd apps/server
pnpm dev
```

## Architecture

The Docker image is built from `apps/server/Dockerfile` and runs `apps/server/dist/index.js`:

| Component | Path | Responsibility |
|---|---|---|
| HTTP server | `apps/server/src/index.ts` | Hono app, route registration, error handler |
| Configuration | `apps/server/src/config.ts` | Zod-validated environment variables |
| Logger | `apps/server/src/logger.ts` | pino structured logging to stdout |
| Auth middleware | `apps/server/src/middleware/auth.ts` | Required Bearer token check (fail-closed per [#317](https://github.com/nfh-trust-labs/opencred/issues/317); see [API reference → Authentication](api-reference.md#authentication)) |
| Routes | `apps/server/src/routes/*.ts` | `/health`, `/keys`, `/schemas`, `/credentials/issue`, `/credentials/verify`, `/credentials/batch`, `/credentials/revocation-hash`, `/credentials/revoke`, `/credentials/revocation-status`, `/credentials/package`, `/metrics` |
| Signer | `apps/server/src/signing/key-manager.ts` | Loads the active signer from a file or Cloud HSM |
| CLI | `apps/server/src/cli.ts` | `opencred` command for one-off operations |

The server consumes the same `@opencred/*` packages used by the Desktop Client, so issuance and verification logic are shared.

## Security defaults

The Docker image is built and configured with security defaults that follow the [seven OpenCred invariants](../security/invariants.md):

* Runs as the non-root `node` user
* Multi-stage build with pinned base image digests for reproducibility
* No secrets baked into image layers — keys and tokens are mounted at runtime
* `docker-compose.yml` enables `read_only: true`, drops all capabilities, adds only `NET_BIND_SERVICE`, and sets `no-new-privileges: true`
* JSON-LD contexts are bundled at build time and never fetched at runtime
* The pino logger writes to stdout in JSON; key material is never logged

See [Security](../security/README.md) for the full model.

## Related documentation

* [Deployment](deployment.md)
* [API reference](api-reference.md)
* [CLI reference](cli-reference.md)
* [Cloud HSM](cloud-hsm.md)
* [Observability](observability.md)
* [Security model](../security/README.md)
* [Concepts: Verifiable Credentials](../concepts/verifiable-credentials.md)
