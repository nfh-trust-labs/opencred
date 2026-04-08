# Deploying the OpenCred Docker Image

This guide covers how to run the OpenCred Docker image in production. The image is built from `apps/server/Dockerfile` and ships as a single Hono HTTP service plus the `opencred` CLI.

## Prerequisites

* Docker 24+ or a compatible OCI runtime
* (Optional) Docker Compose v2 if you want to use the bundled `docker-compose.yml`
* A signing key (see [Key sources](#key-sources) below)

## Build

The image is multi-stage and uses pinned base image digests. Build from the repo root:

```bash
docker build -f apps/server/Dockerfile -t opencred:latest .
```

The build:

1. Installs `pnpm` and resolves the workspace from `pnpm-lock.yaml` (`--frozen-lockfile`).
2. Builds all required `@opencred/*` workspace packages plus `@opencred/server`.
3. Prunes dev dependencies (`pnpm prune --prod`).
4. Copies only the production output into a `node:20-alpine` runtime stage.
5. Configures the container to run as the non-root `node` user.

The resulting image exposes port `3100` and starts via `node apps/server/dist/index.js`.

## Run

### `docker run`

```bash
docker run -d \
  --name opencred \
  -p 3100:3100 \
  -e OPENCRED_PORT=3100 \
  -e OPENCRED_API_KEY=sk_prod_change_me \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -e OPENCRED_LOG_LEVEL=info \
  -v /host/path/issuer-key.pem:/secrets/issuer-key.pem:ro \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=64m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  opencred:latest
```

### Docker Compose

The repository ships a hardened `docker-compose.yml` with all of the above already set:

```bash
docker compose up -d            # start
docker compose logs -f server   # follow logs
docker compose down             # stop
```

The compose file enables:

* `read_only: true` filesystem with a tmpfs for `/tmp`
* All capabilities dropped except `NET_BIND_SERVICE`
* `no-new-privileges: true`
* A health check that polls `/health` every 30s

Mount your signing key by editing the `volumes:` block in `docker-compose.yml`:

```yaml
volumes:
  - ./keys/issuer-key.pem:/app/keys/issuer-key.pem:ro
```

and set `OPENCRED_KEY_PATH=/app/keys/issuer-key.pem` in your `.env` file.

## Environment variables

Configuration is parsed by Zod at startup (`apps/server/src/config.ts`). Invalid values cause an immediate exit with a descriptive error.

### Core

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_PORT` | integer (1–65535) | `3100` | HTTP listen port |
| `OPENCRED_API_KEY` | string | — | **REQUIRED** unless `OPENCRED_DEV_MODE_NO_AUTH=true`. Bearer token for API auth. The server refuses to start without it (fail-closed). |
| `OPENCRED_DEV_MODE_NO_AUTH` | boolean | `false` | Opt-out of API-key auth for local development only. Mutually exclusive with `OPENCRED_API_KEY`. The server refuses to start with this set when `NODE_ENV=production`. |
| `OPENCRED_LOG_LEVEL` | enum | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace` |

### Signing key (file-based)

Used when `OPENCRED_KMS_PROVIDER` is `none` (the default).

| Variable | Type | Description |
|---|---|---|
| `OPENCRED_KEY_PATH` | path | Absolute path to a PEM, JWK, PKCS#8 DER, or PFX file |
| `OPENCRED_KEY_PASSWORD` | string | Password for PFX-encrypted files |
| `OPENCRED_KEY_LABEL` | string | Human-readable label, defaults to `server-key` |

### Cloud HSM

Mutually exclusive with file-based signing. Set `OPENCRED_KMS_PROVIDER` and the matching provider variables.

| Variable | Type | Required when | Description |
|---|---|---|---|
| `OPENCRED_KMS_PROVIDER` | enum | always | `aws`, `azure`, `gcp`, or `none` |
| `OPENCRED_KMS_KEY_ARN` | string | provider = `aws` | AWS KMS key ARN |
| `OPENCRED_AZURE_KEY_VAULT_URL` | URL | provider = `azure` | Azure Key Vault base URL |
| `OPENCRED_AZURE_KEY_NAME` | string | provider = `azure` | Key name in the vault |
| `OPENCRED_GCP_KMS_KEY_NAME` | string | provider = `gcp` | Resource name including version (`projects/.../cryptoKeyVersions/N`) |

See the legacy [Cloud HSM guide](../self-hosted/cloud-hsm.md) for IAM/auth requirements per provider.

### Batch and session

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_BATCH_ROW_LIMIT` | integer | `1000` | Max rows per batch CSV |
| `OPENCRED_SESSION_TTL` | integer (seconds, min 60) | `14400` | Ephemeral credential data TTL (4 hours) |

The session TTL governs how long batch results and packaged outputs survive in memory before being purged. The default is 4 hours, which matches [security invariant 3](../security/invariants.md#3-session-data-is-ephemeral).

## Key sources

| Key source | Configure with | Notes |
|---|---|---|
| Software key file | `OPENCRED_KEY_PATH`, optional `OPENCRED_KEY_PASSWORD` | Mount the file read-only at runtime; never bake it into the image |
| Hardware token (PKCS#11) | Mount the PKCS#11 library and configure via env (paths planned for #301) | Same `pkcs11js` bindings as the Desktop Client |
| AWS KMS | `OPENCRED_KMS_PROVIDER=aws` + `OPENCRED_KMS_KEY_ARN` | Uses AWS SDK default credential chain |
| Azure Key Vault | `OPENCRED_KMS_PROVIDER=azure` + URL/name | Uses `DefaultAzureCredential` |
| GCP Cloud KMS | `OPENCRED_KMS_PROVIDER=gcp` + key name | Uses Application Default Credentials |

The OS certificate store (Windows CNG / macOS Keychain) is **not** available in the Docker image — those backends are Desktop-only.

## Persistent state

The Docker image is **stateless by design**. The only mutable state is in-process and ephemeral (session payloads, batch results) and is purged within `OPENCRED_SESSION_TTL`. Restarting the container loses nothing of value.

If you need persistence beyond the session TTL — for example, to retain a long-running batch job's results across restarts — capture the response payloads in your client and store them yourself. OpenCred deliberately does not act as a database for credential payloads.

The only directories you might want to persist:

| Path | Why |
|---|---|
| `/secrets/` (mount target) | The signing key file. Store securely on the host. |
| `/app/trust-store/` | CSCA trust store PEMs for X.509 chain validation, mounted read-only |

Both are mounts, not volumes you need to back up.

## Health checks

The compose file includes a built-in health check:

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:3100/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

For Kubernetes, use the canonical probe block defined in [Observability → Probe configuration](observability.md#probe-configuration):

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3100
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 3100
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Graceful shutdown

`apps/server/src/index.ts` registers `SIGTERM` and `SIGINT` handlers that close the HTTP server cleanly. Send `SIGTERM` (the default for `docker stop`) and the process drains in-flight requests before exiting.

## Reverse proxy

For production deployments behind TLS, terminate TLS at a reverse proxy (nginx, Caddy, an L7 load balancer) and forward to the OpenCred container. The container ships HTTP-only on purpose so that TLS is managed by infrastructure that already handles certificate rotation.

The `docker-compose.yml` includes a commented-out nginx service block as a starting point.

## Production checklist

| Check | Why |
|---|---|
| `OPENCRED_API_KEY` is set and rotated periodically | Prevents anyone on the network from issuing credentials |
| Signing key file has 0600 permissions on the host | Even though it's mounted read-only, the host filesystem must protect it |
| Container runs as non-root | Built into the image; verify with `docker exec opencred id` |
| TLS terminated upstream (nginx/Caddy/ELB/ALB) | The container does not handle TLS itself |
| Health endpoint reachable from your orchestrator | Required for self-healing and rolling updates |
| Logs ingested by your log aggregator | pino writes JSON to stdout — see [Observability](observability.md) |
| Image tag is a SHA, not `latest` | Reproducible deployments; pin to a known-good build |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits immediately with config errors | Missing required env var, invalid value | Check the error output — Zod prints the offending field |
| `/health` returns `signingKeyLoaded: false` | `OPENCRED_KEY_PATH` not set or file unreadable | Verify the file is mounted and readable by the `node` user |
| 401 on every request | `OPENCRED_API_KEY` is set but the request lacks `Authorization: Bearer <token>` | Add the header or unset the env var (only in dev) |
| `Failed to fetch DID document` during verification | did:web target unreachable or resolves to a private IP | See [SSRF protection](../security/invariants.md#7-didweb-resolution-requires-ssrf-protection) |
