# Deploying the OpenCred Docker Image

This guide covers how to run the OpenCred Docker image in production. The image is built from `apps/server/Dockerfile` and ships as a single Hono HTTP service.

## Prerequisites

* Docker 24+ or a compatible OCI runtime
* (Optional) Docker Compose v2 if you want to use the bundled `docker-compose.yml`
* A signing key (see [Key sources](#key-sources) below)

## Pull the prebuilt image (recommended)

Tagged releases are published to **GitHub Container Registry** as a public image — no authentication required:

```bash
# Latest stable
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest

# Or pin to a specific version
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:1.2.0
```

Each version tag is built by CI from a signed git tag and scanned with Trivy (CRITICAL/HIGH vulnerabilities fail the build). Image labels include `org.opencontainers.image.source`, `revision`, and `version` for provenance.

### Architecture support

From **v1.2.0** the image is published as a **multi-arch manifest** covering `linux/amd64` and `linux/arm64`. Docker pulls the variant matching your host CPU automatically — no `--platform` flag needed on Apple Silicon Macs, AWS Graviton, Ampere Altra, Raspberry Pi 4/5, or amd64 cloud VMs.

`v1.0.x` and `v1.1.x` were `linux/amd64`-only; on arm64 hosts those tags require `--platform linux/amd64` and run via QEMU emulation (functional, ~2× slower).

## Build from source

If you'd rather build the image yourself (e.g. to add custom CA certs or run a forked build), the image is multi-stage and uses pinned base image digests. Build from the repo root:

```bash
docker build -f apps/server/Dockerfile -t opencred:latest .
```

The build:

1. Installs `pnpm` and resolves only the server's workspace dependencies (`--frozen-lockfile --filter @opencred/server...`).
2. Builds all required `@opencred/*` workspace packages plus `@opencred/server`.
3. Re-installs with `--prod` to strip dev dependencies.
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
  --security-opt no-new-privileges:true \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

> **Tip:** Pin a specific version (e.g. `:1.2.0`) in production. `:latest` floats and can change underneath you on the next release.

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
* A health check that polls `/v1/health` every 30s

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
| `OPENCRED_PORT` | integer (1-65535) | `3100` | HTTP listen port |
| `OPENCRED_API_KEY` | string | — | **REQUIRED** unless `OPENCRED_DEV_MODE_NO_AUTH=true`. Bearer token for API auth. The server refuses to start without it (fail-closed). |
| `OPENCRED_DEV_MODE_NO_AUTH` | boolean | `false` | Opt-out of API-key auth for local development only. Mutually exclusive with `OPENCRED_API_KEY`. The server refuses to start with this set when `NODE_ENV=production`. |
| `OPENCRED_LOG_LEVEL` | enum | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace` |

### Signing key (file-based)

Used when `OPENCRED_KMS_PROVIDER` is `none` (the default).

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_KEY_PATH` | path | — | Absolute path to a PEM, JWK, PKCS#8 DER, or PFX file |
| `OPENCRED_KEY_PASSWORD` | string | — | Password for PFX-encrypted files |
| `OPENCRED_KEY_LABEL` | string | `server-key` | Human-readable label |

### Cloud HSM

Mutually exclusive with file-based signing. Set `OPENCRED_KMS_PROVIDER` and the matching provider variables.

| Variable | Type | Required when | Description |
|---|---|---|---|
| `OPENCRED_KMS_PROVIDER` | enum | always | `aws`, `azure`, `gcp`, or `none` |
| `OPENCRED_KMS_KEY_ARN` | string | provider = `aws` | AWS KMS key ARN |
| `OPENCRED_AZURE_KEY_VAULT_URL` | URL | provider = `azure` | Azure Key Vault base URL |
| `OPENCRED_AZURE_KEY_NAME` | string | provider = `azure` | Key name in the vault |
| `OPENCRED_GCP_KMS_KEY_NAME` | string | provider = `gcp` | Resource name including version (`projects/.../cryptoKeyVersions/N`) |

See the [Cloud HSM guide](cloud-hsm.md) for IAM/auth requirements per provider.

### Batch and session

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_BATCH_ROW_LIMIT` | integer | `1000` | Max rows per batch CSV |
| `OPENCRED_SESSION_TTL` | integer (seconds, min 60) | `14400` | Ephemeral credential data TTL (4 hours) |

The session TTL governs how long batch results and packaged outputs survive in memory before being purged. The default is 4 hours, which matches [security invariant 3](../security/invariants.md#3-session-data-is-ephemeral).

### Trust store

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_CSCA_TRUST_STORE_PATH` | path | — | Directory of PEM-encoded CSCA root certificates for X.509 chain validation. Required for verifying DSC-backed credentials. Mount read-only. |

### Schema updates

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_SCHEMA_UPDATE_URL` | URL | — | HTTPS URL of the schema update manifest. If unset, schema updates are disabled. |
| `OPENCRED_SCHEMA_CACHE_DIR` | path | — | Local directory for caching updated schemas between restarts. |

### Job store (batch jobs)

OpenCred batch jobs (`POST /credentials/batch`) live in a pluggable backing store. The default — `memory` — is an in-process Map and matches the behaviour of every release prior to v1.5.x. For horizontal scale (multiple replicas behind a load balancer), set `OPENCRED_JOB_STORE=redis`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_JOB_STORE` | enum | `memory` | `memory` for single-instance, `redis` for horizontal scale. |
| `OPENCRED_REDIS_URL` | URL | — | **REQUIRED** when `OPENCRED_JOB_STORE=redis`. Accepts `redis://` or `rediss://` (TLS). May embed credentials inline. The full URL is never logged — only the redacted `host:port` descriptor. |
| `OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED` | boolean | `true` | Whether to verify the Redis server's TLS certificate when using `rediss://`. Operators must explicitly set `false` to disable verification — there is no silent fall-through. |

See [Horizontal scale](#horizontal-scale) below for when and how to flip between these modes.

### DeDi integration (optional)

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_DEDI_BASE_URL` | URL | — | Base URL for the DeDi instance. When unset, DeDi is disabled. |
| `OPENCRED_DEDI_AUTH_TYPE` | enum | — | `api-key` or `bearer`. Required when `OPENCRED_DEDI_BASE_URL` is set. |
| `OPENCRED_DEDI_API_KEY` | string | — | DeDi API key (required when auth type is `api-key`). |
| `OPENCRED_DEDI_EMAIL` | email | — | DeDi bearer email (required when auth type is `bearer`). |
| `OPENCRED_DEDI_PASSWORD` | string | — | DeDi bearer password (required when auth type is `bearer`). |
| `OPENCRED_DEDI_NAMESPACE` | string | — | Default DeDi namespace. Required when `OPENCRED_DEDI_BASE_URL` is set. |
| `OPENCRED_DEDI_TIMEOUT_MS` | integer (ms) | `10000` | DeDi request timeout. Range: 1000-30000. |

## Key sources

| Key source | Configure with | Notes |
|---|---|---|
| Software key file | `OPENCRED_KEY_PATH`, optional `OPENCRED_KEY_PASSWORD` | Mount the file read-only at runtime; never bake it into the image |
| AWS KMS | `OPENCRED_KMS_PROVIDER=aws` + `OPENCRED_KMS_KEY_ARN` | Uses AWS SDK default credential chain |
| Azure Key Vault | `OPENCRED_KMS_PROVIDER=azure` + URL/name | Uses `DefaultAzureCredential` |
| GCP Cloud KMS | `OPENCRED_KMS_PROVIDER=gcp` + key name | Uses Application Default Credentials |

The OS certificate store (Windows CNG / macOS Keychain) is **not** available in the Docker image — those backends are Desktop-only.

## Horizontal scale

OpenCred is designed so a single instance handles the typical issuance load comfortably. If your traffic outgrows a single replica — or you want a redundant pair behind a load balancer — flip the batch job store from in-process memory to a shared Redis:

```bash
docker run -d \
  --name opencred \
  -p 3100:3100 \
  -e OPENCRED_API_KEY=sk_prod_change_me \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -e OPENCRED_JOB_STORE=redis \
  -e OPENCRED_REDIS_URL=rediss://default:password@redis.prod:6380/0 \
  -v /host/path/issuer-key.pem:/secrets/issuer-key.pem:ro \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

### What "stateless" buys you

* **Visibility:** Every replica can answer `GET /credentials/batch/:jobId` regardless of which replica accepted the original POST. Job records — status, progress, completion timestamps — are read from the shared Redis.
* **Bounded memory:** Redis TTL (`SET ... EX`) evicts records automatically when they exceed `OPENCRED_SESSION_TTL`. The previously observed RSS climb under sustained small-batch load (#446) is structurally fixed: an unbounded in-process Map no longer exists.
* **Restart safety:** Records survive a single replica's restart. A reader hitting a different replica still sees the job.

### What it does NOT do (and why)

* **Cross-replica work stealing.** The actual signing for a batch is pinned to the replica that received the POST. If that replica dies mid-batch, the job is marked `interrupted` in Redis on graceful shutdown; otherwise the entry expires via TTL. There is no automatic re-issuance — clients should re-submit interrupted batches.
* **A queue.** OpenCred does not implement BullMQ, SQS, or any durable work queue. That's a separate roadmap item (Tier 3 in #446) and would change the API contract.

### When to keep `memory`

Single-instance deployments — including every desktop client deployment of this repo — should stick with `memory`. There is no operational benefit to adding Redis if you only run one replica.

### Operating the Redis

* Use a managed Redis (AWS ElastiCache, Memorystore, Upstash, etc.) rather than co-locating. The Redis is on the credential-issuance hot path; a flaky Redis becomes a flaky issuance API.
* Cap memory with `maxmemory` + an `allkeys-lru` or `allkeys-lfu` policy. OpenCred's TTL handles its own keys, but a hard cap is the right belt-and-suspenders.
* Use TLS (`rediss://`) when the Redis is not in the same VPC. Keep `OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED=true` (the default) unless you have a specific reason to relax it.
* Rotate the Redis password by rotating `OPENCRED_REDIS_URL` and rolling the replicas — there is no in-process rotation hook.

### Sizing

For workloads up to ~1000 active jobs simultaneously, a `cache.t4g.micro`-class instance is sufficient. Storage per job is on the order of 10–50 KB depending on row count and proof format.

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
  test: ["CMD", "wget", "-qO-", "http://localhost:3100/v1/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

The health endpoint returns `200` when the signing key is loaded and `503` when it is not. See [Observability → Health Checks](observability.md#health-checks).

For Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /v1/health
    port: 3100
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /v1/health
    port: 3100
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Graceful shutdown

`apps/server/src/index.ts` registers `SIGTERM` and `SIGINT` handlers that stop accepting new connections and wait for existing ones to close. Send `SIGTERM` (the default for `docker stop`) to initiate shutdown.

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
| `/v1/health` returns `503` with `signingKeyLoaded: false` | Key file not set, unreadable, or Cloud HSM misconfigured | Verify the file is mounted and readable by the `node` user, or check Cloud HSM credentials |
| 401 on every request | `OPENCRED_API_KEY` is set but the request lacks `Authorization: Bearer <token>` | Add the header or unset the env var (only in dev) |
| `Failed to fetch DID document` during verification | did:web target unreachable or resolves to a private IP | See [SSRF protection](../security/invariants.md#7-didweb-resolution-requires-ssrf-protection) |
