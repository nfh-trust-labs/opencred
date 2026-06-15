# Docker Deployment Guide

This guide covers deploying the OpenCred Docker image in production. The image is built from `apps/server/Dockerfile` and runs a Hono HTTP server. The Docker image runs in **your** infrastructure -- no data is sent to OpenCred or NFH Trust Labs.

## Prerequisites

- Docker 24+ or a compatible OCI runtime
- Docker Compose v2 (optional, for the bundled compose file)
- A signing key in PEM, JWK, PKCS#8, or PFX format (or a Cloud HSM provider)
- (Optional) A DeDi instance for revocation and directory services

## Pull the prebuilt image (recommended)

```bash
docker pull ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
# or pin to a version tag, e.g. :1.2.0
```

The image is public — no GHCR auth required. Trivy-scanned by CI.

## Build from source

If you'd rather build the image yourself, build from the repo root:

```bash
docker build -f apps/server/Dockerfile -t opencred:latest .
```

The multi-stage build:

1. Installs pnpm and resolves the workspace from `pnpm-lock.yaml` with `--frozen-lockfile`.
2. Builds all required `@opencred/*` workspace packages.
3. Prunes dev dependencies with `pnpm prune --prod`.
4. Copies only production output into a `node:20-alpine` runtime stage.
5. Runs as the non-root `node` user.

The resulting image exposes port 3100 and starts via `node apps/server/dist/index.js`.

## Run

### docker run

```bash
# Generate a strong API key
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

docker run -d \
  --name opencred \
  -p 3100:3100 \
  -e OPENCRED_PORT=3100 \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -e OPENCRED_LOG_LEVEL=info \
  -v /host/path/issuer-key.pem:/secrets/issuer-key.pem:ro \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=64m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

> Use `opencred:latest` instead if you built the image locally.

### Docker Compose

The repository includes a hardened `docker-compose.yml`:

```bash
docker compose up -d            # start
docker compose logs -f server   # follow logs
docker compose down             # stop
```

The compose file enables:

- `read_only: true` filesystem with a tmpfs for `/tmp`
- All capabilities dropped except `NET_BIND_SERVICE`
- `no-new-privileges: true`
- A health check polling `/health` every 30 seconds

Mount your signing key by editing the `volumes:` block:

```yaml
volumes:
  - ./keys/issuer-key.pem:/app/keys/issuer-key.pem:ro
```

And set `OPENCRED_KEY_PATH=/app/keys/issuer-key.pem` in your `.env` file.

## Environment Variables

All configuration is via environment variables, validated at startup with Zod (`apps/server/src/config.ts`). Invalid values cause an immediate exit with a descriptive error. Sensitive values are never logged.

### Core

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_PORT` | integer (1-65535) | `3100` | No | HTTP listen port |
| `OPENCRED_API_KEY` | string | -- | Yes (unless dev mode) | Bearer token for API authentication. Server refuses to start without it (fail-closed). Generate with `openssl rand -base64 32`. |
| `OPENCRED_DEV_MODE_NO_AUTH` | boolean | `false` | No | Explicit opt-out from authentication for local development only. Mutually exclusive with `OPENCRED_API_KEY`. Refused when `NODE_ENV=production`. |
| `OPENCRED_LOG_LEVEL` | enum | `info` | No | Pino log level: `fatal`, `error`, `warn`, `info`, `debug`, `trace` |

### Signing Key (File-Based)

Used when `OPENCRED_KMS_PROVIDER` is `none` (the default).

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KEY_PATH` | string (path) | -- | For issuance | Absolute path to the signing key file (PEM, JWK, PKCS#8 DER, or PFX). Mount as a read-only volume -- never bake key material into the image. |
| `OPENCRED_KEY_PASSWORD` | string | -- | No | Password for PFX/P12 key files |
| `OPENCRED_KEY_LABEL` | string | `server-key` | No | Human-readable label shown in `GET /v1/keys` |

### Cloud HSM

Mutually exclusive with file-based signing. Set `OPENCRED_KMS_PROVIDER` and the matching provider variables.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KMS_PROVIDER` | enum | `none` | No | `aws`, `azure`, `gcp`, or `none` |
| `OPENCRED_KMS_KEY_ARN` | string | -- | If `aws` | AWS KMS key ARN |
| `OPENCRED_AZURE_KEY_VAULT_URL` | URL | -- | If `azure` | Azure Key Vault base URL |
| `OPENCRED_AZURE_KEY_NAME` | string | -- | If `azure` | Key name in the vault |
| `OPENCRED_GCP_KMS_KEY_NAME` | string | -- | If `gcp` | GCP KMS key resource name including version |

Cloud HSM providers use their platform's default credential chain (AWS SDK default chain, Azure `DefaultAzureCredential`, GCP Application Default Credentials). Supported key types include ECDSA (P-256, P-384) and RSA (2048, 3072, 4096).

### Batch and Session

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_BATCH_ROW_LIMIT` | integer | `1000` | No | Maximum rows per batch CSV |
| `OPENCRED_SESSION_TTL` | integer (seconds, min 60) | `14400` | No | Ephemeral credential data TTL (default 4 hours) |

### Trust Store

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_CSCA_TRUST_STORE_PATH` | string (path) | -- | For DSC verification | Directory of PEM-encoded CSCA root certificates for X.509 chain validation. Mount read-only. |

### Schema Updates

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_SCHEMA_UPDATE_URL` | URL | -- | No | HTTPS URL of the schema update manifest. If unset, schema updates are disabled and only bundled schemas are available. |
| `OPENCRED_SCHEMA_CACHE_DIR` | string (path) | `~/.opencred/schemas` | No | Local directory for caching updated schemas between restarts |

### DeDi Integration

DeDi provides revocation and directory services. All DeDi variables are optional -- when `OPENCRED_DEDI_BASE_URL` is unset, DeDi features are disabled.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_DEDI_BASE_URL` | URL | -- | No | Base URL for the DeDi instance |
| `OPENCRED_DEDI_AUTH_TYPE` | enum | -- | If DeDi enabled | `api-key` or `bearer` |
| `OPENCRED_DEDI_API_KEY` | string | -- | If auth type = `api-key` | API key for DeDi |
| `OPENCRED_DEDI_EMAIL` | string (email) | -- | If auth type = `bearer` | Email for DeDi bearer auth |
| `OPENCRED_DEDI_PASSWORD` | string | -- | If auth type = `bearer` | Password for DeDi bearer auth |
| `OPENCRED_DEDI_NAMESPACE` | string | -- | If DeDi enabled | Default DeDi namespace |
| `OPENCRED_DEDI_TIMEOUT_MS` | integer (1000-30000) | `10000` | No | DeDi request timeout in milliseconds. Hard-capped at 10s per request, so values above `10000` have no effect |
| `OPENCRED_DEDI_MAX_RETRIES` | integer (0-5) | `2` | No | Retries for a failed idempotent DeDi request (key/DID resolution); `2` means 3 attempts total, `0` disables. Raise this — not the timeout — to ride out a brief DeDi outage |

### Example .env File

```bash
# Core
OPENCRED_PORT=3100
OPENCRED_API_KEY=sk_prod_your_random_token_here
OPENCRED_LOG_LEVEL=info

# Signing key (file-based)
OPENCRED_KEY_PATH=/secrets/issuer-key.pem
# OPENCRED_KEY_PASSWORD=  # Only needed for PFX

# Batch
OPENCRED_BATCH_ROW_LIMIT=1000

# Trust store (for DSC-backed credential verification)
# OPENCRED_CSCA_TRUST_STORE_PATH=/app/trust-store

# DeDi integration (optional)
# OPENCRED_DEDI_BASE_URL=https://dedi.example.com
# OPENCRED_DEDI_AUTH_TYPE=api-key
# OPENCRED_DEDI_API_KEY=your-dedi-api-key
# OPENCRED_DEDI_NAMESPACE=my-org
```

## Docker Compose Setup

A minimal `docker-compose.yml`:

```yaml
version: "3.8"
services:
  server:
    build:
      context: .
      dockerfile: apps/server/Dockerfile
    ports:
      - "3100:3100"
    env_file:
      - .env
    volumes:
      - ./keys/issuer-key.pem:/secrets/issuer-key.pem:ro
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3100/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

For Kubernetes, use liveness and readiness probes:

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

## Nginx Reverse Proxy

The container ships HTTP-only. Production deployments should sit behind a reverse proxy for TLS termination. The repository includes a ready-to-use nginx configuration at `deploy/nginx.conf`.

### Setup

1. Copy `deploy/nginx.conf` and `deploy/security-headers.conf` to your nginx configuration directory.

2. The nginx configuration proxies to the OpenCred server at `server:3100` (the Docker Compose service name). Adjust the upstream if running standalone.

3. Security features included in the nginx configuration:
   - TLS termination (configure your certificate)
   - Method restriction: only GET, POST, OPTIONS, HEAD
   - Request body size limit: 10 MB (`client_max_body_size 10m`)
   - Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`
   - Proxy timeouts to prevent slow-loris attacks
   - CORS headers with configurable origin via `OPENCRED_CORS_ORIGIN`
   - Server version hidden (`server_tokens off`)

4. Set the CORS origin:

```bash
export OPENCRED_CORS_ORIGIN="https://your-app.example.com"
```

### Security Headers

The `deploy/security-headers.conf` snippet is included in every nginx `location` block to ensure headers are not lost due to nginx's `add_header` inheritance behavior:

```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

## DeDi Integration Configuration

DeDi (Decentralized Directory) provides two services for OpenCred:

1. **Revocation** -- publish and query credential revocation status
2. **Directory** -- schema and key publication for verifier discovery

### Setup

1. Set the DeDi base URL and authentication:

```bash
# API key authentication
OPENCRED_DEDI_BASE_URL=https://dedi.example.com
OPENCRED_DEDI_AUTH_TYPE=api-key
OPENCRED_DEDI_API_KEY=your-dedi-api-key
OPENCRED_DEDI_NAMESPACE=my-org

# Or bearer authentication
OPENCRED_DEDI_BASE_URL=https://dedi.example.com
OPENCRED_DEDI_AUTH_TYPE=bearer
OPENCRED_DEDI_EMAIL=admin@example.com
OPENCRED_DEDI_PASSWORD=your-password
OPENCRED_DEDI_NAMESPACE=my-org
```

2. At startup, the server initializes the DeDi client and attempts to pre-create registries for the configured namespace. Failures are logged but do not prevent startup.

3. With DeDi configured, the following features are enabled:
   - `POST /v1/credentials/issue` with `revocationRegistryUrl` adds a `credentialStatus` block
   - `POST /v1/credentials/revoke` publishes revocation hashes
   - `POST /v1/credentials/revocation-status` queries revocation status
   - Verification via `POST /v1/credentials/verify` checks revocation status for credentials that carry a `credentialStatus`

Without DeDi, these endpoints return `503 DEDI_NOT_CONFIGURED` (except issue, which works without revocation).

## Health Check and Monitoring

### Health Endpoint

`GET /v1/health` returns the server status and whether the signing key is loaded:

```bash
curl -s http://localhost:3100/v1/health
```

- HTTP `200`: Server is ready (signing key loaded)
- HTTP `503`: Server is running but not ready (signing key not loaded)

### Prometheus Metrics

`GET /v1/metrics` returns Prometheus text exposition format. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `http_request_duration_seconds` | Histogram | Request latency distribution |
| `opencred_credentials_issued_total` | Counter | Credentials issued by proof format and schema |
| `opencred_credentials_verified_total` | Counter | Credentials verified by result |
| `opencred_batch_jobs_total` | Counter | Batch jobs by status |
| `opencred_revocations_published_total` | Counter | Revocations published to DeDi |

A sample Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: opencred
    static_configs:
      - targets: ["opencred:3100"]
    metrics_path: /v1/metrics
```

A Grafana dashboard JSON is available at `docs/observability/grafana-dashboard.json`. Prometheus alerting rules are at `docs/observability/prometheus-alerts.yml`.

### OpenTelemetry Tracing

Tracing is opt-in. Set the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable to enable OpenTelemetry tracing:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
```

### Logging

The server uses pino for structured JSON logging to stdout. Configure the level with `OPENCRED_LOG_LEVEL` (default `info`). Standard Docker logging drivers work without modification.

What is logged: key ID, fingerprint, algorithm, request method/path/status/duration, error class names.
What is NOT logged: private keys, signing buffers, request bodies (may contain PII), KMS credentials, internal stack traces.

## Security Considerations

### API Key

- Authentication is fail-closed. The server refuses to start without `OPENCRED_API_KEY` (or an explicit dev-mode opt-out).
- The API key is compared using constant-time comparison (`crypto.timingSafeEqual`) to prevent timing attacks.
- `OPENCRED_DEV_MODE_NO_AUTH=true` is refused when `NODE_ENV=production`.
- Setting both `OPENCRED_API_KEY` and `OPENCRED_DEV_MODE_NO_AUTH` is refused (mutually exclusive).

### HTTPS

The container ships HTTP-only. Always terminate TLS at a reverse proxy (nginx, Caddy, cloud load balancer). Never expose port 3100 directly to the internet.

### SSRF Protection

When resolving `did:web` DIDs during verification, the server validates that resolved IPs are public (rejects private/loopback addresses including IPv4-mapped IPv6). HTTPS only, no redirects, 10-second timeout.

### Key Material

- The server never accepts private key material via the HTTP API. Every POST endpoint recursively scans the request body for forbidden key names and PEM headers.
- Key material is never logged. Logs contain only key IDs and fingerprints.
- Error responses never leak key material, file paths, or signing buffers.

### Container Hardening

- The image runs as the non-root `node` user.
- Use `--read-only` with a tmpfs for `/tmp`.
- Drop all capabilities except `NET_BIND_SERVICE`.
- Set `--security-opt no-new-privileges:true`.
- Mount signing keys read-only with 0600 permissions on the host.

## Graceful Shutdown

The server registers `SIGTERM` and `SIGINT` handlers that close the HTTP server cleanly. Send `SIGTERM` (the default for `docker stop`) and the process drains in-flight requests before exiting. If OpenTelemetry tracing is enabled, the tracer is flushed before shutdown.

## Production Checklist

| Check | Why |
|-------|-----|
| `OPENCRED_API_KEY` is set and rotated periodically | Prevents unauthorized credential issuance |
| Signing key file has 0600 permissions on host | Protects key material at rest |
| Key is mounted read-only (`-v path:path:ro`) | Prevents accidental modification |
| Container runs as non-root | Built into the image; verify with `docker exec opencred id` |
| TLS terminated upstream | Container does not handle TLS itself |
| `OPENCRED_LOG_LEVEL=info` in production | Prevents verbose debug output |
| Health check configured | Detect signing key load failures |
| Metrics endpoint scraped | Monitor issuance volume and errors |
