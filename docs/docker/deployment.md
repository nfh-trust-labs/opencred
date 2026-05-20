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

### Read-tier mode

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_READ_ONLY` | boolean | `false` | When `true`, write endpoints (`/credentials/issue`, `/credentials/batch`, `/credentials/revoke`, `/keys/publish`, `/schemas/generate`, `/dedi/*`) return `405 READ_ONLY_MODE`. The read surface (verify, key resolve, schemas, health, metrics) stays enabled. See [Read-tier deployment](#read-tier-deployment) below. |

### Job store (batch jobs)

OpenCred batch jobs (`POST /credentials/batch`) live in a pluggable backing store. The default — `memory` — is an in-process Map and matches the behaviour of every release prior to v1.5.x. For horizontal scale (multiple replicas behind a load balancer), set `OPENCRED_JOB_STORE=redis`.

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCRED_JOB_STORE` | enum | `memory` | `memory` for single-instance, `redis` for horizontal scale. |
| `OPENCRED_REDIS_URL` | URL | — | **REQUIRED** when `OPENCRED_JOB_STORE=redis`. Accepts `redis://` or `rediss://` (TLS). May embed credentials inline. The full URL is never logged — only the redacted `host:port` descriptor. |
| `OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED` | boolean | `true` | Whether to verify the Redis server's TLS certificate when using `rediss://`. Operators must explicitly set `false` to disable verification — there is no silent fall-through. |
| `OPENCRED_HEARTBEAT_INTERVAL_SEC` | integer (1–60) | `5` | How often a running replica refreshes its job's `lastSeenAt` timestamp in the JobStore. Observers treat a job as candidate-for-interruption when `lastSeenAt` is older than 2× this value. See [Stale-replica detection](#stale-replica-detection). |

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

### Multi-replica with a load balancer

Once `OPENCRED_JOB_STORE=redis` is in play, you can run N replicas behind any L4/L7 load balancer with **no sticky-session requirement**. Every job-status read (`GET /credentials/batch/:jobId`) goes through the Redis-backed JobStore, so any replica can answer for any job — the LB is free to round-robin every request, including reads for in-flight batches.

A minimal 3-replica + 1-Redis + nginx LB compose looks like this:

```yaml
# docker-compose.scale.yml
version: "3.9"

services:
  redis:
    image: redis:7-alpine
    # No persistence — OpenCred uses Redis for ephemeral TTL'd job records.
    # `--save ""` disables RDB snapshots; `--appendonly no` disables AOF.
    command: ["redis-server", "--save", "", "--appendonly", "no", "--maxmemory", "256mb", "--maxmemory-policy", "allkeys-lru"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  opencred-1: &opencred
    image: ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
    depends_on:
      redis:
        condition: service_healthy
    environment:
      OPENCRED_PORT: "3100"
      OPENCRED_API_KEY: "${OPENCRED_API_KEY:?set OPENCRED_API_KEY in .env}"
      OPENCRED_KEY_PATH: "/secrets/issuer-key.pem"
      OPENCRED_JOB_STORE: "redis"
      OPENCRED_REDIS_URL: "redis://redis:6379/0"
      OPENCRED_HEARTBEAT_INTERVAL_SEC: "5"
      OPENCRED_LOG_LEVEL: "info"
    volumes:
      - ./keys/issuer-key.pem:/secrets/issuer-key.pem:ro
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3100/v1/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  opencred-2:
    <<: *opencred

  opencred-3:
    <<: *opencred

  nginx:
    image: nginx:1.27-alpine
    depends_on:
      opencred-1:
        condition: service_healthy
      opencred-2:
        condition: service_healthy
      opencred-3:
        condition: service_healthy
    ports:
      - "8080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

And a matching `nginx.conf` — round-robin across the three replicas, with the rate-limit-cheap `/health` endpoint used as the upstream probe:

```nginx
upstream opencred {
    # Default round-robin. No `ip_hash` — sticky sessions are NOT required.
    server opencred-1:3100 max_fails=2 fail_timeout=10s;
    server opencred-2:3100 max_fails=2 fail_timeout=10s;
    server opencred-3:3100 max_fails=2 fail_timeout=10s;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Batch endpoints can ship large CSV bodies; nginx defaults are tight.
    client_max_body_size 50m;
    proxy_request_buffering off;

    location / {
        proxy_pass http://opencred;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Long-poll friendly — batch GETs can be slow on large progress arrays.
        proxy_read_timeout 60s;
    }

    # Passive upstream health check via /v1/health. The endpoint is
    # rate-limit-cheap (see issue #569) so the LB can poll it aggressively.
    # If you also need active health checks, NGINX Plus or an L7 LB does the
    # ping itself; on open-source NGINX, the `max_fails` directive above
    # gives you passive ejection.
    location = /health {
        access_log off;
        proxy_pass http://opencred/v1/health;
    }
}
```

Front this with a real L7 (AWS ALB, GCP HTTPS LB, Caddy, Traefik) in production. Terminate TLS at the LB; the upstream connections stay HTTP-only, the same posture as a single-replica deployment.

#### Replica health-check config

Both the LB (above) and the container orchestrator should probe `/v1/health`:

- **Liveness:** returns `200` when the signing key is loaded; `503` otherwise. A 503 here is a hard-fail state — restarting the replica is the right response.
- **Readiness:** identical endpoint; the LB pulls a replica out of rotation when probes start failing. The default exclusion threshold (`max_fails=2, fail_timeout=10s` in nginx, or 2-of-3 in Cloud Run) is a good starting point.
- **Cost:** `/health` is on the cheap rate-limit bucket (issue #569). A 30 s probe interval × N replicas × M LB layers is well under the bucket's budget.

#### What "stateless" buys you

* **Visibility:** Every replica can answer `GET /credentials/batch/:jobId` regardless of which replica accepted the original POST. Job records — status, progress, completion timestamps, `lastSeenAt` heartbeat — are read from the shared Redis.
* **Bounded memory:** Redis TTL (`SET ... EX`) evicts records automatically when they exceed `OPENCRED_SESSION_TTL`. The previously observed RSS climb under sustained small-batch load (#446) is structurally fixed: an unbounded in-process Map no longer exists.
* **Restart safety:** Records survive a single replica's restart. A reader hitting a different replica still sees the job.
* **Liveness signal:** Each running batch carries a `lastSeenAt` ISO-8601 timestamp refreshed every `OPENCRED_HEARTBEAT_INTERVAL_SEC` by the owning replica. Observers can detect a dead replica from the stored record alone — see [Stale-replica detection](#stale-replica-detection).

#### What it does NOT do (and why)

* **Cross-replica work stealing — `inline` mode only.** In the default `inline` dispatch the actual signing for a batch is pinned to the replica that received the POST. If that replica dies mid-batch:
  - On a *graceful* shutdown (SIGTERM), the replica marks every in-flight job as `interrupted` in Redis before exiting. A client polling for that job sees the settled state and can re-submit.
  - On an *abrupt* exit (kernel OOM, hard kill), no terminal write happens. The job's `lastSeenAt` stops refreshing; the entry eventually expires via TTL. The heartbeat signal is what lets an observer notice this gap without waiting for the full TTL.
  In neither case does another replica pick up the work — re-issuance is the client's call. The opt-in `queue` dispatch (see below) lifts this restriction by moving signing into a separate worker fleet.

### Queue dispatch (worker fleet) — `OPENCRED_BATCH_DISPATCH=queue`

When you scale beyond a single API replica AND batches are large enough that you want them to survive an API restart, opt into the worker-fleet model (Tier 3 #8 of nfh-trust-labs/opencred#446):

```bash
# .env additions
OPENCRED_BATCH_DISPATCH=queue
OPENCRED_JOB_STORE=redis
OPENCRED_REDIS_URL=rediss://redis.prod:6380/0
# Optional knobs (sensible defaults if unset)
OPENCRED_WORKER_CONCURRENCY=4              # jobs per worker process (default min(4, cpus))
OPENCRED_WEBHOOK_WORKER_CONCURRENCY=4      # webhook deliveries per worker
```

```yaml
# docker-compose.yml — uncomment the `worker` stanza
worker:
  image: ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
  command: ["node", "apps/server/dist/worker.js"]
  env_file: .env
  restart: unless-stopped
  depends_on:
    - server
  volumes:
    - ./issuer-key.pem:/app/keys/key.pem:ro
```

Then:

```bash
docker compose up -d --scale worker=4
```

**How it works.** In queue mode the API process does:

1. Parse + validate the CSV body (same as inline).
2. Persist the initial `JobRecord` with `status: "queued"` to Redis.
3. Enqueue a `BatchJob` message onto the `opencred:batch` BullMQ queue.
4. Return `202 { jobId, status: "queued" }` immediately.

Worker processes consume the queue, run the streaming engine, push progress frames back into the shared JobStore via the engine's `onProgress` hook, and enqueue a webhook delivery (if `webhookUrl` was supplied) onto `opencred:webhook` for the same fleet to handle with retry + DLQ semantics.

**Failure model.**

| Event | Behaviour |
| --- | --- |
| Worker crashes mid-batch | BullMQ marks the job stalled after `lockDuration` (~30 s) and re-enqueues it. At-least-once — see the [spike doc](../spikes/spike-1-external-job-queue.md) for the duplicate-row caveat. |
| API replica restart | No effect on in-flight work — workers own it. Returning replicas read the same Redis. |
| Webhook receiver down | Webhook job retries up to 5× with exponential backoff (2s, 4s, 8s, 16s, 32s), then lands in BullMQ's `failed` set (DLQ). Batch outcome is unaffected. |
| Redis down | Enqueue fails → API returns 503. Already-running batches lose progress visibility until Redis returns. |

**Security.** Workers load the signing key from `OPENCRED_KEY_PATH` (or a Cloud HSM provider) the same way the API does — keys NEVER travel through the queue payload (CLAUDE.md rule 1). Webhook signing secrets are read from `OPENCRED_WEBHOOK_SECRET` in the worker's own env at delivery time; the secret never enters a queue message.

#### Stale-replica detection

When a replica dies mid-batch, its `JobRecord` stays in Redis until the TTL expires (default 4 h). The `lastSeenAt` field is how you tell "dead 5 minutes ago" from "still working at it":

- The owning replica writes `lastSeenAt` every `OPENCRED_HEARTBEAT_INTERVAL_SEC` (default `5` s).
- Any observer — another replica, a sidecar exporter, a monitoring script — treats a job as **candidate-for-interruption** when:
  1. `status === "running"` (or `"queued"`), AND
  2. `lastSeenAt` is older than `2 × OPENCRED_HEARTBEAT_INTERVAL_SEC` (default 10 s).

The helper `findStaleRunningJobs(jobStore, { heartbeatIntervalSeconds })` (exported from `apps/server/src/batch/job-store/types.ts`) implements this; build dashboards or alerts on top.

**Important: the helper does NOT auto-transition stale records.** It only reports them. A future external-queue tier (#446 Tier 3 #8 / #583) is the right place to introduce re-queueing; until then, the heartbeat is a *signal*, not a coordination primitive. This matches the CLAUDE.md security model — keys never move between replicas, so silent work transfer would violate the local-signing invariant.

#### When to keep `memory`

Single-instance deployments — including every desktop client deployment of this repo — should stick with `memory`. There is no operational benefit to adding Redis if you only run one replica.

#### Operating the Redis

* Use a managed Redis (AWS ElastiCache, Memorystore, Upstash, etc.) rather than co-locating. The Redis is on the credential-issuance hot path; a flaky Redis becomes a flaky issuance API.
* Cap memory with `maxmemory` + an `allkeys-lru` or `allkeys-lfu` policy. OpenCred's TTL handles its own keys, but a hard cap is the right belt-and-suspenders.
* Use TLS (`rediss://`) when the Redis is not in the same VPC. Keep `OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED=true` (the default) unless you have a specific reason to relax it.
* Rotate the Redis password by rotating `OPENCRED_REDIS_URL` and rolling the replicas — there is no in-process rotation hook.

#### Sizing

For workloads up to ~1000 active jobs simultaneously, a `cache.t4g.micro`-class instance is sufficient. Storage per job is on the order of 10–50 KB depending on row count and proof format.

### Future work — Node `cluster` API

Node's built-in [`cluster`](https://nodejs.org/api/cluster.html) module lets a single process fork N worker processes (one per CPU core) over a shared listening socket. It's a different shape from the multi-replica deployment above:

| | Multi-replica (current) | Node `cluster` (future) |
|---|---|---|
| Process boundary | N separate Node processes, possibly on N hosts | 1 parent + N child processes on ONE host |
| Shared state | Redis | IPC + Redis (if also multi-host) |
| Failure isolation | Per-host | Per-worker, shared host kernel |
| Operational story | Standard container orchestration | One container, internal supervision |

**Decision (this PR):** punted. Implementing `cluster` correctly under the CLAUDE.md key-management invariant requires non-trivial design — the signing key must stay in the parent process, and every worker has to round-trip a "sign this credential" request over IPC. That's a meaningful refactor of the signer interface, with its own performance characteristics to measure. The multi-replica path above already delivers the headline scale benefit (horizontal capacity) without touching the signing path.

If this becomes a need later, the design constraint is fixed up front: **key material never leaves the parent process**. The likely shape is a `cluster.fork()` parent that owns the signer instance and a worker pool that handles HTTP via IPC-forwarded sign requests. Tracked as a follow-up to #446 Tier 2 #6.

## Read-tier deployment

Most production traffic against an OpenCred deployment is **verify**, not issue: end users carry a credential, a verifier validates it. Verify is read-only, idempotent, and its expensive dependencies (DID document resolution, CSCA trust-store lookups, JSON Schema bodies) are cacheable. If your verify rate dwarfs your issue rate — the usual shape once you've issued a few thousand credentials — split the two surfaces.

This section covers two complementary deployment patterns:

  1. **Put a CDN in front of the read endpoints.** The server emits `ETag` and `Cache-Control` headers on every cacheable response; any HTTP cache (CloudFront, Fastly, nginx caching proxy, a service-worker) can dedupe identical reads.
  2. **Run a dedicated read tier of replicas** with `OPENCRED_READ_ONLY=true`. These replicas have **no signing key** and refuse every write endpoint with a `405 Method Not Allowed`. Front them with a load balancer; route write traffic to a separate, smaller fleet that holds the signing key.

You can combine the two — a read-tier fleet behind a CDN — or use either one alone.

### Endpoints with cache headers

Implemented in Tier 3 #9 of [#446](https://github.com/nfh-trust-labs/opencred/issues/446):

| Endpoint | Method | Cache-Control | Notes |
|---|---|---|---|
| `/v1/schemas` | GET | `public, max-age=3600, stale-while-revalidate=300` | Vary: `category` |
| `/v1/schemas/:id` | GET | `public, max-age=3600, stale-while-revalidate=300` | Schemas in the v1 catalogue are versioned in the id, so the body is effectively immutable |
| `/v1/keys/resolve` | GET | `public, max-age=300, stale-while-revalidate=60` | DID document resolution |
| `/v1/keys/resolve` | POST | `public, max-age=300, stale-while-revalidate=60` | Same as the GET surface; POST exists for DIDs whose serialization is unfriendly to an L7 proxy |
| `/v1/credentials/verify` | POST | `private, max-age=60` | Vary: `Content-Type, Authorization`. POSTs cannot be cached by a shared CDN, but a client-side cache (service-worker, in-process LRU) can dedupe rapid re-verifications |

Every cacheable response carries a weak `ETag` (`W/"<sha256-hex>"`) computed deterministically from the response body. A conditional request with a matching `If-None-Match` returns `304 Not Modified` with an empty body and the validators preserved.

### Sample nginx caching proxy

The following snippet sits in front of an OpenCred read tier and adds CDN-style edge caching for the GET-cacheable endpoints. It honours the upstream `Cache-Control` directives and bypasses caching for any path it doesn't explicitly recognise.

```nginx
# /etc/nginx/conf.d/opencred-readtier.conf

proxy_cache_path /var/cache/nginx/opencred
                 levels=1:2
                 keys_zone=opencred_read:100m
                 max_size=1g
                 inactive=24h
                 use_temp_path=off;

upstream opencred_read_tier {
    # Round-robin across the read replicas. Each runs with
    # OPENCRED_READ_ONLY=true and no signing key.
    server opencred-read-1.internal:3100 max_fails=3 fail_timeout=10s;
    server opencred-read-2.internal:3100 max_fails=3 fail_timeout=10s;
    server opencred-read-3.internal:3100 max_fails=3 fail_timeout=10s;
}

server {
    listen 443 ssl http2;
    server_name verify.example.org;
    # ssl_certificate + ssl_certificate_key elided

    # Pass through whatever Cache-Control the upstream sets — don't
    # widen the directive on our own initiative.
    proxy_cache opencred_read;
    proxy_cache_key "$scheme://$host$request_uri";
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    proxy_cache_revalidate on;             # honour upstream ETag for 304 path
    proxy_cache_lock on;                   # collapse stampedes
    proxy_cache_background_update on;      # serve stale + refresh in bg
    add_header X-Cache-Status $upstream_cache_status always;

    # GET /v1/schemas, GET /v1/schemas/:id → 1h cache, 5m SWR
    location ~ ^/v1/schemas {
        proxy_pass http://opencred_read_tier;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_valid 200 1h;
        proxy_cache_valid 404 1m;
        proxy_cache_methods GET HEAD;
    }

    # GET/POST /v1/keys/resolve → 5m cache, 1m SWR
    location = /v1/keys/resolve {
        proxy_pass http://opencred_read_tier;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # Only GET is shared-cacheable. The upstream sets Cache-Control
        # on POSTs too (`public, max-age=300`) but nginx by default
        # refuses to cache POST responses. Leave that off.
        proxy_cache_methods GET HEAD;
        proxy_cache_valid 200 5m;
    }

    # POST /v1/credentials/verify → never edge-cache. The upstream
    # response is `private, max-age=60` so a client-side cache can
    # dedupe; nginx must not.
    location = /v1/credentials/verify {
        proxy_pass http://opencred_read_tier;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
    }

    # Health, metrics, everything else: pass through, don't cache.
    location / {
        proxy_pass http://opencred_read_tier;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

The `proxy_cache_revalidate on` directive is what makes the `If-None-Match` ➜ `304 Not Modified` path work end-to-end: nginx forwards its cached `ETag` upstream and on a 304 swaps in the cached body, avoiding the upstream serialization cost entirely.

### Read-only mode

Set `OPENCRED_READ_ONLY=true` to refuse every write endpoint at the route boundary with a `405 Method Not Allowed` and a `READ_ONLY_MODE` error code:

```bash
docker run -d \
  --name opencred-read-1 \
  -p 3100:3100 \
  -e OPENCRED_API_KEY=sk_prod_change_me \
  -e OPENCRED_READ_ONLY=true \
  -e OPENCRED_CSCA_TRUST_STORE_PATH=/app/trust-store \
  -v /host/path/trust-store:/app/trust-store:ro \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

Note that the read tier:

  - Does NOT need `OPENCRED_KEY_PATH` or any `OPENCRED_KMS_*` variables. There is no signing key on these replicas — that's the entire point.
  - Still needs `OPENCRED_API_KEY`. Read-only is a deployment topology, not an authentication bypass.
  - Still needs `OPENCRED_CSCA_TRUST_STORE_PATH` if you want DSC-backed credentials to verify (the trust store is used by `/credentials/verify`).
  - Still benefits from `OPENCRED_DEDI_*` configuration if you use DeDi for revocation or did:web hosting — verify consults DeDi for revocation, key rotation, and DID-document fallback.

#### What `OPENCRED_READ_ONLY=true` blocks

  - `POST /credentials/issue`
  - `POST /credentials/batch` (POST is start; `GET /credentials/batch/:jobId` and `/results` remain readable)
  - `POST /credentials/revoke`
  - `POST /keys/publish`
  - `POST /schemas/generate`
  - `POST /dedi/namespace/ensure`

#### What stays open

  - `GET /health`, `GET /metrics`
  - `GET /schemas`, `GET /schemas/:id`
  - `GET /keys/resolve`, `POST /keys/resolve`
  - `POST /credentials/verify`
  - `POST /credentials/revocation-status` (read against DeDi)
  - `POST /credentials/revocation-hash` and `/batch` (local hash compute, deterministic)

#### Fail-closed semantics

The enforcement middleware uses a denylist of *write-prefix paths* (`/credentials/`, `/keys/`, `/batch/`, `/schemas/`, `/dedi/`) and a small allowlist of known-safe POSTs. **A new write endpoint added later without updating the allowlist is blocked by default** — the read surface is explicit, the write surface is implicit. This is intentional: a quiet leak of a new write endpoint onto the read tier is the failure mode we never want.

If you add an endpoint that should be reachable from the read tier, update both `READ_OPERATIONS` in `apps/server/src/middleware/read-only.ts` and the table above.

### Sizing the split

Per-replica capacity is roughly:

| Tier | Endpoints | CPU bottleneck | Memory |
|---|---|---|---|
| Write (`OPENCRED_READ_ONLY=false`) | issue, batch, revoke, publish | Signing (RSA-3072 / P-384 sign per credential) | Bounded by job-store TTL |
| Read (`OPENCRED_READ_ONLY=true`) | verify, resolve, schemas | Verifier crypto (ECDSA / Ed25519 verify) + JSON-LD canonicalize | Stateless; bounded by request rate |

A common starting split is one write replica per ~50 issuances/s and one read replica per ~500 verifications/s. Front the read replicas with a CDN once your steady-state verify QPS exceeds what a single replica can serve at its tail latency budget.

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
