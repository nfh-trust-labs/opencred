# Observability

The OpenCred Docker image is designed to be observed by the same tools you already use for the rest of your stack: a log aggregator that ingests JSON from stdout, an HTTP health check, a Prometheus metrics endpoint, and opt-in OpenTelemetry tracing. There is no built-in dashboard, no telemetry sent home, and no third-party APM integration baked into the image.

## Logging

The server uses [pino](https://getpino.io/) for structured logging. Logs are written to **stdout** as JSON, one event per line. The configuration lives in `apps/server/src/logger.ts`.

### Log levels

Set with `OPENCRED_LOG_LEVEL`. Default `info`.

| Level | Use for |
|---|---|
| `fatal` | Process about to exit due to unrecoverable error |
| `error` | Failed requests, signing failures, network errors |
| `warn` | Recoverable but suspicious events |
| `info` | Startup, shutdown, key loaded (production default) |
| `debug` | Verbose request lifecycle for development |
| `trace` | Per-step internal state — never use in production |

### Sample log lines

```json
{"level":"info","time":"2026-04-07T10:00:00.000Z","port":3100,"msg":"Starting OpenCred Server"}
{"level":"info","time":"2026-04-07T10:00:00.234Z","port":3100,"msg":"OpenCred Server listening"}
{"level":"info","time":"2026-04-07T10:01:23.456Z","msg":"Shutting down","signal":"SIGTERM"}
{"level":"info","time":"2026-04-07T10:01:23.512Z","msg":"Server closed"}
```

### What is and is not logged

| Logged | Not logged |
|---|---|
| Key ID, fingerprint, algorithm | Private key bytes, signing buffers, JWK `d` field |
| Cloud HSM provider, key ID | KMS auth credentials |
| Error class name and sanitized message | Request bodies (may contain credential subject PII) |

This is enforced by [security invariant 2 — never log key material](../security/invariants.md#2-never-log-key-material) and [invariant 5 — no secrets in error responses](../security/invariants.md#5-no-secrets-in-error-responses).

### Shipping logs to your aggregator

Because pino writes to stdout, the standard Docker logging drivers work without modification:

```bash
# JSON file driver (default) — log files under /var/lib/docker/containers/
docker logs opencred

# Send to Elasticsearch
docker run --log-driver gelf --log-opt gelf-address=udp://logserver:12201 ...

# Send to AWS CloudWatch via the awslogs driver
docker run --log-driver awslogs --log-opt awslogs-group=opencred ...

# Send to Loki via Promtail (no driver needed)
```

For Kubernetes, every node-local agent (Fluent Bit, Vector, Promtail, Datadog, etc.) ingests stdout/stderr automatically. JSON parsing is automatic for any agent that recognises pino-style payloads.

## Health Checks

The `/v1/health` endpoint is unauthenticated so that container orchestrators can probe liveness without holding the API key.

```bash
$ curl http://localhost:3100/v1/health
{
  "status": "ok",
  "ready": true,
  "signingKeyLoaded": true,
  "dediConfigured": false,
  "timestamp": "2026-04-07T10:00:00.000Z"
}
```

The handler is in `apps/server/src/routes/health.ts` and returns:

* `status`: always `"ok"` if the process is running
* `ready`: `true` when the signing key is loaded (the minimum requirement for issuing credentials)
* `signingKeyLoaded`: `true` if a signer was successfully loaded at startup
* `dediConfigured`: `true` if a DeDi client is configured for revocation
* `timestamp`: current ISO-8601 timestamp

**HTTP status codes:** Returns `200` when `signingKeyLoaded` is true and `503` when false. If `signingKeyLoaded` is `false`, the server is up but cannot issue credentials. Treat this as a critical alert in production — issue endpoints will fail with 500 errors until a signer is loaded.

### Probe configuration

**Docker Compose** (already in `docker-compose.yml`):

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:3100/v1/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

**Kubernetes**:

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

For a stricter readiness check that gates traffic on the signing key, parse the JSON in your probe and require `signingKeyLoaded == true`. The orchestrator can then route traffic away from a node whose key failed to load.

## Metrics

The server exposes a Prometheus-compatible metrics endpoint at `GET /metrics` (also mounted at `/v1/metrics`). This endpoint is unauthenticated so Prometheus can scrape it without holding the API key.

The implementation uses `prom-client` with a custom registry (`apps/server/src/metrics.ts`). Default Node.js process metrics are collected automatically.

### Custom metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | `method`, `path`, `status` | HTTP request duration in seconds |
| `opencred_credentials_issued_total` | Counter | `proof_format`, `schema_id` | Total credentials issued |
| `opencred_credentials_verified_total` | Counter | `result` | Total credentials verified |
| `opencred_batch_jobs_total` | Counter | `status` | Total batch jobs |
| `opencred_revocations_published_total` | Counter | — | Total revocation hashes published to DeDi |

Request method, path, status code, and duration are recorded by the metrics middleware (`apps/server/src/middleware/metrics.ts`) for every HTTP request.

### Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: opencred
    static_configs:
      - targets: ["opencred:3100"]
    metrics_path: /v1/metrics
```

## Tracing

OpenTelemetry critical-path tracing is opt-in via the `OPENCRED_OTEL_ENABLED=true` master switch. When disabled (the default), the tracer is never installed and the instrumentation adds zero overhead — every release before this flag landed ran without it. When enabled, the server emits spans for HTTP requests and for the four hot paths that drive latency: batch issuance, signing, verification, and DeDi calls.

```bash
docker run \
  -e OPENCRED_OTEL_ENABLED=true \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  -e OTEL_SERVICE_NAME=opencred-server \
  -e OTEL_TRACES_SAMPLER=parentbased_traceidratio \
  -e OTEL_TRACES_SAMPLER_ARG=0.1 \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

Standard OpenTelemetry env vars apply: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` (defaults to `opencred-server`), `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG`. The implementation lives in `apps/server/src/tracing.ts`; spans are batched via `BatchSpanProcessor` and flushed on graceful shutdown. When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset, spans go to a no-op exporter — useful for local validation without standing up a collector.

### Span inventory

| Span | Source | Key attributes |
|---|---|---|
| `<METHOD> <route>` | `tracingMiddleware` | `http.request.method`, `http.route`, `http.response.status_code` |
| `signer.sign` | `wrapSignerWithTracing` | `signer.algorithm`, `signer.kind`, `signer.fingerprint`, `signer.input_bytes`, `signer.signature_bytes` |
| `batch.run` | `createBatchEngine` / `createStreamingBatchEngine` | `batch.job_id`, `batch.proof_format`, `batch.total_rows` |
| `batch.row.process` | `createBatchEngine` / `createStreamingBatchEngine` | `batch.job_id`, `batch.row_index`, `batch.proof_format`, `batch.row_status` |
| `verify.credential` | `routes/credentials.ts` | `verify.format`, `verify.code`, `verify.verified` |
| `verify.did_resolve` | `wrapDidResolverWithTracing` | `did.method`, `did` |
| `verify.schema_validate` | `routes/credentials.ts` | `verify.schema_id`, `verify.inline_schema` |
| `dedi.lookup_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |
| `dedi.publish_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |
| `dedi.update_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |

### Grafana dashboard

A sample dashboard with HTTP-server p50/p95/p99, `batch.row.process` distribution, `signer.sign` by algorithm and kind, `verify.credential` outcomes, `verify.did_resolve` latency by DID method, DeDi adapter latency, and error rate by span name lives at [`docs/observability/grafana-dashboards/opencred-overview.json`](../observability/grafana-dashboards/opencred-overview.json). See [the README](../observability/grafana-dashboards/README.md) for import steps.

### Security contract

Spans MUST NOT carry private key material, signing buffers, or credential subject PII. Span attributes are opaque identifiers only — job-id UUIDs, key fingerprints (hashes), DID strings. `dedi.host` is the HOST only; record-name paths are stripped before attachment. The contract is enforced by the helpers in `apps/server/src/observability/` and documented in CLAUDE.md (security invariants 2 and 5).

## Auditing

Because OpenCred is stateless, "audit" usually means "what happened to a particular request" — and the answer lives in your log stream. Useful searches:

* All issuance events: `msg=*issue* OR path=/credentials/issue`
* All shutdown events: `msg="Shutting down"`
* All `signingKeyLoaded` failures: search the startup log for `signingKeyLoaded:false`

If you need a tamper-evident audit log, ship the pino events into an append-only store (e.g., AWS CloudWatch Logs with retention locks, or a WORM S3 bucket).

## Operational alerts

A minimal alerting setup:

| Alert | Severity | Trigger |
|---|---|---|
| Health endpoint returns 503 for > 1 min | Critical | The signing key failed to load |
| Health endpoint unreachable for > 1 min | Critical | The server is down or wedged |
| HTTP 5xx rate > 1% over 5 min | Warning | Likely a key, schema, or Cloud HSM issue |
| Container restart count > 3 / hour | Warning | Crash loop |
| Disk pressure on the log volume | Warning | Logs are filling up faster than rotation |
