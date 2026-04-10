# Observability

The OpenCred Docker image is designed to be observed by the same tools you already use for the rest of your stack: a log aggregator that ingests JSON from stdout, an HTTP health check, and (optionally) a metrics endpoint at the orchestrator level. There is no built-in dashboard, no telemetry sent home, and no third-party APM integration baked into the image.

## Logging

The server uses [pino](https://getpino.io/) for structured logging. Logs are written to **stdout** as JSON, one event per line. The configuration lives in `apps/server/src/logger.ts`:

```ts
import pino from "pino";
import { getConfig } from "./config.js";

export function createLogger(): pino.Logger {
  const config = getConfig();
  return pino({
    level: config.OPENCRED_LOG_LEVEL,
    formatters: {
      level(label) {
        return { level: label };
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
```

### Log levels

Set with `OPENCRED_LOG_LEVEL`. Default `info`.

| Level | Use for |
|---|---|
| `fatal` | Process about to exit due to unrecoverable error |
| `error` | Failed requests, signing failures, network errors |
| `warn` | Recoverable but suspicious events |
| `info` | Startup, shutdown, key loaded, successful requests (production default) |
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
| Request method, path, status, duration | Request body for `/credentials/issue` (contains the credential subject) |
| Issuer DID | Holder PII unless explicitly required |
| Cloud HSM provider, key ID | KMS auth credentials |
| Error class name and sanitized message | Internal stack traces in production responses |

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

The `/health` endpoint is the only built-in observability surface. It is unauthenticated (so probes can hit it without a token) and intentionally cheap.

```bash
$ curl http://localhost:3100/health
{
  "status": "ok",
  "signingKeyLoaded": true,
  "timestamp": "2026-04-07T10:00:00.000Z"
}
```

The handler is in `apps/server/src/routes/health.ts` and returns:

* `status`: always `"ok"` if the process is running
* `signingKeyLoaded`: `true` if a signer was successfully loaded at startup
* `timestamp`: current ISO-8601 timestamp

If `signingKeyLoaded` is `false`, the server is up but cannot issue credentials. Treat this as a critical alert in production — issue endpoints will fail with 500 errors until a signer is loaded.

### Probe configuration

**Docker Compose** (already in `docker-compose.yml`):

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:3100/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

**Kubernetes**:

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

For a stricter readiness check that gates traffic on the signing key, parse the JSON in your probe and require `signingKeyLoaded == true`. The orchestrator can then route traffic away from a node whose key failed to load.

## Metrics

The Docker image does **not** ship a Prometheus or OpenTelemetry endpoint today. Tracking is left to the orchestrator (request counts, latencies, error rates from your ingress) and to your log aggregator (events extracted from pino logs).

If you need application-level metrics, the recommended pattern is:

1. Run a sidecar that scrapes pino's stdout and emits metrics to your TSDB.
2. Or, terminate the request at a reverse proxy (nginx, Envoy, Caddy) and rely on the proxy's built-in request metrics.

A native Prometheus endpoint is on the long-term roadmap and will be tracked under a separate issue.

## Auditing

Because OpenCred is stateless, "audit" usually means "what happened to a particular request" — and the answer lives in your log stream. Useful searches:

* All requests by status code: `level=info status>=400`
* All issuance events: `msg=*issue* OR path=/credentials/issue`
* All shutdown events: `msg="Shutting down"`
* All `signingKeyLoaded` failures: search the startup log for `signingKeyLoaded:false`

If you need a tamper-evident audit log, ship the pino events into an append-only store (e.g., AWS CloudWatch Logs with retention locks, or a WORM S3 bucket).

## Tracing

OpenCred does not currently emit OpenTelemetry traces. The Hono framework supports tracing middleware, and adding it is on the roadmap. For now, instrument the upstream load balancer or service mesh (Linkerd, Istio, AWS App Mesh) to capture request traces at the network layer.

## Operational alerts

A minimal alerting setup:

| Alert | Severity | Trigger |
|---|---|---|
| Health endpoint fails for > 1 min | Critical | The server is down or wedged |
| `signingKeyLoaded` is `false` | Critical | The image started but cannot issue credentials |
| HTTP 5xx rate > 1% over 5 min | Warning | Likely a key, schema, or Cloud HSM issue |
| Container restart count > 3 / hour | Warning | Crash loop |
| Disk pressure on the log volume | Warning | Logs are filling up faster than rotation |

For most teams these are already standard metrics in their orchestrator — no OpenCred-specific configuration is needed.
