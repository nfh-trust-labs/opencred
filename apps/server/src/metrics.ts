/**
 * Prometheus metrics for the OpenCred server.
 *
 * Uses a CUSTOM prom-client Registry (not the global default) to avoid
 * test pollution and allow independent metric collection per test run.
 *
 * SECURITY: Metric labels MUST NOT contain key material, auth tokens,
 * request bodies, or Authorization headers. Only use stable, low-cardinality
 * values (method, route pattern, status code, proof format, schema ID).
 */

import { Registry, Counter, Histogram, collectDefaultMetrics } from "prom-client";

const registry = new Registry();
collectDefaultMetrics({ register: registry });

export const httpRequestsTotal = new Counter({
  name: "http_requests_total",
  help: "Total HTTP requests",
  labelNames: ["method", "path", "status"] as const,
  registers: [registry],
});

export const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "path", "status"] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

export const credentialsIssuedTotal = new Counter({
  name: "opencred_credentials_issued_total",
  help: "Total credentials issued",
  labelNames: ["proof_format", "schema_id"] as const,
  registers: [registry],
});

export const credentialsVerifiedTotal = new Counter({
  name: "opencred_credentials_verified_total",
  help: "Total credentials verified",
  labelNames: ["result"] as const,
  registers: [registry],
});

export const batchJobsTotal = new Counter({
  name: "opencred_batch_jobs_total",
  help: "Total batch jobs",
  labelNames: ["status"] as const,
  registers: [registry],
});

export const revocationsPublishedTotal = new Counter({
  name: "opencred_revocations_published_total",
  help: "Total revocation hashes published to DeDi",
  registers: [registry],
});

export function getMetricsRegistry(): Registry {
  return registry;
}
