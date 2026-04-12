/**
 * HTTP metrics middleware for Hono.
 *
 * Records request count and duration for every HTTP request using
 * Prometheus counters and histograms. Path labels use the matched
 * route pattern (not the raw URL) to avoid cardinality explosion
 * from UUIDs or query strings.
 *
 * SECURITY: Never captures request bodies, Authorization headers,
 * or query parameters in metric labels.
 */

import type { Context, Next } from "hono";
import { httpRequestsTotal, httpRequestDuration } from "../metrics.js";

export async function metricsMiddleware(c: Context, next: Next): Promise<void> {
  const start = performance.now();

  await next();

  const duration = (performance.now() - start) / 1000;
  const method = c.req.method;
  // Use the matched route pattern to avoid high-cardinality labels from
  // dynamic segments (e.g. /credentials/batch/:jobId -> stable label).
  const path = c.req.routePath || c.req.path;
  const status = String(c.res.status);

  httpRequestsTotal.inc({ method, path, status });
  httpRequestDuration.observe({ method, path, status }, duration);
}
