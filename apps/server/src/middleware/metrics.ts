/**
 * HTTP metrics middleware for Hono.
 *
 * Records request count and duration for every HTTP request using
 * Prometheus counters and histograms. Path labels are normalized by
 * replacing UUID and hex-ID segments with /:id to avoid cardinality
 * explosion.
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
  // Normalize the raw path by replacing UUID and hex-ID segments to avoid
  // high-cardinality labels. c.req.routePath returns "*" when registered
  // via app.use("*", ...) so we cannot rely on it.
  const rawPath = c.req.path;
  const path = rawPath
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "/:id")
    .replace(/\/[0-9a-f]{24,}/gi, "/:id");
  const status = String(c.res.status);

  httpRequestsTotal.inc({ method, path, status });
  httpRequestDuration.observe({ method, path, status }, duration);
}
