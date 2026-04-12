/**
 * Prometheus metrics endpoint.
 *
 * GET /metrics — returns all collected metrics in Prometheus text format.
 */

import { Hono } from "hono";
import { getMetricsRegistry } from "../metrics.js";

const metrics = new Hono();

metrics.get("/metrics", async (c) => {
  const registry = getMetricsRegistry();
  const body = await registry.metrics();
  return c.text(body, 200, { "Content-Type": registry.contentType });
});

export { metrics };
