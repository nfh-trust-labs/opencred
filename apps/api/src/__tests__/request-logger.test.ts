import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createHealthRoutes } from "../routes/health.js";
import { makeTestLogger } from "./helpers.js";
import { requestLogger } from "../middleware/request-logger.js";

/**
 * Build a minimal app with request-logger middleware + health route — the
 * same pipeline as createApp() but without importing route modules that
 * carry the (removed) @opencred/delegation dependency.
 */
function buildMinimalApp() {
  const logger = makeTestLogger();
  const app = new Hono();

  app.use("/*", requestLogger(logger));
  app.route("/", createHealthRoutes());

  return app;
}

describe("Request logger middleware", () => {
  it("adds X-Request-Id header to response", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health");
    expect(res.headers.get("x-request-id")).toBeDefined();
    expect(res.headers.get("x-request-id")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("echoes back client-provided X-Request-Id", async () => {
    const app = buildMinimalApp();
    const requestId = "custom-request-id-123";
    const res = await app.request("/health", {
      headers: { "x-request-id": requestId },
    });
    expect(res.headers.get("x-request-id")).toBe(requestId);
  });
});
