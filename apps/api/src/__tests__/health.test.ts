import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { createHealthRoutes } from "../routes/health.js";
import { makeTestLogger } from "./helpers.js";
import { requestLogger } from "../middleware/request-logger.js";
import { errorHandler } from "../middleware/error-handler.js";

/**
 * Build a minimal app with middleware + health route + 404 handler — the
 * same pipeline as createApp() but without importing route modules that
 * carry the (removed) @opencred/delegation dependency.
 */
function buildMinimalApp() {
  const logger = makeTestLogger();
  const app = new Hono();

  app.use("/*", requestLogger(logger));
  app.route("/", createHealthRoutes());

  // JSON 404 handler — same as createApp()
  app.notFound((c) =>
    c.json(
      { error: { code: "NOT_FOUND", message: `${c.req.method} ${c.req.path} not found` } },
      404,
    ),
  );

  app.onError(errorHandler(logger));

  return app;
}

describe("JSON 404 for unknown routes", () => {
  it("returns JSON error for unknown paths", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/nonexistent-route");
    expect(res.status).toBe(404);
    const body = await res.json() as { error: { code: string; message: string } };
    expect(body.error.code).toBe("NOT_FOUND");
    expect(body.error.message).toContain("not found");
  });

  it("returns JSON content-type for 404", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/no-such-path");
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toContain("application/json");
  });
});

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; timestamp: string };
    expect(body.status).toBe("ok");
    expect(body.timestamp).toBeDefined();
  });

  it("returns a valid ISO timestamp", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health");
    const body = (await res.json()) as { timestamp: string };
    const parsed = new Date(body.timestamp);
    expect(parsed.toISOString()).toBe(body.timestamp);
  });
});

interface ReadyBody {
  status: string;
  timestamp: string;
  checks: Record<string, { status: string; detail?: string }>;
}

describe("GET /health/ready", () => {
  it("returns 200 with status ready when no dediClient is configured", async () => {
    const healthRouter = createHealthRoutes();
    const app = new Hono();
    app.route("/", healthRouter);

    const res = await app.request("/health/ready");
    expect(res.status).toBe(200);

    const body = (await res.json()) as ReadyBody;
    expect(body.status).toBe("ready");
    expect(body.timestamp).toBeDefined();
    expect(body.checks).toEqual({});
  });

  it("returns 200 with dedi ok when getStats succeeds", async () => {
    const mockDediClient = {
      apiClient: {
        getStats: vi.fn().mockResolvedValue({ namespaces: 1, registries: 2, records: 10 }),
      },
    };

    const healthRouter = createHealthRoutes({ dediClient: mockDediClient as never });
    const app = new Hono();
    app.route("/", healthRouter);

    const res = await app.request("/health/ready");
    expect(res.status).toBe(200);

    const body = (await res.json()) as ReadyBody;
    expect(body.status).toBe("ready");
    expect(body.checks.dedi.status).toBe("ok");
  });

  it("returns 503 with degraded status when getStats throws", async () => {
    const mockDediClient = {
      apiClient: {
        getStats: vi.fn().mockRejectedValue(new Error("connection refused")),
      },
    };

    const healthRouter = createHealthRoutes({ dediClient: mockDediClient as never });
    const app = new Hono();
    app.route("/", healthRouter);

    const res = await app.request("/health/ready");
    expect(res.status).toBe(503);

    const body = (await res.json()) as ReadyBody;
    expect(body.status).toBe("degraded");
    expect(body.checks.dedi.status).toBe("unavailable");
    expect(body.checks.dedi.detail).toBe("connection refused");
  });
});
