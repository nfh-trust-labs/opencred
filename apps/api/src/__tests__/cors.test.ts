import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { createHealthRoutes } from "../routes/health.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";
import { requestLogger } from "../middleware/request-logger.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";

/**
 * Build a minimal app with CORS + request-logger + rate-limit middleware
 * and the health route — the same middleware pipeline as createApp() but
 * without pulling in route modules that carry heavy dependencies.
 */
function buildMinimalApp(configOverrides: Record<string, unknown> = {}) {
  const config = makeTestConfig(configOverrides);
  const logger = makeTestLogger();
  const app = new Hono();

  app.use(
    "/*",
    cors({
      origin: config.CORS_ORIGIN,
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization"],
      exposeHeaders: [
        "X-Request-Id",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
      ],
      maxAge: 86400,
      credentials: true,
    }),
  );

  app.use("/*", requestLogger(logger));
  app.use("/*", rateLimitMiddleware({ windowMs: 60_000, maxRequests: 100 }));

  app.route("/", createHealthRoutes());

  return app;
}

describe("CORS", () => {
  it("includes CORS headers for allowed origin", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health", {
      headers: { Origin: "http://localhost:5173" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
  });

  it("does not include CORS headers for disallowed origin", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health", {
      headers: { Origin: "http://evil.example.com" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("handles preflight OPTIONS request", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
  });

  it("exposes rate limit and request ID headers", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
      },
    });
    const exposed = res.headers.get("access-control-expose-headers") ?? "";
    expect(exposed).toContain("X-Request-Id");
    expect(exposed).toContain("X-RateLimit-Limit");
  });

  it("allows GET, POST, PUT, DELETE, and OPTIONS methods (#144)", async () => {
    const app = buildMinimalApp();
    const res = await app.request("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
      },
    });
    const methods = res.headers.get("access-control-allow-methods") ?? "";
    expect(methods).toContain("GET");
    expect(methods).toContain("POST");
    expect(methods).toContain("PUT");
    expect(methods).toContain("DELETE");
  });

  it("respects custom CORS origin from config", async () => {
    const app = buildMinimalApp({ CORS_ORIGIN: "https://app.opencred.io" });
    const res = await app.request("/health", {
      headers: { Origin: "https://app.opencred.io" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.opencred.io");
  });
});
