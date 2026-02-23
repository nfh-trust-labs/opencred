import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

interface ErrorBody {
  error: { code: string; message: string };
}

const logger = makeTestLogger();

function createTestApp(maxRequests: number) {
  const app = new Hono();
  app.use(
    "/*",
    rateLimitMiddleware({
      windowMs: 60_000,
      maxRequests,
      keyFn: () => "test-client",
    }),
  );
  app.get("/test", (c) => c.json({ ok: true }));
  app.onError(errorHandler(logger));
  return app;
}

describe("Rate limit middleware", () => {
  it("allows requests within the limit", async () => {
    const app = createTestApp(5);
    const res = await app.request("/test");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-ratelimit-limit")).toBe("5");
    expect(res.headers.get("x-ratelimit-remaining")).toBe("4");
    expect(res.headers.get("x-ratelimit-reset")).toBeDefined();
  });

  it("returns 429 when limit is exceeded", async () => {
    const app = createTestApp(3);
    for (let i = 0; i < 3; i++) {
      const res = await app.request("/test");
      expect(res.status).toBe(200);
    }
    const res = await app.request("/test");
    expect(res.status).toBe(429);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("RATE_LIMIT_EXCEEDED");
  });

  it("decrements remaining count with each request", async () => {
    const app = createTestApp(5);
    for (let i = 0; i < 3; i++) {
      const res = await app.request("/test");
      expect(res.headers.get("x-ratelimit-remaining")).toBe(String(5 - i - 1));
    }
  });

  it("sets remaining to 0 when at limit", async () => {
    const app = createTestApp(2);
    await app.request("/test");
    const res = await app.request("/test");
    expect(res.headers.get("x-ratelimit-remaining")).toBe("0");
  });
});
