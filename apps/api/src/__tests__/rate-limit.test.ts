import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  rateLimitMiddleware,
  extractClientIp,
  InMemoryRateLimitStore,
} from "../middleware/rate-limit.js";
import type { RateLimitStore } from "../middleware/rate-limit.js";
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

describe("extractClientIp (#125, #175)", () => {
  function fakeContext(headers: Record<string, string> = {}) {
    return {
      req: {
        header: (name: string) => headers[name.toLowerCase()],
      },
    } as unknown as import("hono").Context;
  }

  it("returns 'direct' when trustedProxyHops is 0", () => {
    const c = fakeContext({ "x-forwarded-for": "1.2.3.4" });
    expect(extractClientIp(c, 0)).toBe("direct");
  });

  it("returns single IP with trustedProxyHops=1", () => {
    const c = fakeContext({ "x-forwarded-for": "10.0.0.1" });
    expect(extractClientIp(c, 1)).toBe("10.0.0.1");
  });

  it("selects the correct trusted proxy entry", () => {
    // client -> proxy1 -> proxy2 -> our-server
    // XFF: "client-ip, proxy1-ip" (proxy2 appended proxy1-ip)
    // With trustedProxyHops=1, we want parts[length-1] = "proxy1-ip"
    // which is the IP that the last (trusted) proxy actually saw.
    const c = fakeContext({ "x-forwarded-for": "spoofed, 10.0.0.1" });
    expect(extractClientIp(c, 1)).toBe("10.0.0.1");
  });

  it("returns leftmost when hops exceeds parts", () => {
    const c = fakeContext({ "x-forwarded-for": "10.0.0.1" });
    expect(extractClientIp(c, 5)).toBe("10.0.0.1");
  });

  it("returns 'unknown' when XFF is missing", () => {
    const c = fakeContext({});
    expect(extractClientIp(c, 1)).toBe("unknown");
  });

  it("prevents spoofing — attacker-injected IPs are ignored", () => {
    // Attacker sends: X-Forwarded-For: fake-ip
    // Trusted proxy appends real IP: "fake-ip, real-ip"
    // With trustedProxyHops=1, we pick "real-ip" (rightmost = what proxy saw)
    const c = fakeContext({ "x-forwarded-for": "fake-ip, real-ip" });
    expect(extractClientIp(c, 1)).toBe("real-ip");
  });
});

describe("InMemoryRateLimitStore (#151)", () => {
  it("tracks entries correctly", () => {
    const store = new InMemoryRateLimitStore(60_000);
    store.set("k", { count: 0, resetAt: Date.now() + 60_000 });
    const count = store.increment("k");
    expect(count).toBe(1);
    const entry = store.get("k");
    expect(entry?.count).toBe(1);
  });

  it("returns 0 for increment on missing key", () => {
    const store = new InMemoryRateLimitStore(60_000);
    expect(store.increment("missing")).toBe(0);
  });

  it("expires entries whose resetAt has passed", () => {
    const store = new InMemoryRateLimitStore(60_000);
    store.set("expired", { count: 5, resetAt: Date.now() - 1 });
    expect(store.get("expired")).toBeUndefined();
  });
});

describe("Per-IP rate limiting with trusted proxy", () => {
  it("rate-limits per real client IP when trustedProxyHops is set", async () => {
    const app = new Hono();
    app.use(
      "/*",
      rateLimitMiddleware({
        windowMs: 60_000,
        maxRequests: 2,
        trustedProxyHops: 1,
      }),
    );
    app.get("/test", (c) => c.json({ ok: true }));
    app.onError(errorHandler(logger));

    // Two requests from IP "a" — should be allowed
    for (let i = 0; i < 2; i++) {
      const res = await app.request("/test", {
        headers: { "x-forwarded-for": "a" },
      });
      expect(res.status).toBe(200);
    }

    // Third from "a" — rate limited
    const res = await app.request("/test", {
      headers: { "x-forwarded-for": "a" },
    });
    expect(res.status).toBe(429);

    // Request from different IP "b" — should still be allowed
    const res2 = await app.request("/test", {
      headers: { "x-forwarded-for": "b" },
    });
    expect(res2.status).toBe(200);
  });
});

describe("Pluggable store (#151)", () => {
  it("accepts a custom store implementation", async () => {
    const data = new Map<string, { count: number; resetAt: number }>();
    const customStore: RateLimitStore = {
      get: (k) => data.get(k),
      set: (k, v) => data.set(k, v),
      increment: (k) => {
        const e = data.get(k);
        if (!e) return 0;
        e.count++;
        return e.count;
      },
    };

    const app = new Hono();
    app.use(
      "/*",
      rateLimitMiddleware({
        windowMs: 60_000,
        maxRequests: 1,
        keyFn: () => "custom",
        store: customStore,
      }),
    );
    app.get("/test", (c) => c.json({ ok: true }));
    app.onError(errorHandler(logger));

    const res1 = await app.request("/test");
    expect(res1.status).toBe(200);

    const res2 = await app.request("/test");
    expect(res2.status).toBe(429);

    // Verify the custom store was used
    expect(data.has("custom")).toBe(true);
  });
});
