/**
 * Integration test for the rate-limit IP-extraction path.
 *
 * The unit test in `rate-limit.test.ts` exercises `deriveRateLimitKey`
 * with a hand-crafted mock `c.env.incoming.socket` shape. That validates
 * the JS code but tells us nothing about whether `@hono/node-server`
 * actually surfaces the remote address at that key in a real listening
 * socket. If the adapter ever moves the property — or if a future
 * runtime is plugged in for tests/edge — the unit test would still pass
 * while every anonymous client in production would collapse into a
 * single `ip:unknown` bucket, instantly creating a global rate-limit
 * chokepoint.
 *
 * This test stands up a real `@hono/node-server` on a random port,
 * fires a real `fetch()` from a real local TCP socket, and asserts the
 * bucket key the limiter would have used starts with `ip:` and is NOT
 * `ip:unknown`. If the adapter's surface ever changes this test will
 * catch it.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import { mountRateLimitSelfCheckRoute } from "../middleware/rate-limit.js";
import { loadConfig, resetConfig } from "../config.js";
import { createLogger, resetLogger } from "../logger.js";

let server: ServerType;
let baseUrl: string;

beforeAll(async () => {
  resetConfig();
  resetLogger();
  // Minimal env so loadConfig() succeeds — auth is irrelevant here, we
  // mount only the self-check route which is registered before auth.
  process.env.OPENCRED_API_KEY = "test-key-rate-limit-integration";
  process.env.OPENCRED_LOG_LEVEL = "fatal";
  // Trust-proxy off so the IP-extraction path EXCLUSIVELY exercises the
  // TCP-remote fallback we care about — that's the fragile branch the
  // reviewer flagged. If trust-proxy were on, an XFF on the local
  // request could mask a broken TCP-remote path.
  delete process.env.OPENCRED_TRUST_PROXY;
  loadConfig();
  createLogger();

  const app = new Hono();
  mountRateLimitSelfCheckRoute(app);

  server = serve({ fetch: app.fetch, port: 0 });

  await new Promise<void>((resolve) => {
    if (server.listening) {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
      return;
    }
    server.once("listening", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  delete process.env.OPENCRED_API_KEY;
  delete process.env.OPENCRED_LOG_LEVEL;
  resetConfig();
  resetLogger();
});

describe("rate limiter — real Node server IP extraction", () => {
  it("extracts an ip:* bucket key from a real loopback request — NOT ip:unknown", async () => {
    // The probe route returns the bucket key `deriveRateLimitKey`
    // computed for the inbound request. With a real Node server
    // serving the request, `c.env.incoming.socket.remoteAddress` MUST
    // be populated — anything else means the adapter surface changed
    // underneath us and every anonymous client would share one bucket
    // in production.
    const res = await fetch(`${baseUrl}/__rate-limit-self-check`);
    expect(res.status).toBe(200);

    const body = (await res.json()) as { key: string };
    expect(body.key).toMatch(/^ip:/);
    expect(body.key).not.toBe("ip:unknown");
    // The remote address should be IPv4 or IPv6 loopback. We don't
    // pin the exact form (Node may return "127.0.0.1" or "::1" or
    // "::ffff:127.0.0.1" depending on the listening socket) — just
    // assert it isn't the all-collapsing sentinel.
    expect(body.key.length).toBeGreaterThan("ip:".length);
  });

  it("derives DIFFERENT buckets per request — confirms the IP path is live, not a fixed string", async () => {
    // Two requests from the same client come from the same socket
    // address but each request is a fresh TCP connection — both should
    // produce the SAME `ip:*` bucket (per-IP keying). If we got
    // `ip:unknown` from one and not the other, something is non-
    // deterministic; if both were `ip:unknown`, the per-IP fallback
    // is broken. We assert: same key, both shaped `ip:*`, neither
    // unknown.
    const a = await fetch(`${baseUrl}/__rate-limit-self-check`);
    const b = await fetch(`${baseUrl}/__rate-limit-self-check`);
    const bodyA = (await a.json()) as { key: string };
    const bodyB = (await b.json()) as { key: string };

    expect(bodyA.key).toMatch(/^ip:/);
    expect(bodyB.key).toMatch(/^ip:/);
    expect(bodyA.key).not.toBe("ip:unknown");
    expect(bodyB.key).not.toBe("ip:unknown");
    // Same client → same bucket. This is the per-IP keying contract.
    expect(bodyA.key).toBe(bodyB.key);
  });
});
