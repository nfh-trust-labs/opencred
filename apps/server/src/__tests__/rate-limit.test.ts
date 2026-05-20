/**
 * Rate-limit middleware tests (issue #446 Tier 1.2).
 *
 * Pins down:
 *  - 429 + Retry-After on bucket bust
 *  - Per-token buckets when an Authorization header is present
 *  - Per-IP buckets when no token is present
 *  - X-Forwarded-For trusted iff OPENCRED_TRUST_PROXY=true
 *  - Separate tiers for issue / verify / read
 *  - Tokens are SHA-256-hashed before they hit the in-memory store —
 *    the raw bearer never appears in any response, log, or store key
 *
 * The tests stand up a tiny Hono app, mount `applyRateLimits`, then fire
 * synthetic requests through `app.request()`. We don't need to wire up
 * the rest of the routes for this — the only thing the limiter cares
 * about is the path prefix.
 */

import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applyRateLimits, deriveRateLimitKey } from "../middleware/rate-limit.js";
import { loadConfig, resetConfig } from "../config.js";
import { createLogger, resetLogger } from "../logger.js";

// ---------------------------------------------------------------------------
// Test app builder
// ---------------------------------------------------------------------------

interface AppOptions {
  /** Override the rate-limit window. */
  windowMs?: number;
  /** Override the issue-bucket limit. */
  issueLimit?: number;
  /** Override the verify-bucket limit. */
  verifyLimit?: number;
  /** Override the read-bucket limit. */
  readLimit?: number;
  /** When true, set OPENCRED_TRUST_PROXY=true so XFF is honoured. */
  trustProxy?: boolean;
}

function setEnv(opts: AppOptions): void {
  resetConfig();
  resetLogger();

  // Auth is irrelevant to these tests — use dev-mode opt-out so 401 doesn't
  // confound the 429 assertions.
  delete process.env.OPENCRED_API_KEY;
  process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
  process.env.OPENCRED_RATE_LIMIT_ENABLED = "true";
  process.env.OPENCRED_LOG_LEVEL = "fatal";

  if (opts.windowMs !== undefined) {
    process.env.OPENCRED_RATE_LIMIT_WINDOW_MS = String(opts.windowMs);
  } else {
    delete process.env.OPENCRED_RATE_LIMIT_WINDOW_MS;
  }
  if (opts.issueLimit !== undefined) {
    process.env.OPENCRED_RATE_LIMIT_ISSUE = String(opts.issueLimit);
  } else {
    delete process.env.OPENCRED_RATE_LIMIT_ISSUE;
  }
  if (opts.verifyLimit !== undefined) {
    process.env.OPENCRED_RATE_LIMIT_VERIFY = String(opts.verifyLimit);
  } else {
    delete process.env.OPENCRED_RATE_LIMIT_VERIFY;
  }
  if (opts.readLimit !== undefined) {
    process.env.OPENCRED_RATE_LIMIT_READ = String(opts.readLimit);
  } else {
    delete process.env.OPENCRED_RATE_LIMIT_READ;
  }
  if (opts.trustProxy) {
    process.env.OPENCRED_TRUST_PROXY = "true";
  } else {
    delete process.env.OPENCRED_TRUST_PROXY;
  }
}

function buildApp(opts: AppOptions = {}): Hono {
  setEnv(opts);
  loadConfig();
  createLogger();

  const app = new Hono();
  applyRateLimits(app);

  // Mock route bodies — the limiter mounts on the path prefix, so we just
  // need handlers that return 200 to confirm "limit not yet exceeded".
  // We register them ON the same paths the limiter watches so a successful
  // path through the middleware reaches the handler.
  app.post("/credentials/issue", (c) => c.json({ ok: true }));
  app.post("/v1/credentials/issue", (c) => c.json({ ok: true }));
  app.post("/credentials/batch", (c) => c.json({ ok: true }));
  app.post("/v1/credentials/batch", (c) => c.json({ ok: true }));
  app.get("/credentials/batch/:id", (c) => c.json({ ok: true }));
  app.post("/credentials/verify", (c) => c.json({ ok: true }));
  app.post("/v1/credentials/verify", (c) => c.json({ ok: true }));
  app.get("/schemas", (c) => c.json({ ok: true }));
  app.get("/schemas/:id", (c) => c.json({ ok: true }));
  app.get("/v1/schemas", (c) => c.json({ ok: true }));
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/v1/health", (c) => c.json({ ok: true }));

  return app;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

const ENV_KEYS = [
  "OPENCRED_API_KEY",
  "OPENCRED_DEV_MODE_NO_AUTH",
  "OPENCRED_RATE_LIMIT_ENABLED",
  "OPENCRED_RATE_LIMIT_WINDOW_MS",
  "OPENCRED_RATE_LIMIT_ISSUE",
  "OPENCRED_RATE_LIMIT_VERIFY",
  "OPENCRED_RATE_LIMIT_READ",
  "OPENCRED_TRUST_PROXY",
  "OPENCRED_LOG_LEVEL",
];

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
  resetConfig();
  resetLogger();
});

// ---------------------------------------------------------------------------
// Tier limits
// ---------------------------------------------------------------------------

describe("rate limiter — per-tier limits", () => {
  it("returns 429 with Retry-After on issue-bucket bust", async () => {
    const app = buildApp({ issueLimit: 2, windowMs: 60_000 });

    // Use a single token so all three requests fall into the same bucket.
    const headers = { Authorization: "Bearer tok-a" };
    const ok1 = await app.request("/credentials/issue", { method: "POST", headers });
    const ok2 = await app.request("/credentials/issue", { method: "POST", headers });
    const limited = await app.request("/credentials/issue", { method: "POST", headers });

    expect(ok1.status).toBe(200);
    expect(ok2.status).toBe(200);
    expect(limited.status).toBe(429);

    const retryAfter = limited.headers.get("Retry-After");
    expect(retryAfter).not.toBeNull();
    expect(Number(retryAfter)).toBeGreaterThan(0);

    const body = (await limited.json()) as { error?: { code?: string; message?: string } };
    expect(body.error?.code).toBe("RATE_LIMIT_EXCEEDED");
    // Body MUST NOT echo the bearer token or any identifying header back.
    expect(JSON.stringify(body)).not.toContain("tok-a");
  });

  it("isolates tokens — each bearer gets its own bucket", async () => {
    const app = buildApp({ issueLimit: 1, windowMs: 60_000 });

    // Two distinct tokens — both get exactly one request through.
    const headersA = { Authorization: "Bearer alpha" };
    const headersB = { Authorization: "Bearer bravo" };

    const a1 = await app.request("/credentials/issue", { method: "POST", headers: headersA });
    const b1 = await app.request("/credentials/issue", { method: "POST", headers: headersB });
    const a2 = await app.request("/credentials/issue", { method: "POST", headers: headersA });

    expect(a1.status).toBe(200);
    expect(b1.status).toBe(200);
    expect(a2.status).toBe(429);
  });

  it("uses a HIGHER cap on /credentials/verify than on /credentials/issue", async () => {
    const app = buildApp({
      issueLimit: 1,
      verifyLimit: 3,
      windowMs: 60_000,
    });
    const headers = { Authorization: "Bearer same-tok" };

    // Issue should bust at the 2nd request.
    await app.request("/credentials/issue", { method: "POST", headers });
    const issueBust = await app.request("/credentials/issue", { method: "POST", headers });
    expect(issueBust.status).toBe(429);

    // Verify shares NO state with issue — different bucket label, different
    // limit. We can fire three before the cap, fourth should 429.
    const v1 = await app.request("/credentials/verify", { method: "POST", headers });
    const v2 = await app.request("/credentials/verify", { method: "POST", headers });
    const v3 = await app.request("/credentials/verify", { method: "POST", headers });
    const v4 = await app.request("/credentials/verify", { method: "POST", headers });

    expect(v1.status).toBe(200);
    expect(v2.status).toBe(200);
    expect(v3.status).toBe(200);
    expect(v4.status).toBe(429);
  });

  it("uses a HIGHER cap for /schemas and /health than for write routes", async () => {
    const app = buildApp({ readLimit: 5, issueLimit: 1, windowMs: 60_000 });
    const headers = { Authorization: "Bearer read-tok" };

    for (let i = 0; i < 5; i++) {
      const res = await app.request("/schemas", { headers });
      expect(res.status).toBe(200);
    }
    const bust = await app.request("/schemas", { headers });
    expect(bust.status).toBe(429);
  });

  it("applies the issue-bucket cap to /v1/credentials/issue and /v1/credentials/batch too", async () => {
    const app = buildApp({ issueLimit: 1, windowMs: 60_000 });
    const headers = { Authorization: "Bearer v1-tok" };

    const issue = await app.request("/v1/credentials/issue", { method: "POST", headers });
    // Same bucket key on /v1/credentials/batch — second request busts.
    const batch = await app.request("/v1/credentials/batch", { method: "POST", headers });

    expect(issue.status).toBe(200);
    expect(batch.status).toBe(429);
  });
});

// ---------------------------------------------------------------------------
// Proxy / IP handling
// ---------------------------------------------------------------------------

describe("rate limiter — X-Forwarded-For trust policy", () => {
  it("IGNORES X-Forwarded-For when OPENCRED_TRUST_PROXY is unset", async () => {
    const app = buildApp({ issueLimit: 1, windowMs: 60_000, trustProxy: false });

    // No Authorization header — keys must derive from IP. Without trust, both
    // requests fall into the same "ip:unknown" bucket and the second 429s.
    const first = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.1" },
    });
    const second = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.2" },
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
  });

  it("HONOURS X-Forwarded-For when OPENCRED_TRUST_PROXY=true", async () => {
    const app = buildApp({ issueLimit: 1, windowMs: 60_000, trustProxy: true });

    // Distinct XFF IPs → distinct buckets → both 200.
    const a = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.10" },
    });
    const b = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.20" },
    });

    expect(a.status).toBe(200);
    expect(b.status).toBe(200);

    // Repeating the FIRST IP must bust now.
    const aAgain = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.10" },
    });
    expect(aAgain.status).toBe(429);
  });

  it("uses only the first IP in a comma-separated X-Forwarded-For chain", async () => {
    const app = buildApp({ issueLimit: 1, windowMs: 60_000, trustProxy: true });

    const first = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.100, 10.0.0.1, 192.168.1.1" },
    });
    expect(first.status).toBe(200);

    // Different downstream proxies but SAME client IP at the front of the
    // chain — must hit the same bucket.
    const second = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "X-Forwarded-For": "203.0.113.100, 10.0.0.99, 10.0.0.42" },
    });
    expect(second.status).toBe(429);
  });
});

// ---------------------------------------------------------------------------
// Key generator
// ---------------------------------------------------------------------------

describe("deriveRateLimitKey", () => {
  beforeEach(() => {
    // Default config posture used by these direct-call tests.
    setEnv({ windowMs: 60_000 });
    loadConfig();
    createLogger();
  });

  it("prefers the bearer token (hashed) over IPs", () => {
    const mockContext = {
      env: { incoming: { socket: { remoteAddress: "203.0.113.1" } } },
      req: {
        header: (name: string) => (name === "Authorization" ? "Bearer secret-token" : undefined),
      },
    };
    const key = deriveRateLimitKey(mockContext as never);
    expect(key.startsWith("tok:")).toBe(true);
    // The raw token MUST NOT appear in the key — the hash is the only
    // value the in-memory store sees.
    expect(key).not.toContain("secret-token");
    // Length: "tok:" + 32 hex chars.
    expect(key).toHaveLength("tok:".length + 32);
  });

  it("falls back to the TCP remote address when no bearer is present", () => {
    const mockContext = {
      env: { incoming: { socket: { remoteAddress: "203.0.113.50" } } },
      req: {
        header: () => undefined,
      },
    };
    const key = deriveRateLimitKey(mockContext as never);
    expect(key).toBe("ip:203.0.113.50");
  });

  it("returns ip:unknown when neither a bearer nor an IP is available", () => {
    const mockContext = {
      env: undefined,
      req: {
        header: () => undefined,
      },
    };
    const key = deriveRateLimitKey(mockContext as never);
    expect(key).toBe("ip:unknown");
  });

  it("produces the same hash for the same token across calls", () => {
    const buildCtx = (auth: string) => ({
      env: undefined,
      req: { header: (n: string) => (n === "Authorization" ? auth : undefined) },
    });
    const a = deriveRateLimitKey(buildCtx("Bearer reusable") as never);
    const b = deriveRateLimitKey(buildCtx("Bearer reusable") as never);
    expect(a).toBe(b);
  });

  it("produces DIFFERENT hashes for different tokens", () => {
    const buildCtx = (auth: string) => ({
      env: undefined,
      req: { header: (n: string) => (n === "Authorization" ? auth : undefined) },
    });
    const a = deriveRateLimitKey(buildCtx("Bearer one") as never);
    const b = deriveRateLimitKey(buildCtx("Bearer two") as never);
    expect(a).not.toBe(b);
  });
});

// ---------------------------------------------------------------------------
// Disable switch
// ---------------------------------------------------------------------------

describe("rate limiter — disable switch", () => {
  it("is a no-op when OPENCRED_RATE_LIMIT_ENABLED=false", async () => {
    setEnv({ issueLimit: 1, windowMs: 60_000 });
    // Override what setEnv just turned on.
    process.env.OPENCRED_RATE_LIMIT_ENABLED = "false";
    resetConfig();
    loadConfig();
    createLogger();

    const app = new Hono();
    applyRateLimits(app);
    app.post("/credentials/issue", (c) => c.json({ ok: true }));

    // With the limiter disabled, ten requests with the same bearer all
    // succeed even though the configured cap is 1.
    const headers = { Authorization: "Bearer never-bust" };
    for (let i = 0; i < 10; i++) {
      const res = await app.request("/credentials/issue", { method: "POST", headers });
      expect(res.status).toBe(200);
    }
  });
});
