import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:dns so tests do not perform real DNS lookups. The default
// mock resolves every hostname to a public IPv4 address; tests that
// exercise SSRF behaviour override this via vi.mocked() or spyOn.
vi.mock("node:dns", () => ({
  promises: {
    resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
    resolve6: vi.fn().mockResolvedValue([]),
  },
}));
import { DeDiClientError } from "@opencred/shared";
import { DeDiApiClient } from "../api/api-client.js";
import { DeDiClient } from "../adapter/client.js";
import { CircuitBreaker } from "../circuit-breaker.js";
import { withRetry } from "../retry.js";
import { noopLogger } from "../logger.js";
import type { DeDiLogger } from "../logger.js";
import type { DeDiApiClientConfig } from "../api/api-client.js";

function createLogger(): DeDiLogger & {
  debug: ReturnType<typeof vi.fn>;
  warn: ReturnType<typeof vi.fn>;
  error: ReturnType<typeof vi.fn>;
} {
  return {
    debug: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

function fakeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({ exp: expSeconds }));
  return `${header}.${payload}.fake`;
}

function jwtExpiringIn(seconds: number): string {
  return fakeJwt(Math.floor(Date.now() / 1000) + seconds);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function createConfig(overrides?: Partial<DeDiApiClientConfig>): DeDiApiClientConfig {
  return {
    baseUrl: "https://dedi.example.com",
    timeoutMs: 5000,
    auth: { type: "api-key", apiKey: "dk_test_key" },
    circuitBreakerThreshold: 5,
    maxRetries: 0,
    ...overrides,
  };
}

// ── Auth logging ──────────────────────────────────────────────────────

describe("auth logging", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  it("logs debug on successful login", async () => {
    const logger = createLogger();
    const jwt = jwtExpiringIn(3600);

    mockFetch.mockResolvedValueOnce(
      jsonResponse({ access_token: jwt, refresh_token: "rt_1", token_type: "bearer" }),
    );
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));

    const client = new DeDiApiClient(
      createConfig({
        auth: { type: "bearer", email: "u@t.com", password: "p" },
        logger,
      }),
    );

    await client.getStats();

    expect(logger.debug).toHaveBeenCalledWith("DeDi login successful");
  });

  it("logs debug on successful token refresh", async () => {
    const logger = createLogger();
    const soonJwt = jwtExpiringIn(50);
    const freshJwt = jwtExpiringIn(3600);

    // Login
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
    );
    // First API call
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));
    // Refresh
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ access_token: freshJwt, refresh_token: "rt_2", token_type: "bearer" }),
    );
    // Second API call
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));

    const client = new DeDiApiClient(
      createConfig({
        auth: { type: "bearer", email: "u@t.com", password: "p", refreshBufferMs: 60_000 },
        logger,
      }),
    );

    await client.getStats();
    await client.getStats();

    expect(logger.debug).toHaveBeenCalledWith("DeDi token refresh successful");
  });

  it("logs error on authentication failure", async () => {
    const logger = createLogger();
    mockFetch.mockResolvedValue(new Response("Unauthorized", { status: 401 }));

    const client = new DeDiApiClient(
      createConfig({
        auth: { type: "bearer", email: "u@t.com", password: "p" },
        logger,
      }),
    );

    await expect(client.getStats()).rejects.toThrow();

    expect(logger.error).toHaveBeenCalledWith("DeDi authentication failed with status 401");
  });
});

// ── Circuit breaker logging ──────────────────────────────────────────

describe("circuit breaker logging", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("logs warn when circuit breaker opens after threshold failures", async () => {
    const logger = createLogger();
    const cb = new CircuitBreaker({ threshold: 3, logger });

    for (let i = 0; i < 3; i++) {
      await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow();
    }

    expect(logger.warn).toHaveBeenCalledWith("Circuit breaker opened after 3 failures");
  });

  it("logs debug on OPEN to HALF_OPEN transition", async () => {
    const logger = createLogger();
    const cb = new CircuitBreaker({ threshold: 1, resetTimeoutMs: 1000, logger });

    await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow();

    vi.advanceTimersByTime(1000);

    await cb.execute(() => Promise.resolve("ok"));

    expect(logger.debug).toHaveBeenCalledWith(
      "Circuit breaker transitioning from OPEN to HALF_OPEN",
    );
  });

  it("logs debug on HALF_OPEN to CLOSED transition", async () => {
    const logger = createLogger();
    const cb = new CircuitBreaker({ threshold: 1, resetTimeoutMs: 1000, logger });

    await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow();

    vi.advanceTimersByTime(1000);

    await cb.execute(() => Promise.resolve("ok"));

    expect(logger.debug).toHaveBeenCalledWith(
      "Circuit breaker transitioning from HALF_OPEN to CLOSED",
    );
  });

  it("logs warn on HALF_OPEN to OPEN transition", async () => {
    const logger = createLogger();
    const cb = new CircuitBreaker({ threshold: 2, resetTimeoutMs: 1000, logger });

    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow();
    }

    logger.warn.mockClear();
    vi.advanceTimersByTime(1000);

    await expect(cb.execute(() => Promise.reject(new Error("fail again")))).rejects.toThrow();

    expect(logger.warn).toHaveBeenCalledWith("Circuit breaker opened after HALF_OPEN failure");
  });

  it("does not log when no logger is provided", async () => {
    const cb = new CircuitBreaker({ threshold: 1, resetTimeoutMs: 1000 });

    await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow();

    vi.advanceTimersByTime(1000);
    await cb.execute(() => Promise.resolve("ok"));
  });
});

// ── Retry logging ────────────────────────────────────────────────────

describe("retry logging", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("logs debug on each retry attempt", async () => {
    const logger = createLogger();
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new DeDiClientError("server error", 502))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 3, baseDelayMs: 100, logger });
    await vi.advanceTimersByTimeAsync(100);
    await promise;

    expect(logger.debug).toHaveBeenCalledWith("Retrying request, attempt 1 of 3");
  });

  it("logs error when all retries exhausted", async () => {
    const logger = createLogger();
    const fn = vi.fn().mockRejectedValue(new DeDiClientError("server error", 502));

    const promise = withRetry(fn, { maxRetries: 2, baseDelayMs: 100, logger });
    const assertion = expect(promise).rejects.toThrow("server error");
    await vi.advanceTimersByTimeAsync(300);
    await assertion;

    expect(logger.error).toHaveBeenCalledWith("All 2 retry attempts exhausted");
  });

  it("does not log when no logger is provided", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new DeDiClientError("server error", 502))
      .mockResolvedValue("ok");

    const promise = withRetry(fn, { maxRetries: 1, baseDelayMs: 100 });
    await vi.advanceTimersByTimeAsync(100);
    await promise;
  });
});

// ── DeDiClient (adapter) 404 fallback logging ───────────────────────

describe("DeDiClient 404 error propagation", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  it("throws on 404 instead of treating as not-revoked", async () => {
    const logger = createLogger();

    mockFetch.mockResolvedValue(new Response(null, { status: 404 }));

    const client = new DeDiClient({
      baseUrl: "https://dedi.example.com",
      timeoutMs: 5000,
      maxRetries: 0,
      circuitBreakerThreshold: 5,
      auth: { type: "api-key", apiKey: "dk_test" },
      defaultNamespace: "example.com",
      logger,
    });

    await expect(client.queryRevocationHash("missing-hash")).rejects.toThrow();
  });
});

// ── Security: no credential logging ──────────────────────────────────

describe("security: no credential logging", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  it("never logs passwords, API keys, or JWT tokens via the injectable logger", async () => {
    const logger = createLogger();
    const jwt = jwtExpiringIn(3600);
    const password = "super-s3cret-password";
    const apiKey = "dk_test_secret_key_12345";

    mockFetch.mockResolvedValueOnce(
      jsonResponse({ access_token: jwt, refresh_token: "rt_secret_1", token_type: "bearer" }),
    );
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));

    const bearerClient = new DeDiApiClient(
      createConfig({
        auth: { type: "bearer", email: "user@test.com", password },
        logger,
      }),
    );
    await bearerClient.getStats();

    const apiKeyClient = new DeDiApiClient(
      createConfig({
        auth: { type: "api-key", apiKey },
        logger,
      }),
    );
    mockFetch.mockResolvedValueOnce(jsonResponse({ data: {} }));
    await apiKeyClient.getStats();

    const allCalls = [
      ...logger.debug.mock.calls,
      ...logger.warn.mock.calls,
      ...logger.error.mock.calls,
    ];
    const allOutput = JSON.stringify(allCalls);

    expect(allOutput).not.toContain(password);
    expect(allOutput).not.toContain(apiKey);
    expect(allOutput).not.toContain(jwt);
    expect(allOutput).not.toContain("rt_secret_1");
  });

  it("never logs credentials via the injectable logger on auth failure", async () => {
    const logger = createLogger();
    const password = "super-s3cret-password";

    mockFetch.mockResolvedValue(new Response("Unauthorized", { status: 401 }));

    const client = new DeDiApiClient(
      createConfig({
        auth: { type: "bearer", email: "user@test.com", password },
        logger,
      }),
    );

    await expect(client.getStats()).rejects.toThrow();

    const allCalls = [
      ...logger.debug.mock.calls,
      ...logger.warn.mock.calls,
      ...logger.error.mock.calls,
    ];
    const allOutput = JSON.stringify(allCalls);

    expect(allOutput).not.toContain(password);
  });
});

// ── noopLogger ───────────────────────────────────────────────────────

describe("noopLogger", () => {
  it("does not throw when called", () => {
    expect(() => noopLogger.debug("test")).not.toThrow();
    expect(() => noopLogger.warn("test")).not.toThrow();
    expect(() => noopLogger.error("test")).not.toThrow();
  });
});

// ── Backward compatibility ───────────────────────────────────────────

describe("backward compatibility", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("works without providing a logger (no logging, no errors)", async () => {
    mockFetch.mockResolvedValue(jsonResponse({ data: {} }));

    const client = new DeDiApiClient(createConfig());
    await client.getStats();
  });
});
