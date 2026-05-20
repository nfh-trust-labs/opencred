/**
 * Factory-level tests for the JobStore.
 *
 * The factory's job is to translate `ServerConfig` flags into a concrete
 * `JobStore`. The tests focus on:
 *  1. Memory default (no env vars set).
 *  2. Redis selection, with the injected client factory.
 *  3. The safe-logging contract: the redis URL — including credentials —
 *     MUST NOT appear in the logger output. We assert this by asserting
 *     on the recorded pino calls.
 */

import { describe, it, expect, vi } from "vitest";
import { createJobStore, safeRedisInfo } from "../factory.js";
import type { RedisLike } from "../redis.js";
import { MemoryJobStore } from "../memory.js";
import { RedisJobStore } from "../redis.js";
import type { ServerConfig } from "../../../config.js";

function makeConfig(overrides: Partial<ServerConfig>): ServerConfig {
  // Cast through unknown — only the fields the factory reads need to be
  // present. The rest of the config schema is irrelevant here.
  return {
    OPENCRED_JOB_STORE: "memory",
    OPENCRED_SESSION_TTL: 14_400,
    OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED: true,
    ...overrides,
  } as unknown as ServerConfig;
}

function makeLogger() {
  // Pino's interface is wider than this, but the factory only reaches
  // for `info`. A counter shim is sufficient.
  const calls: Array<{ obj: Record<string, unknown>; msg: string }> = [];
  const logger = {
    info(obj: Record<string, unknown>, msg: string) {
      calls.push({ obj, msg });
    },
    warn() {},
    error() {},
    debug() {},
    fatal() {},
    trace() {},
  } as unknown as Parameters<typeof createJobStore>[1];
  return { logger, calls };
}

function makeFakeRedis(): RedisLike {
  return {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue("OK"),
    del: vi.fn().mockResolvedValue(0),
    scan: vi.fn().mockResolvedValue(["0", []]),
    quit: vi.fn().mockResolvedValue("OK"),
    disconnect: vi.fn(),
    status: "ready",
  };
}

describe("safeRedisInfo", () => {
  it("strips credentials and returns host:port for a credential-bearing URL", () => {
    const info = safeRedisInfo("redis://user:supersecret@redis.prod:6380/0");
    expect(info).toBe("redis.prod:6380");
    expect(info).not.toContain("user");
    expect(info).not.toContain("supersecret");
  });

  it("falls back to port 6379 when the URL omits it", () => {
    expect(safeRedisInfo("redis://localhost")).toBe("localhost:6379");
  });

  it("returns <unparseable> on a malformed URL", () => {
    expect(safeRedisInfo("not a url")).toBe("<unparseable>");
  });
});

describe("createJobStore", () => {
  it("returns a MemoryJobStore when OPENCRED_JOB_STORE=memory", async () => {
    const { logger } = makeLogger();
    const store = await createJobStore(
      makeConfig({ OPENCRED_JOB_STORE: "memory" }),
      logger,
    );
    expect(store).toBeInstanceOf(MemoryJobStore);
    await store.close();
  });

  it("returns a RedisJobStore when OPENCRED_JOB_STORE=redis and OPENCRED_REDIS_URL is set", async () => {
    const { logger } = makeLogger();
    const fake = makeFakeRedis();
    const store = await createJobStore(
      makeConfig({
        OPENCRED_JOB_STORE: "redis",
        OPENCRED_REDIS_URL: "redis://localhost:6379",
      }),
      logger,
      { createRedisClient: () => fake },
    );
    expect(store).toBeInstanceOf(RedisJobStore);
    await store.close();
  });

  it("throws when OPENCRED_JOB_STORE=redis but OPENCRED_REDIS_URL is unset", async () => {
    // (loadConfig() catches this earlier, but the factory still defends
    // against a future code path that bypasses validation.)
    const { logger } = makeLogger();
    await expect(
      createJobStore(makeConfig({ OPENCRED_JOB_STORE: "redis" }), logger),
    ).rejects.toThrow(/OPENCRED_REDIS_URL/);
  });

  it("logs only host:port for Redis — never the full URL with credentials", async () => {
    const { logger, calls } = makeLogger();
    const fake = makeFakeRedis();
    const credUrl = "redis://user:supersecret@redis.prod:6380/0";

    await createJobStore(
      makeConfig({
        OPENCRED_JOB_STORE: "redis",
        OPENCRED_REDIS_URL: credUrl,
      }),
      logger,
      { createRedisClient: () => fake },
    );

    // No log line may contain the password or the full URL.
    const serialized = JSON.stringify(calls);
    expect(serialized).not.toContain("supersecret");
    expect(serialized).not.toContain("user:supersecret");
    expect(serialized).not.toContain(credUrl);

    // But the redacted descriptor IS present so the operator can confirm
    // they hit the right Redis.
    expect(serialized).toContain("redis.prod:6380");
  });

  it("passes the TLS flag to the client factory when the URL is rediss://", async () => {
    const { logger } = makeLogger();
    const create = vi.fn().mockReturnValue(makeFakeRedis());
    await createJobStore(
      makeConfig({
        OPENCRED_JOB_STORE: "redis",
        OPENCRED_REDIS_URL: "rediss://redis.prod:6380",
      }),
      logger,
      { createRedisClient: create },
    );
    expect(create).toHaveBeenCalledWith("rediss://redis.prod:6380", true);
  });

  it("does NOT set the TLS flag for plain redis://", async () => {
    const { logger } = makeLogger();
    const create = vi.fn().mockReturnValue(makeFakeRedis());
    await createJobStore(
      makeConfig({
        OPENCRED_JOB_STORE: "redis",
        OPENCRED_REDIS_URL: "redis://redis.prod:6379",
      }),
      logger,
      { createRedisClient: create },
    );
    expect(create).toHaveBeenCalledWith("redis://redis.prod:6379", false);
  });
});
