/**
 * Job-store factory. Reads server config and produces the right backing
 * implementation, plus does the redacted boot-time logging that the
 * security invariants demand.
 *
 * Public entry points:
 *  - `createJobStore(config, logger)` — the production path
 *  - `createJobStoreFromInjected(opts)` — for tests that want to bypass
 *    env-var driven selection
 *
 * SECURITY: the Redis URL frequently embeds credentials. This module
 * NEVER logs the raw URL; it logs only host/port and the count of
 * key-prefixed credentials. See `safeRedisInfo`.
 */

import type { Logger } from "pino";
import type { ServerConfig } from "../../config.js";
import { MemoryJobStore } from "./memory.js";
import { RedisJobStore, type RedisLike } from "./redis.js";
import type { JobStore } from "./types.js";

/**
 * Extract `host:port` from a Redis URL without exposing credentials.
 * Returns a redacted descriptor `"<host>:<port>"`, or `"<unparseable>"`
 * if the URL is malformed (the factory will surface that as a config
 * error before this returns, but we still defend the logger).
 */
export function safeRedisInfo(url: string): string {
  try {
    const u = new URL(url);
    const port = u.port || "6379";
    return `${u.hostname}:${port}`;
  } catch {
    return "<unparseable>";
  }
}

interface FactoryDeps {
  /**
   * Test/seam: lets the factory construct an ioredis client lazily so
   * the unit tests don't need to install or mock the real package.
   * Production wiring (in `index.ts`) imports the default constructor.
   */
  createRedisClient?: (url: string, tls: boolean) => RedisLike;
}

/**
 * Build a JobStore from the loaded server config.
 *
 * Behaviour:
 *  - `OPENCRED_JOB_STORE=memory` (default) — returns a `MemoryJobStore`.
 *  - `OPENCRED_JOB_STORE=redis`            — requires `OPENCRED_REDIS_URL`.
 *    Returns a `RedisJobStore` connected to that URL. The URL is parsed
 *    only for the boot-time host/port log; credentials embedded in the
 *    URL are passed straight through to ioredis and never recorded.
 *
 * The factory throws if `OPENCRED_JOB_STORE=redis` is set without a
 * `OPENCRED_REDIS_URL`. The route module catches this at startup so the
 * server refuses to boot with an ambiguous job-store configuration.
 */
export async function createJobStore(
  config: ServerConfig,
  logger: Logger,
  deps: FactoryDeps = {},
): Promise<JobStore> {
  if (config.OPENCRED_JOB_STORE === "memory") {
    logger.info({ jobStore: "memory" }, "Job store: in-process Map");
    return new MemoryJobStore();
  }

  // redis
  const url = config.OPENCRED_REDIS_URL;
  if (!url) {
    // Should already be caught by `loadConfig`, but we defend the rest
    // of the bootstrap from a future code path that bypasses validation.
    throw new Error(
      "OPENCRED_JOB_STORE=redis requires OPENCRED_REDIS_URL (config validation should have caught this earlier).",
    );
  }

  const create =
    deps.createRedisClient ??
    (await loadRealIoredisFactory(config.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED));

  const tls = url.startsWith("rediss://");
  const client = create(url, tls);

  logger.info(
    {
      jobStore: "redis",
      host: safeRedisInfo(url),
      tls,
      // Pino convention — never log the URL. The host:port descriptor
      // is enough for operators to confirm they hit the right replica.
    },
    "Job store: Redis",
  );

  return new RedisJobStore({ client });
}

/**
 * Lazy import of ioredis so the test suite doesn't have to load the
 * full Redis client stack when it's wiring the memory store. Returns a
 * factory function that takes the URL and produces a typed `RedisLike`.
 */
async function loadRealIoredisFactory(
  rejectUnauthorized: boolean,
): Promise<(url: string, tls: boolean) => RedisLike> {
  // ioredis is CommonJS; importing the named `Redis` export is the
  // most portable pattern across `module: Node16` and `module: NodeNext`
  // resolution — `default` interop varies by tsconfig flag combinations
  // that downstream consumers may tweak.
  const { Redis } = await import("ioredis");
  return (url: string, tls: boolean) => {
    const opts: Record<string, unknown> = {
      // ioredis spawns retries forever by default. Cap each connection
      // attempt with exponential backoff up to 10 s — long enough to
      // weather a Redis failover, short enough that a permanently dead
      // Redis surfaces as ENOENT in the logs within a minute.
      retryStrategy(times: number): number {
        return Math.min(1000 * 2 ** times, 10_000);
      },
      // ioredis fires `error` events when reconnecting. We mute the
      // process-level handler by attaching our own no-op below; the
      // pino logger is wired in `index.ts` after the client is created.
      lazyConnect: false,
      maxRetriesPerRequest: 3,
    };
    if (tls) {
      opts.tls = { rejectUnauthorized };
    }
    // ioredis accepts a Redis URL string as the first argument; any
    // user/password embedded in the URL is honoured directly.
    const client = new Redis(url, opts);
    // Suppress unhandled "error" events from ioredis. The reconnect
    // strategy already handles transient failures; without this listener
    // Node treats the first error as unhandled and exits.
    client.on("error", () => {
      // Intentionally empty — the consuming route logs via its own path
      // when an operation fails. This handler exists only to keep the
      // EventEmitter from going "uncaught".
    });
    return client as unknown as RedisLike;
  };
}
