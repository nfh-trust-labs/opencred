import type { Context, Next } from "hono";
import { RateLimitError } from "@opencred/shared";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyFn?: (c: Context) => string;
}

const DEFAULT_OPTIONS: RateLimitOptions = {
  windowMs: 60_000,
  maxRequests: 100,
};

export function rateLimitMiddleware(options: Partial<RateLimitOptions> = {}) {
  const config = { ...DEFAULT_OPTIONS, ...options };
  const store = new Map<string, RateLimitEntry>();

  // Periodic cleanup of expired entries
  const sweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (now >= entry.resetAt) {
        store.delete(key);
      }
    }
  }, config.windowMs);

  if (typeof sweepTimer === "object" && "unref" in sweepTimer) {
    sweepTimer.unref();
  }

  return async (c: Context, next: Next) => {
    const key = config.keyFn
      ? config.keyFn(c)
      : (c.req.header("x-forwarded-for") ?? c.req.header("x-real-ip") ?? "unknown");
    const now = Date.now();
    let entry = store.get(key);

    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + config.windowMs };
      store.set(key, entry);
    }

    entry.count++;

    c.header("X-RateLimit-Limit", String(config.maxRequests));
    c.header("X-RateLimit-Remaining", String(Math.max(0, config.maxRequests - entry.count)));
    c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > config.maxRequests) {
      throw new RateLimitError();
    }

    await next();
  };
}
