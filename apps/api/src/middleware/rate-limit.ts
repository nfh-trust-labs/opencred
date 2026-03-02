import type { Context, Next } from "hono";
import { RateLimitError } from "@opencred/shared";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

/**
 * Pluggable store interface for rate-limit state (#151).
 *
 * The default {@link InMemoryRateLimitStore} works for single-instance
 * deployments.  For multi-instance setups, implement this interface
 * backed by Redis or another shared data store.
 */
export interface RateLimitStore {
  get(key: string): RateLimitEntry | undefined;
  set(key: string, entry: RateLimitEntry): void;
  increment(key: string): number;
}

/**
 * In-memory rate-limit store with periodic sweep of expired entries.
 */
export class InMemoryRateLimitStore implements RateLimitStore {
  private readonly map = new Map<string, RateLimitEntry>();
  private readonly sweepTimer: ReturnType<typeof setInterval>;

  constructor(sweepIntervalMs: number) {
    this.sweepTimer = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.map) {
        if (now >= entry.resetAt) {
          this.map.delete(key);
        }
      }
    }, sweepIntervalMs);

    if (typeof this.sweepTimer === "object" && "unref" in this.sweepTimer) {
      (this.sweepTimer as NodeJS.Timeout).unref();
    }
  }

  get(key: string): RateLimitEntry | undefined {
    const entry = this.map.get(key);
    if (entry && Date.now() >= entry.resetAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry;
  }

  set(key: string, entry: RateLimitEntry): void {
    this.map.set(key, entry);
  }

  increment(key: string): number {
    const entry = this.map.get(key);
    if (!entry) return 0;
    entry.count++;
    return entry.count;
  }
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyFn?: (c: Context) => string;
  /** Pluggable store — defaults to {@link InMemoryRateLimitStore}. */
  store?: RateLimitStore;
  /**
   * Number of trusted reverse-proxy hops between the client and this
   * server.  When set to 0 (the default), X-Forwarded-For is ignored
   * entirely, preventing header-spoofing attacks (#125, #175).
   */
  trustedProxyHops?: number;
}

const DEFAULT_OPTIONS = {
  windowMs: 60_000,
  maxRequests: 100,
  trustedProxyHops: 0,
} satisfies Partial<RateLimitOptions>;

/**
 * Extract the real client IP from the X-Forwarded-For header using the
 * "rightmost trusted" strategy.
 *
 * With `trustedProxyHops = N`, the Nth entry from the right is selected
 * — this is the IP that the outermost trusted proxy saw as the
 * connecting address, which cannot be spoofed by the client.
 *
 * When `trustedProxyHops` is 0, XFF is ignored and a constant key is
 * returned (safe default for deployments without a reverse proxy).
 */
export function extractClientIp(
  c: Context,
  trustedProxyHops: number,
): string {
  if (trustedProxyHops <= 0) return "direct";

  const xff = c.req.header("x-forwarded-for");
  if (!xff) return "unknown";

  const parts = xff
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const index = parts.length - trustedProxyHops;
  return parts[Math.max(0, index)] ?? "unknown";
}

export function rateLimitMiddleware(options: Partial<RateLimitOptions> = {}) {
  const config = { ...DEFAULT_OPTIONS, ...options };
  const store =
    config.store ?? new InMemoryRateLimitStore(config.windowMs);

  return async (c: Context, next: Next) => {
    const key = config.keyFn
      ? config.keyFn(c)
      : extractClientIp(c, config.trustedProxyHops ?? 0);

    const now = Date.now();
    let entry = store.get(key);

    if (!entry) {
      entry = { count: 0, resetAt: now + config.windowMs };
      store.set(key, entry);
    }

    const count = store.increment(key);

    c.header("X-RateLimit-Limit", String(config.maxRequests));
    c.header(
      "X-RateLimit-Remaining",
      String(Math.max(0, config.maxRequests - count)),
    );
    c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));

    if (count > config.maxRequests) {
      throw new RateLimitError();
    }

    await next();
  };
}
