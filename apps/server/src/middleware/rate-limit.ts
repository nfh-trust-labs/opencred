/**
 * Per-route rate limiter — addresses the "tail-latency collapse" finding
 * from the end-to-end scale review (issue #446).
 *
 * The server hosts three latency classes of endpoint, and a single global
 * bucket would either choke read traffic to protect signing, or let
 * signing traffic starve everything. Instead we mount three independent
 * limiters and let Hono's path-prefix routing pick the right one per
 * request:
 *
 *   - issue/batch (write-heavy, signature path) — default 60/min/key
 *   - verify (read-mostly) — default 120/min/key
 *   - schemas / health / metrics (read-only) — default 600/min/key
 *
 * Keys are derived as: bearer-token hash (if present) → trusted
 * X-Forwarded-For IP (when OPENCRED_TRUST_PROXY=true) → connection IP.
 *
 * SECURITY:
 *  - The bearer token is hashed (SHA-256 truncated) before it is used as
 *    a bucket key. The raw token never reaches the in-memory store and is
 *    never logged. See CLAUDE.md rule 2.
 *  - X-Forwarded-For is honoured only when OPENCRED_TRUST_PROXY=true.
 *    Otherwise an internet client could spoof a fresh "IP" per request
 *    and trivially bypass the limit. See CLAUDE.md rule 5 by analogy.
 *  - The 429 response body never includes the offending IP, token, or
 *    any header value. Only a stable error code, a human-readable
 *    message, and the standard `Retry-After` header.
 */

import { createHash } from "node:crypto";
import type { Context, MiddlewareHandler } from "hono";
import { rateLimiter } from "hono-rate-limiter";
import { getConfig } from "../config.js";
import { getLogger } from "../logger.js";

/**
 * Hash a bearer token so it can be used as a bucket key without ever
 * landing in memory or logs in cleartext. Truncated to 32 chars — the
 * resulting birthday-bound collision probability is negligible at the
 * bucket scale we operate at, and shorter keys keep the in-memory store
 * compact.
 */
function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 32);
}

/**
 * Pull a client identifier out of the request. Order of precedence:
 *
 *   1. SHA-256 of the Bearer token, when present. (Same client, multiple
 *      IPs — e.g. mobile + WFH — gets a single bucket, which is the
 *      semantically correct behaviour for an API quota.)
 *   2. The first IP in `X-Forwarded-For`, but ONLY when
 *      OPENCRED_TRUST_PROXY=true. Otherwise the header is ignored.
 *   3. The TCP remote address.
 *   4. The literal string "unknown" as a last-resort bucket so a
 *      misconfigured environment still throttles instead of crashing.
 */
export function deriveRateLimitKey(c: Context): string {
  const auth = c.req.header("Authorization");
  if (auth) {
    const parts = auth.split(" ");
    if (parts.length === 2 && parts[0] === "Bearer" && parts[1]) {
      return `tok:${hashToken(parts[1])}`;
    }
  }

  const config = getConfig();
  if (config.OPENCRED_TRUST_PROXY) {
    const xff = c.req.header("X-Forwarded-For");
    if (xff) {
      const first = xff.split(",")[0]?.trim();
      if (first) return `ip:${first}`;
    }
  }

  // Hono on @hono/node-server exposes `c.env.incoming.socket.remoteAddress`.
  // Pull it defensively — non-Node environments (Cloudflare, Bun, tests)
  // may not surface it, in which case we fall through to the "unknown"
  // bucket. That bucket is shared, so a single unhealthy peer cannot evade
  // throttling by stripping its address.
  const envWithIncoming = c.env as
    | {
        incoming?: { socket?: { remoteAddress?: string } };
      }
    | undefined;
  const remote = envWithIncoming?.incoming?.socket?.remoteAddress;
  if (remote) return `ip:${remote}`;

  return "ip:unknown";
}

/**
 * Build the JSON body and Retry-After header for a 429. Kept as a single
 * function so the limit-exceeded handler is consistent across all three
 * buckets. The body intentionally omits the offending key — including it
 * would leak whatever the limiter's key generator returned (an IP or a
 * token hash), which is a non-zero observability surface for nothing.
 */
function buildLimitExceededResponse(c: Context, resetAt: Date | undefined) {
  const retryAfterSeconds = resetAt
    ? Math.max(1, Math.ceil((resetAt.getTime() - Date.now()) / 1000))
    : 60;
  c.header("Retry-After", String(retryAfterSeconds));
  return c.json(
    {
      error: {
        code: "RATE_LIMIT_EXCEEDED",
        message: "Too many requests. Retry after the time indicated by Retry-After.",
      },
    },
    429,
  );
}

/**
 * Construct a rate-limit middleware bound to the given window/limit. We
 * factor this so every tier shares the same key generator, the same 429
 * shape, and the same handler — only the cap moves.
 */
function buildLimiter(getLimit: () => number, label: string): MiddlewareHandler {
  // `requestPropertyName: ''` disables the default `c.set('rateLimit', …)`
  // call that the library performs on every request. We don't read it,
  // and the call itself raises a "key is not specified" warning under
  // Hono 4.x — see hono-rate-limiter#125.
  return rateLimiter({
    windowMs: getConfig().OPENCRED_RATE_LIMIT_WINDOW_MS,
    limit: getLimit(),
    standardHeaders: "draft-7",
    keyGenerator: deriveRateLimitKey,
    requestPropertyName: "" as unknown as undefined,
    handler: (c, _next, _options) => {
      // The store keeps a `resetTime` on the in-memory client entry, but
      // exposing it through the limit handler requires reading the same
      // store the limiter just wrote to. The library does not surface the
      // entry through the context API, so we approximate `resetTime` as
      // `now + windowMs`. The header is always >=1s, which honours the
      // RFC 6585 Retry-After contract and is good enough operationally —
      // a client that ignores it just keeps getting 429s.
      const resetAt = new Date(Date.now() + getConfig().OPENCRED_RATE_LIMIT_WINDOW_MS);
      // Log at info level (NOT warn) — rate-limit hits are normal under
      // load and warn-level noise drowns the real signal. We log the
      // bucket label only (e.g. "issue"), never the key, never the token.
      getLogger().info({ bucket: label }, "Rate limit exceeded");
      return buildLimitExceededResponse(c, resetAt);
    },
  });
}

/**
 * Mount the three per-tier limiters on the supplied Hono app. Both the
 * legacy and `/v1` path prefixes are wired so issuers using either surface
 * see the same caps.
 *
 * No-ops cleanly when `OPENCRED_RATE_LIMIT_ENABLED=false`.
 */
export function applyRateLimits<E extends { use: (path: string, h: MiddlewareHandler) => unknown }>(
  app: E,
): void {
  const config = getConfig();
  if (!config.OPENCRED_RATE_LIMIT_ENABLED) return;

  const issueLimiter = buildLimiter(() => config.OPENCRED_RATE_LIMIT_ISSUE, "issue");
  const verifyLimiter = buildLimiter(() => config.OPENCRED_RATE_LIMIT_VERIFY, "verify");
  const readLimiter = buildLimiter(() => config.OPENCRED_RATE_LIMIT_READ, "read");

  // Note on Hono path semantics: `app.use("/foo/*", ...)` matches BOTH
  // `/foo/` subpaths AND `/foo` exactly. Registering the bare `/foo`
  // alongside the `/foo/*` form double-counts every request — see the
  // rate-limit test for the proof. We therefore use a single trailing
  // glob and let it cover the base path too.
  //
  // Issue + batch — signing path. The glob also covers the batch
  // progress / results GETs (`/credentials/batch/:jobId(/results)?`).
  app.use("/credentials/issue", issueLimiter);
  app.use("/v1/credentials/issue", issueLimiter);
  app.use("/credentials/batch/*", issueLimiter);
  app.use("/v1/credentials/batch/*", issueLimiter);
  // Bare /credentials/batch is matched by the glob above; no extra mount
  // needed.

  // Verify — read-heavy.
  app.use("/credentials/verify", verifyLimiter);
  app.use("/v1/credentials/verify", verifyLimiter);

  // Read-only public surfaces. `/schemas/*` matches both `/schemas` and
  // `/schemas/:id` (see Hono path-globbing note above).
  app.use("/schemas/*", readLimiter);
  app.use("/v1/schemas/*", readLimiter);
  app.use("/health", readLimiter);
  app.use("/v1/health", readLimiter);
}
