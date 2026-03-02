import type { Context } from "hono";

/**
 * Derives a per-namespace rate-limit key from the request context.
 *
 * Priority:
 * 1. JWT `sub` claim (set by auth middleware) → `ns:<sub>`
 * 2. Bearer token prefix (first 16 chars)     → `tok:<prefix>`
 * 3. Fallback for anonymous requests          → `anon:credentials`
 */
export function namespaceRateLimitKey(c: Context): string {
  const ns = c.get("jwtPayload")?.sub as string | undefined;
  if (ns) return `ns:${ns}`;

  const authHeader = c.req.header("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7, 23);
    if (token) return `tok:${token}`;
  }

  return `anon:credentials`;
}
