/**
 * Bearer token authentication middleware for the OpenCred server.
 *
 * Auth is REQUIRED for all non-public endpoints. The fail-closed invariant
 * is enforced at config-load time (see loadConfig() in ../config.ts), so by
 * the time a request reaches this middleware exactly one of the following
 * is true:
 *
 *  1. OPENCRED_API_KEY is set — every protected endpoint requires a matching
 *     Bearer token in the Authorization header.
 *  2. OPENCRED_DEV_MODE_NO_AUTH=true is set — auth is bypassed for local
 *     development. The server logged a loud warning at startup, and refused
 *     to start if NODE_ENV=production.
 *
 * Public paths (currently /health and /v1/health) are always reachable without
 * an Authorization header.
 *
 * SECURITY: Uses constant-time comparison to prevent timing attacks.
 */

import { timingSafeEqual } from "node:crypto";
import type { Context, Next } from "hono";
import { getConfig } from "../config.js";
import { AuthenticationError } from "@opencred/shared";

/** Paths that are always reachable without an Authorization header. */
const PUBLIC_PATHS = new Set<string>(["/health", "/v1/health"]);

export async function authMiddleware(c: Context, next: Next): Promise<void> {
  const config = getConfig();

  // Health endpoint is always public — both legacy and /v1 paths.
  if (PUBLIC_PATHS.has(c.req.path)) {
    await next();
    return;
  }

  // Explicit dev-mode opt-out: bypass auth. Config validation already
  // refused to load if this flag is combined with NODE_ENV=production,
  // and a loud warning was emitted at startup.
  if (config.OPENCRED_DEV_MODE_NO_AUTH) {
    await next();
    return;
  }

  // Fail closed: if we got here without an API key, config validation is
  // broken. Reject the request defensively rather than processing it.
  if (!config.OPENCRED_API_KEY) {
    throw new AuthenticationError(
      "Server authentication is not configured. Set OPENCRED_API_KEY before starting the server.",
    );
  }

  const header = c.req.header("Authorization");
  if (!header) {
    throw new AuthenticationError("Missing Authorization header");
  }

  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    throw new AuthenticationError("Invalid Authorization header format");
  }

  const provided = Buffer.from(parts[1]);
  const expected = Buffer.from(config.OPENCRED_API_KEY);

  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new AuthenticationError("Invalid API key");
  }

  await next();
}
