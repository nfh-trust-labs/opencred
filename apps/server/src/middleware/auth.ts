/**
 * Bearer token authentication middleware for the OpenCred server.
 *
 * If an API key is configured via environment, all requests (except /health)
 * must provide a matching Bearer token in the Authorization header.
 *
 * If no API key is configured, authentication is disabled.
 *
 * SECURITY: Uses constant-time comparison to prevent timing attacks.
 */

import { timingSafeEqual } from "node:crypto";
import type { Context, Next } from "hono";
import { getConfig } from "../config.js";
import { AuthenticationError } from "@opencred/shared";

export async function authMiddleware(c: Context, next: Next): Promise<void> {
  const config = getConfig();

  // Skip auth if no key is configured
  if (!config.OPENCRED_API_KEY) {
    await next();
    return;
  }

  // Health endpoint is always public
  if (c.req.path === "/health") {
    await next();
    return;
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
