import type { Context, Next } from "hono";
import { validateCapabilityToken, checkScope } from "@opencred/auth";
import { AuthenticationError, AuthorizationError } from "@opencred/shared";

export interface AuthMiddlewareOptions {
  verificationKey: Uint8Array;
  issuer?: string;
  audience?: string;
  algorithms?: string[];
}

export function authMiddleware(options: AuthMiddlewareOptions, requiredScope?: string) {
  return async (c: Context, next: Next) => {
    const authHeader = c.req.header("Authorization");
    if (!authHeader) {
      throw new AuthenticationError("Missing Authorization header");
    }

    const match = authHeader.match(/^Bearer\s+(\S+)$/);
    if (!match) {
      throw new AuthenticationError("Invalid Authorization header format");
    }

    const token = match[1];
    const result = await validateCapabilityToken({
      token,
      verificationKey: options.verificationKey,
      issuer: options.issuer,
      audience: options.audience,
      algorithms: options.algorithms,
    });

    if (!result.valid || !result.payload) {
      throw new AuthenticationError(result.error ?? "Invalid token");
    }

    if (requiredScope && !checkScope(result.payload, requiredScope)) {
      throw new AuthorizationError(`Missing required scope: ${requiredScope}`);
    }

    c.set("tokenPayload", result.payload);
    await next();
  };
}
