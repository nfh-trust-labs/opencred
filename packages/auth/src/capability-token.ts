import { SignJWT, jwtVerify } from "jose";
import { randomUUID } from "node:crypto";
import { ValidationError } from "@opencred/shared";
import type {
  CapabilityTokenOptions,
  CapabilityTokenPayload,
  TokenValidationOptions,
  TokenValidationResult,
} from "./types.js";

export async function createCapabilityToken(options: CapabilityTokenOptions): Promise<string> {
  const { subject, issuer, audience, expiresInSeconds, scope, namespace, signingKey, algorithm } =
    options;

  if (!scope.length) {
    throw new ValidationError("At least one scope is required");
  }
  if (!namespace) {
    throw new ValidationError("Namespace is required");
  }

  const alg = algorithm ?? (signingKey instanceof Uint8Array ? "HS256" : "ES256");
  const now = Math.floor(Date.now() / 1000);
  const jti = randomUUID();

  const builder = new SignJWT({ scope, namespace })
    .setProtectedHeader({ alg })
    .setIssuedAt(now)
    .setIssuer(issuer)
    .setSubject(subject)
    .setExpirationTime(now + expiresInSeconds)
    .setJti(jti);

  if (audience) {
    builder.setAudience(audience);
  }

  return builder.sign(signingKey);
}

export async function validateCapabilityToken(
  options: TokenValidationOptions,
): Promise<TokenValidationResult> {
  const { token, verificationKey, issuer, audience, algorithms } = options;

  try {
    const verifyOptions: {
      issuer?: string;
      audience?: string;
      algorithms?: string[];
    } = {};
    if (issuer) verifyOptions.issuer = issuer;
    if (audience) verifyOptions.audience = audience;
    if (algorithms) verifyOptions.algorithms = algorithms;

    const { payload } = await jwtVerify(token, verificationKey, verifyOptions);

    if (!payload.scope || !Array.isArray(payload.scope)) {
      return { valid: false, error: "Missing or invalid scope claim" };
    }
    if (!payload.namespace || typeof payload.namespace !== "string") {
      return { valid: false, error: "Missing or invalid namespace claim" };
    }

    if (!payload.sub || typeof payload.sub !== "string") {
      return { valid: false, error: "Missing or invalid sub claim" };
    }
    if (!payload.iss || typeof payload.iss !== "string") {
      return { valid: false, error: "Missing or invalid iss claim" };
    }
    if (typeof payload.exp !== "number") {
      return { valid: false, error: "Missing or invalid exp claim" };
    }
    if (typeof payload.iat !== "number") {
      return { valid: false, error: "Missing or invalid iat claim" };
    }
    if (!payload.jti || typeof payload.jti !== "string") {
      return { valid: false, error: "Missing or invalid jti claim" };
    }

    return {
      valid: true,
      payload: {
        sub: payload.sub,
        iss: payload.iss,
        aud: payload.aud as string | undefined,
        exp: payload.exp,
        iat: payload.iat,
        jti: payload.jti,
        scope: payload.scope as string[],
        namespace: payload.namespace as string,
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Token validation failed";
    return { valid: false, error: message };
  }
}

export function checkScope(payload: CapabilityTokenPayload, requiredScope: string): boolean {
  return payload.scope.includes(requiredScope);
}
