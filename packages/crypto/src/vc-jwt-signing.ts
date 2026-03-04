import { SignJWT } from "jose";
import { CryptoError } from "@opencred/shared";
import type { SigningKey, SigningAlgorithm, VcJwtSigningOptions } from "./types.js";

/**
 * Map a SigningAlgorithm to the corresponding JWS algorithm identifier.
 */
function signingAlgorithmToJwsAlg(algorithm: SigningAlgorithm): string {
  switch (algorithm) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "RSA-2048":
    case "RSA-3072":
    case "RSA-4096":
      return "PS256";
    default:
      throw new CryptoError(`Unsupported algorithm for VC-JWT: ${algorithm}`);
  }
}

/**
 * Convert an ISO 8601 date string to a Unix timestamp (seconds).
 */
function isoToUnixTimestamp(isoDate: string): number {
  return Math.floor(new Date(isoDate).getTime() / 1000);
}

/**
 * Build the JWT claims from an unsigned VC (DM 1.1 layout with nested `vc` claim).
 */
function buildVcJwtClaims(unsignedVC: Record<string, unknown>): Record<string, unknown> {
  const claims: Record<string, unknown> = {};

  // iss: from issuer
  const issuer = unsignedVC["issuer"];
  if (issuer) {
    claims.iss = typeof issuer === "string" ? issuer : (issuer as { id: string }).id;
  }

  // sub: from credentialSubject.id
  const subject = unsignedVC["credentialSubject"] as Record<string, unknown> | undefined;
  if (subject?.id) {
    claims.sub = subject.id;
  }

  // jti: from id
  if (unsignedVC["id"]) {
    claims.jti = unsignedVC["id"];
  }

  // nbf: from validFrom or issuanceDate
  const validFrom = (unsignedVC["validFrom"] ?? unsignedVC["issuanceDate"]) as string | undefined;
  if (validFrom) {
    claims.nbf = isoToUnixTimestamp(validFrom);
  }

  // exp: from validUntil or expirationDate
  const validUntil = (unsignedVC["validUntil"] ?? unsignedVC["expirationDate"]) as string | undefined;
  if (validUntil) {
    claims.exp = isoToUnixTimestamp(validUntil);
  }

  // vc: the full credential object (without proof)
  claims.vc = unsignedVC;

  return claims;
}

/**
 * Sign an unsigned VC as a VC-JWT (Delegated Signing).
 *
 * Produces a standard JWT with the `vc` claim containing the credential data
 * per the W3C VC Data Model 1.1 JWT encoding.
 *
 * Header: { "alg": "<algorithm>", "typ": "JWT", "kid": "<verificationMethod>" }
 * Payload: { iss, sub, jti, nbf, exp, vc }
 */
export async function signCredentialVcJwt(
  unsignedVC: Record<string, unknown>,
  signingKey: SigningKey,
  options: VcJwtSigningOptions,
): Promise<string> {
  const alg = signingAlgorithmToJwsAlg(signingKey.algorithm);
  const claims = buildVcJwtClaims(unsignedVC);

  const jwt = await new SignJWT(claims)
    .setProtectedHeader({
      alg,
      typ: "JWT",
      kid: options.verificationMethod,
    })
    .sign(signingKey.privateKey);

  return jwt;
}

/**
 * Prepared VC-JWT proof for two-phase Interface Signing.
 */
export interface VcJwtPreparedProof {
  /** The base64url(header) + "." + base64url(payload) string that must be signed. */
  signingInput: string;
  /** The JWS protected header (for reference). */
  protectedHeader: Record<string, unknown>;
}

/**
 * Prepare a VC-JWT for Interface Signing (Phase 1).
 *
 * Builds the JWT header and payload, returns the signing input that the
 * external signer must sign.
 */
export function prepareVcJwtProof(
  unsignedVC: Record<string, unknown>,
  algorithm: SigningAlgorithm,
  options: VcJwtSigningOptions,
): VcJwtPreparedProof {
  const alg = signingAlgorithmToJwsAlg(algorithm);
  const header = { alg, typ: "JWT", kid: options.verificationMethod };
  const claims = buildVcJwtClaims(unsignedVC);

  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString("base64url");

  return {
    signingInput: `${headerB64}.${payloadB64}`,
    protectedHeader: header,
  };
}

/**
 * Complete a VC-JWT with an external signature (Phase 2).
 *
 * Combines the signing input with the raw signature bytes to produce
 * the final JWT string.
 */
export function completeVcJwtProof(signingInput: string, signatureBytes: Uint8Array): string {
  if (!signingInput.includes(".")) {
    throw new CryptoError("Invalid signing input: expected base64url(header).base64url(payload)");
  }
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");
  return `${signingInput}.${signatureB64}`;
}
