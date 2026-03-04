import { randomBytes, createHash } from "node:crypto";
import { SignJWT } from "jose";
import { CryptoError } from "@opencred/shared";
import type { UnsignedCredential } from "@opencred/vc-core";
import type { SigningKey, SdJwtVcSigningOptions, SdJwtVcPreparedProof } from "./types.js";
import { signingAlgorithmToJwsAlg } from "./alg-mapping.js";

/**
 * Create a single SD-JWT disclosure.
 * Format: base64url(JSON.stringify([salt, claimName, claimValue]))
 * Salt is 16 bytes from CSPRNG (crypto.randomBytes).
 */
function createDisclosure(claimName: string, claimValue: unknown): string {
  const salt = randomBytes(16).toString("base64url");
  const disclosure = JSON.stringify([salt, claimName, claimValue]);
  return Buffer.from(disclosure).toString("base64url");
}

/**
 * Compute the SHA-256 digest of a disclosure string, returned as base64url.
 * The hash is computed over the base64url-encoded disclosure string itself (ASCII bytes).
 */
function computeDisclosureDigest(disclosureB64: string): string {
  const hash = createHash("sha256").update(disclosureB64, "ascii").digest();
  return Buffer.from(hash).toString("base64url");
}

/**
 * Build the SD-JWT VC payload from an unsigned VC and signing options.
 * Extracts selectively disclosable claims, creates disclosures, and builds the _sd array.
 *
 * Returns the JWT payload and the list of base64url-encoded disclosures.
 */
function buildSdJwtVcPayload(
  unsignedVC: UnsignedCredential,
  options: SdJwtVcSigningOptions,
): { payload: Record<string, unknown>; disclosures: string[] } {
  const issuer = typeof unsignedVC.issuer === "string"
    ? unsignedVC.issuer
    : unsignedVC.issuer.id;

  // Start with the base JWT payload
  const payload: Record<string, unknown> = {
    iss: issuer,
    vct: options.vct,
    iat: Math.floor(new Date(options.created ?? new Date().toISOString()).getTime() / 1000),
  };

  // Add nbf from validFrom
  if (unsignedVC.validFrom) {
    payload.nbf = Math.floor(new Date(unsignedVC.validFrom).getTime() / 1000);
  }

  // Add exp from validUntil
  if (unsignedVC.validUntil) {
    payload.exp = Math.floor(new Date(unsignedVC.validUntil).getTime() / 1000);
  }

  // Add sub from credentialSubject.id
  if (unsignedVC.credentialSubject.id) {
    payload.sub = unsignedVC.credentialSubject.id;
  }

  // Add holder key binding if provided
  if (options.holderPublicKeyJwk) {
    payload.cnf = { jwk: options.holderPublicKeyJwk };
  }

  // Collect all credential subject claims (excluding 'id' which goes to 'sub')
  const subjectClaims: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(unsignedVC.credentialSubject)) {
    if (key !== "id") {
      subjectClaims[key] = value;
    }
  }

  // Build disclosures and _sd array for selectively disclosable claims
  const disclosures: string[] = [];
  const sdDigests: string[] = [];
  const sdClaimSet = new Set(options.selectiveDisclosureClaims);

  for (const [key, value] of Object.entries(subjectClaims)) {
    if (sdClaimSet.has(key)) {
      // Make this claim selectively disclosable
      const disclosure = createDisclosure(key, value);
      disclosures.push(disclosure);
      sdDigests.push(computeDisclosureDigest(disclosure));
    } else {
      // Include directly in the payload
      payload[key] = value;
    }
  }

  if (sdDigests.length > 0) {
    payload._sd = sdDigests;
    payload._sd_alg = "sha-256";
  }

  return { payload, disclosures };
}

/**
 * Assemble the final SD-JWT VC string from a JWT and disclosures.
 * Format: <jwt>~<disclosure1>~<disclosure2>~...~
 */
function assembleSdJwtVc(jwt: string, disclosures: string[]): string {
  if (disclosures.length === 0) {
    return `${jwt}~`;
  }
  return `${jwt}~${disclosures.join("~")}~`;
}

/**
 * Sign an unsigned VC as an SD-JWT VC (Delegated Signing path).
 *
 * The private key is available server-side. This produces the complete
 * SD-JWT VC string: <issuer-jwt>~<disclosure1>~<disclosure2>~...~
 */
export async function signCredentialSdJwtVc(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: SdJwtVcSigningOptions,
): Promise<string> {
  const alg = signingAlgorithmToJwsAlg(signingKey.algorithm);
  const { payload, disclosures } = buildSdJwtVcPayload(unsignedVC, options);

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg,
      typ: "vc+sd-jwt",
      kid: options.verificationMethod,
    })
    .sign(signingKey.privateKey);

  return assembleSdJwtVc(jwt, disclosures);
}

/**
 * Prepare an SD-JWT VC proof for two-phase Interface Signing (Phase 1).
 *
 * Builds the JWT payload and disclosures, returns the signing input
 * (base64url(header).base64url(payload)) that must be signed externally.
 */
export function prepareSdJwtVcProof(
  unsignedVC: UnsignedCredential,
  algorithm: string,
  options: SdJwtVcSigningOptions,
): SdJwtVcPreparedProof {
  const alg = signingAlgorithmToJwsAlg(algorithm as SigningKey["algorithm"]);
  const { payload, disclosures } = buildSdJwtVcPayload(unsignedVC, options);

  const header = { alg, typ: "vc+sd-jwt", kid: options.verificationMethod };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");

  return {
    signingInput: `${headerB64}.${payloadB64}`,
    disclosures,
    algorithm: alg,
  };
}

/**
 * Complete an SD-JWT VC proof with the external signature (Phase 2).
 *
 * Combines the signing input with the signature bytes and disclosures
 * to produce the final SD-JWT VC string.
 */
export function completeSdJwtVcProof(
  signingInput: string,
  signatureBytes: Uint8Array,
  disclosures: string[],
): string {
  if (!signingInput.includes(".")) {
    throw new CryptoError("Invalid signing input: expected base64url(header).base64url(payload)");
  }
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");
  const jwt = `${signingInput}.${signatureB64}`;
  return assembleSdJwtVc(jwt, disclosures);
}
