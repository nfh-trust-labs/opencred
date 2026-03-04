import { CompactSign } from "jose";
import { CryptoError } from "@opencred/shared";
import type { JwsProofOptions, JwsPreparedProof, SigningKey } from "./types.js";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";

/**
 * Map RSA key sizes to JWS algorithms.
 * All RSA keys use RSASSA-PSS (PS256/PS384/PS512).
 */
function rsaAlgorithm(algorithm: string): string {
  switch (algorithm) {
    case "RSA-2048":
    case "RSA-3072":
      return "PS256";
    case "RSA-4096":
      return "PS256";
    default:
      throw new CryptoError(`Unsupported RSA algorithm: ${algorithm}`);
  }
}

/**
 * Sign an unsigned VC as a JWS compact string (for RSA keys).
 *
 * The result is a three-part compact JWS: base64url(header).base64url(payload).base64url(signature)
 * Header includes: { "alg": "PS256", "kid": "<verificationMethod>" }
 * Payload: unsigned VC JSON
 */
export async function signCredentialJws(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: JwsProofOptions,
): Promise<string> {
  if (!signingKey.algorithm.startsWith("RSA")) {
    throw new CryptoError("signCredentialJws only supports RSA keys");
  }

  const alg = rsaAlgorithm(signingKey.algorithm);
  const payload = new TextEncoder().encode(JSON.stringify(unsignedVC));
  const jws = await new CompactSign(payload)
    .setProtectedHeader({ alg, kid: options.verificationMethod })
    .sign(signingKey.privateKey);
  return jws;
}

/**
 * Prepare a JWS proof for two-phase Interface Signing.
 *
 * Returns the signing input (base64url(header).base64url(payload))
 * that the external signer must sign. The external signer computes
 * the signature over these bytes and returns the raw signature.
 */
export function prepareJwsProof(
  unsignedVC: UnsignedCredential,
  algorithm: string,
  options: JwsProofOptions,
): JwsPreparedProof {
  const alg = algorithm.startsWith("RSA") ? rsaAlgorithm(algorithm) : algorithm;
  const header = { alg, kid: options.verificationMethod };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
  return {
    signingInput: `${headerB64}.${payloadB64}`,
    protectedHeader: header,
  };
}

/**
 * Complete a JWS proof with the external signature.
 *
 * Combines the signing input (header.payload) with the signature bytes
 * to produce the final JWS compact serialization string.
 */
export function completeJwsProof(signingInput: string, signatureBytes: Uint8Array): string {
  if (!signingInput.includes(".")) {
    throw new CryptoError("Invalid signing input: expected base64url(header).base64url(payload)");
  }
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");
  return `${signingInput}.${signatureB64}`;
}

/**
 * Auto-dispatch: EC keys use Data Integrity proofs, RSA keys use JWS.
 *
 * Returns a JWS compact string for RSA keys, or a VerifiableCredential
 * object with embedded Data Integrity proof for EC keys.
 */
export async function signCredentialAuto(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: { verificationMethod: string; proofPurpose?: string },
): Promise<string | VerifiableCredential> {
  if (signingKey.algorithm.startsWith("RSA")) {
    return signCredentialJws(unsignedVC, signingKey, {
      verificationMethod: options.verificationMethod,
    });
  }
  // EC: use Data Integrity
  const { signCredential } = await import("./data-integrity.js");
  return signCredential(unsignedVC, signingKey, {
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose ?? "assertionMethod",
  });
}
