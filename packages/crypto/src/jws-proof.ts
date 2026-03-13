import { CompactSign } from "jose";
import { CryptoError } from "@opencred/shared";
import type { JwsProofOptions, JwsPreparedProof, SigningKey, SigningAlgorithm, ProofFormat, SdJwtVcSigningOptions } from "./types.js";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import { signingAlgorithmToJwsAlg } from "./alg-mapping.js";

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

  const alg = signingAlgorithmToJwsAlg(signingKey.algorithm);
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
  const alg = signingAlgorithmToJwsAlg(algorithm as SigningAlgorithm);
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
 * Return the default proof format for a given signing algorithm.
 */
export function defaultProofFormat(_algorithm: SigningAlgorithm): ProofFormat {
  return "vc-jwt";
}

/**
 * Auto-dispatch credential signing to the appropriate proof format.
 *
 * When `proofFormat` is omitted, defaults to VC-JWT for all algorithms.
 */
export async function signCredentialAuto(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: {
    verificationMethod: string;
    proofPurpose?: string;
    proofFormat?: ProofFormat;
    sdJwtOptions?: SdJwtVcSigningOptions;
  },
): Promise<string | VerifiableCredential> {
  const format = options.proofFormat ?? defaultProofFormat(signingKey.algorithm);

  switch (format) {
    case "data-integrity": {
      const { signCredential } = await import("./data-integrity.js");
      return signCredential(unsignedVC, signingKey, {
        verificationMethod: options.verificationMethod,
        proofPurpose: options.proofPurpose ?? "assertionMethod",
      });
    }
    case "eddsa-di": {
      const { signCredentialEdDsa } = await import("./eddsa-data-integrity.js");
      return signCredentialEdDsa(unsignedVC, signingKey, {
        verificationMethod: options.verificationMethod,
        proofPurpose: options.proofPurpose ?? "assertionMethod",
      });
    }
    case "jws":
      return signCredentialJws(unsignedVC, signingKey, {
        verificationMethod: options.verificationMethod,
      });
    case "vc-jwt": {
      const { signCredentialVcJwt } = await import("./vc-jwt-signing.js");
      return signCredentialVcJwt(unsignedVC as unknown as Record<string, unknown>, signingKey, {
        verificationMethod: options.verificationMethod,
      });
    }
    case "sd-jwt-vc": {
      if (!options.sdJwtOptions) {
        throw new CryptoError("sdJwtOptions is required for sd-jwt-vc proof format");
      }
      const { signCredentialSdJwtVc } = await import("./sd-jwt-vc-signing.js");
      return signCredentialSdJwtVc(unsignedVC, signingKey, options.sdJwtOptions);
    }
  }
}
