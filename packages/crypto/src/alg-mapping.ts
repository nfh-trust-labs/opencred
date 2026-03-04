import type { SigningAlgorithm } from "./types.js";

/**
 * Map OpenCred SigningAlgorithm to JWS algorithm identifier.
 */
export function signingAlgorithmToJwsAlg(algorithm: SigningAlgorithm): string {
  switch (algorithm) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "RSA-2048":
    case "RSA-3072":
    case "RSA-4096":
      return "PS256";
    case "Ed25519":
      return "EdDSA";
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}
