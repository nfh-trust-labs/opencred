import { CryptoError } from "@opencred/shared";
import type { SigningAlgorithm } from "./types.js";

/**
 * Map a SigningAlgorithm to the corresponding JWS algorithm identifier.
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
      throw new CryptoError(`Unsupported algorithm for JWS: ${algorithm}`);
  }
}
