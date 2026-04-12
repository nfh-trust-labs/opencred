import { compactVerify, importJWK, type JWK } from "jose";
import type { DIDResolver } from "@opencred/did";
import { DIDJwkResolver } from "@opencred/did";
import { assertJwtSize } from "@opencred/shared";
import type { VerificationCheck } from "./types.js";

/**
 * Allowed JWS signing algorithms for proof verification.
 *
 * Mirrors the algorithms produced by @opencred/crypto for VC signing
 * (see signingAlgorithmToJwsAlg):
 * - ES256 - ECDSA P-256
 * - ES384 - ECDSA P-384
 * - PS256 - RSASSA-PSS with SHA-256 (RSA-2048/3072/4096)
 * - EdDSA - Ed25519
 *
 * Passed to compactVerify as defence-in-depth against algorithm
 * confusion and downgrade attacks. This explicitly rejects
 * alg none (the classic JWS attack vector) and any symmetric
 * HMAC (HS*) algorithm, which are neither produced nor verifiable
 * with an asymmetric public key in this code path.
 */
export const ALLOWED_JWS_ALGORITHMS = ["ES256", "ES384", "PS256", "EdDSA"] as const;

/**
 * Verify a VC-JOSE-COSE JWS compact serialization proof.
 *
 * Resolves the signer's public key from the `kid` header (DID URL),
 * then verifies the JWS signature using the `jose` library.
 *
 * @param jwsString - The JWS compact serialization string (header.payload.signature).
 * @param didResolver - Optional DID resolver; defaults to DIDJwkResolver.
 * @returns VerificationCheck indicating whether the signature is valid.
 */
export async function verifyJwsProof(
  jwsString: string,
  didResolver?: DIDResolver,
): Promise<VerificationCheck> {
  // Reject oversized tokens before any decoding
  assertJwtSize(jwsString);

  // Parse JWS header to get kid
  const parts = jwsString.split(".");
  if (parts.length !== 3) {
    return {
      name: "signature",
      passed: false,
      detail: "Invalid JWS: expected 3 dot-separated parts",
    };
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  } catch {
    return { name: "signature", passed: false, detail: "Failed to decode JWS protected header" };
  }

  const kid = header.kid as string | undefined;
  if (!kid) {
    return { name: "signature", passed: false, detail: "JWS header missing 'kid'" };
  }

  const alg = header.alg as string | undefined;
  if (!alg) {
    return { name: "signature", passed: false, detail: "JWS header missing 'alg'" };
  }

  // Reject any algorithm not on the allowlist. This explicitly rejects
  // the classic alg none attack and any other unexpected algorithm
  // (HS*, ES512, etc.) before the public key is even loaded, closing
  // off algorithm confusion and downgrade attacks at the earliest
  // opportunity.
  if (!(ALLOWED_JWS_ALGORITHMS as readonly string[]).includes(alg)) {
    return {
      name: "signature",
      passed: false,
      detail: `JWS 'alg' not permitted: ${alg}. Allowed: ${ALLOWED_JWS_ALGORITHMS.join(", ")}`,
    };
  }

  // Resolve public key from kid (DID URL)
  const did = kid.split("#")[0];
  const resolver = didResolver ?? new DIDJwkResolver();

  let resolution;
  try {
    resolution = await resolver.resolve(did);
  } catch {
    return { name: "signature", passed: false, detail: "Failed to resolve DID from kid" };
  }

  if (!resolution.didDocument) {
    return { name: "signature", passed: false, detail: "Failed to resolve DID document" };
  }

  const vm = resolution.didDocument.verificationMethod?.find(
    (m) => m.id === kid || m.id === `#${kid.split("#")[1]}`,
  );
  if (!vm?.publicKeyJwk) {
    return {
      name: "signature",
      passed: false,
      detail: "Verification method not found or missing JWK",
    };
  }

  let publicKey;
  try {
    publicKey = await importJWK(vm.publicKeyJwk as JWK, alg);
  } catch {
    return { name: "signature", passed: false, detail: "Failed to import public key from JWK" };
  }

  try {
    // Pass the allowlist to compactVerify as defence-in-depth.
    // Even though we already rejected disallowed algorithms above,
    // supplying the algorithms option ensures jose also enforces it
    // and keeps the constraint live if the code above is ever
    // refactored.
    await compactVerify(jwsString, publicKey, {
      algorithms: ALLOWED_JWS_ALGORITHMS as unknown as string[],
    });
    return { name: "signature", passed: true };
  } catch {
    return { name: "signature", passed: false, detail: "JWS signature verification failed" };
  }
}
