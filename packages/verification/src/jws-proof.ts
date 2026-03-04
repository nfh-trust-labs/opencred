import { compactVerify, importJWK, type JWK } from "jose";
import type { DIDResolver } from "@opencred/did";
import { DIDJwkResolver } from "@opencred/did";
import type { VerificationCheck } from "./types.js";

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
  // Parse JWS header to get kid
  const parts = jwsString.split(".");
  if (parts.length !== 3) {
    return { name: "signature", passed: false, detail: "Invalid JWS: expected 3 dot-separated parts" };
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
    await compactVerify(jwsString, publicKey);
    return { name: "signature", passed: true };
  } catch {
    return { name: "signature", passed: false, detail: "JWS signature verification failed" };
  }
}
