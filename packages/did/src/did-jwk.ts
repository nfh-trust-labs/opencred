/**
 * did:jwk resolution — encodes a JWK as a DID identifier.
 *
 * Used for RSA keys where did:key is draft-only and produces very long identifiers.
 * EC keys continue using did:key.
 *
 * Spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
 */

import { DIDResolutionError } from "@opencred/shared";
import type { DIDDocument, DIDResolutionResult, JWK, VerificationMethod } from "./types.js";
import type { DIDResolver } from "./resolver.js";

/**
 * Encode a JWK as a did:jwk identifier.
 *
 * @param jwk - The public JWK (must not contain private components).
 * @returns The did:jwk string (e.g., `did:jwk:<base64url(JSON)>`).
 */
export function encodeDidJwk(jwk: JWK): string {
  // Strip private components for safety
  const publicJwk = { ...jwk };
  delete publicJwk.d;
  const json = JSON.stringify(publicJwk);
  const encoded = Buffer.from(json).toString("base64url");
  return `did:jwk:${encoded}`;
}

/**
 * Get the verification method ID for a did:jwk.
 * Per spec, the fragment is always "#0".
 */
export function didJwkVerificationMethodId(did: string): string {
  return `${did}#0`;
}

/**
 * Resolve a did:jwk to a DID document.
 */
export class DIDJwkResolver implements DIDResolver {
  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }

    const parts = did.split(":");
    if (parts.length !== 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }

    if (parts[1] !== "jwk") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }

    const encoded = parts[2];
    if (!encoded) {
      throw new DIDResolutionError("Missing JWK data in did:jwk");
    }

    let jwk: JWK;
    try {
      const json = Buffer.from(encoded, "base64url").toString("utf-8");
      jwk = JSON.parse(json) as JWK;
    } catch {
      throw new DIDResolutionError("Failed to decode JWK from did:jwk");
    }

    if (!jwk.kty) {
      throw new DIDResolutionError("Decoded JWK missing required 'kty' field");
    }

    const verificationMethodId = `${did}#0`;

    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: did,
      publicKeyJwk: jwk,
    };

    const didDocument: DIDDocument = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
      ],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityInvocation: [verificationMethodId],
      capabilityDelegation: [verificationMethodId],
    };

    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
}
