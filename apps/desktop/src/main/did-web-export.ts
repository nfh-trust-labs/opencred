/**
 * DID document export for the Self-Published Keys (did:web) workflow.
 *
 * Generates a W3C DID document from an issuer's public key JWK and domain,
 * suitable for hosting at `.well-known/did.json`.
 *
 * SECURITY NOTE: Only the public key is used — the private key never
 * appears in or passes through this module.
 */

import { encodeDidWeb, generateDidWebDocument } from "@opencred/did";
import type { JWK } from "@opencred/did";

/**
 * Build a JSON-serialised DID document for a did:web identifier.
 *
 * @param publicKeyJwk - The issuer's public key in JWK format.
 * @param domain - The domain where the DID document will be hosted.
 * @returns Pretty-printed JSON string of the DID document.
 */
export function exportDidDocument(publicKeyJwk: JWK, domain: string): string {
  const did = encodeDidWeb(domain);
  const doc = generateDidWebDocument(did, publicKeyJwk);
  return JSON.stringify(doc, null, 2);
}
