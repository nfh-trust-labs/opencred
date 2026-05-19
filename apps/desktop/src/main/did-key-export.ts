/**
 * DID document export for the Self-Published Keys (did:key) workflow.
 *
 * Sibling to {@link ./did-web-export.ts}. Generates a W3C DID document for
 * a `did:key:z…` identifier so it can be published to DeDi as an
 * attribution record. The DID document we produce here is exactly what
 * `DIDKeyResolver.resolve()` would synthesise locally — DeDi's public
 * mirror simply caches that synthesis so verifiers can also discover
 * `orgName` / contact metadata alongside it.
 *
 * SECURITY NOTE: No private key material crosses this boundary — the
 * did:key string itself encodes the public key, and the resolver
 * unpacks it deterministically with no network I/O.
 */

import { DIDKeyResolver } from "@opencred/did";
import type { DIDDocument } from "@opencred/did";

/**
 * Build a DID document for a `did:key` identifier.
 *
 * Delegates to {@link DIDKeyResolver} so the published document is
 * byte-for-byte the one verifiers would synthesise locally: a single
 * `Multikey` verification method whose fragment is the multibase suffix
 * of the DID itself (matching the `verificationMethod` reference that
 * every did:key signer in this codebase puts on credential proofs).
 *
 * @param didKey - The full `did:key:z…` identifier (without the
 *   `#fragment` verification-method suffix).
 * @returns The DID document object, ready to be JSON-serialised.
 */
export async function buildDidKeyDocument(didKey: string): Promise<DIDDocument> {
  const resolver = new DIDKeyResolver();
  const result = await resolver.resolve(didKey);
  if (!result.didDocument) {
    throw new Error(`DIDKeyResolver returned no document for ${didKey}`);
  }
  return result.didDocument;
}

/**
 * Build a JSON-serialised DID document string for a did:key identifier.
 * Mirrors the `did-web-export.ts` API shape so callers can swap between
 * the two branches without restructuring.
 */
export async function exportDidKeyDocument(didKey: string): Promise<string> {
  const doc = await buildDidKeyDocument(didKey);
  return JSON.stringify(doc, null, 2);
}
