/**
 * DID document export for the Self-Published Keys (did:key) workflow.
 *
 * Sibling to {@link ./did-web-export.ts}. Generates a W3C DID document for
 * a `did:key:z…` identifier so it can be published to DeDi as an
 * attribution record. The DID document we produce here is the same shape
 * as `DIDKeyResolver.resolve()` would synthesise locally — DeDi's public
 * mirror simply caches that synthesis so verifiers can also discover
 * `orgName` / contact metadata alongside it.
 *
 * SECURITY NOTE: Only the public key (as JWK) crosses this boundary. The
 * private key stays in the main process and never appears in either
 * input or output.
 */

import { generateDidWebDocument } from "@opencred/did";
import type { JWK, DIDDocument } from "@opencred/did";

/**
 * Build a DID document for a `did:key` identifier.
 *
 * Implementation note: we deliberately re-use {@link generateDidWebDocument}
 * because the document shape for did:key publishing is identical (controller,
 * verificationMethod with publicKeyJwk, the four relationship arrays). The
 * only thing that differs is the DID identifier itself, which the caller
 * already has from the signer. Keeping these in sync via shared code avoids
 * the trap where did:web and did:key documents drift in subtle ways.
 *
 * @param publicKeyJwk - The issuer's public key in JWK format.
 * @param didKey - The full `did:key:z…` identifier (without the
 *   `#fragment` verification-method suffix).
 * @returns The DID document object, ready to be JSON-serialised.
 */
export function buildDidKeyDocument(publicKeyJwk: JWK, didKey: string): DIDDocument {
  return generateDidWebDocument(didKey, publicKeyJwk);
}

/**
 * Build a JSON-serialised DID document string for a did:key identifier.
 * Mirrors the `did-web-export.ts` API shape so callers can swap between
 * the two branches without restructuring.
 */
export function exportDidKeyDocument(publicKeyJwk: JWK, didKey: string): string {
  return JSON.stringify(buildDidKeyDocument(publicKeyJwk, didKey), null, 2);
}
