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
 * Caching: when a {@link Signer} is in scope, callers should prefer
 * {@link buildDidKeyDocumentForSigner} so repeated exports (e.g. re-publishing
 * to DeDi after an outage) hit the process-wide signer-DID-document cache
 * keyed on the public-key fingerprint. The DID-string-only overload exists
 * for paths where only the DID string is available (e.g. legacy callers
 * loading a persisted DID without re-instantiating the Signer).
 *
 * SECURITY NOTE: No private key material crosses this boundary — the
 * did:key string itself encodes the public key, and the resolver
 * unpacks it deterministically with no network I/O.
 */

import { DIDKeyResolver } from "@opencred/did";
import type { DIDDocument } from "@opencred/did";
import type { Signer } from "@opencred/signing/types";
import { getCachedSignerDidDocument } from "@opencred/signing/signer-did-cache";

/**
 * Build a DID document for a `did:key` identifier from a Signer.
 *
 * This is the cached path: routes through {@link getCachedSignerDidDocument},
 * which memoises the result by the signer's SHA-256 public-key fingerprint.
 * A subsequent call with the same signer returns the same DIDDocument
 * reference without re-invoking the resolver — useful when an issuer
 * republishes their DID to DeDi after a transient outage, or in the
 * server's batch path where every row's `verificationMethod` is the same
 * signer's `id`.
 *
 * @param signer - The active signer.
 * @returns The cached or freshly-resolved DID document.
 */
export async function buildDidKeyDocumentForSigner(signer: Signer): Promise<DIDDocument> {
  return getCachedSignerDidDocument(signer);
}

/**
 * Build a DID document for a `did:key` identifier.
 *
 * Delegates to {@link DIDKeyResolver} so the published document is
 * byte-for-byte the one verifiers would synthesise locally: a single
 * `Multikey` verification method whose fragment is the multibase suffix
 * of the DID itself (matching the `verificationMethod` reference that
 * every did:key signer in this codebase puts on credential proofs).
 *
 * Uncached fallback: this overload is for callers that have only the DID
 * string in hand (no `Signer`). When a Signer is available, prefer
 * {@link buildDidKeyDocumentForSigner} so the result is cached across
 * subsequent calls.
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
 *
 * Two overloads:
 *   - pass a {@link Signer} to route through the signer-DID-document cache;
 *   - pass a DID string for the uncached fallback path.
 */
export async function exportDidKeyDocument(input: string | Signer): Promise<string> {
  const doc =
    typeof input === "string"
      ? await buildDidKeyDocument(input)
      : await buildDidKeyDocumentForSigner(input);
  return JSON.stringify(doc, null, 2);
}
