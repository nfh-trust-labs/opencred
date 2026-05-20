/**
 * In-process DID document cache for active signers.
 *
 * Why this exists
 * ----------------
 * A server with a single active signer was re-deriving the issuer's
 * DID document on every credential-issuance call. For `did:key` and
 * `did:jwk` the document is a pure function of the DID identifier —
 * no network I/O, but base58btc / base64url decoding plus a fresh
 * object allocation per call. The cost is small per call (~milliseconds
 * on a software-key path) but multiplied by 1000-row batches it adds up.
 *
 * Scope of the cache
 * ------------------
 * - Keyed on the signer's public-key fingerprint (`signer.metadata.fingerprint`,
 *   a SHA-256 of the SPKI-encoded public key). Two signers with the same
 *   public key would share an entry — that is correct: their DID document
 *   is by definition identical for `did:key` / `did:jwk`.
 * - Value is a {@link DIDDocument} object. Callers MUST treat it as
 *   read-only — the cache hands out the same reference on each hit.
 * - In-process `Map`. No TTL. No Redis. Single-signer servers churn one
 *   entry; multi-signer development hosts churn a handful. If the active
 *   signer rotates, the old entry can stay — old keys aren't used to sign
 *   new credentials, and a stale entry costs ~1 KiB of memory at worst.
 *
 * Security invariants (CLAUDE.md)
 * -------------------------------
 * - The cache stores ONLY the public DID document — never any private key
 *   material. Cache keys are SHA-256 fingerprints of public keys.
 * - Nothing in this module logs the cache key or value at any level beyond
 *   `debug`, and even there we log only the fingerprint string (already
 *   safe to display per `Signer.metadata.fingerprint`).
 */

import { DIDKeyResolver, DIDJwkResolver, type DIDDocument } from "@opencred/did";
import { CryptoError } from "@opencred/shared";
import type { Signer } from "./types.js";

/**
 * Singleton cache mapping `Signer.metadata.fingerprint` → DIDDocument.
 *
 * Module-scope so all callers within the same process share entries.
 * A fresh `Map` is created at module load; tests that need isolation
 * can call {@link resetSignerDidDocumentCache}.
 */
const cache: Map<string, DIDDocument> = new Map();

/**
 * Resolve the DID document for a given {@link Signer}, using an in-process
 * memoization cache keyed on the signer's public-key fingerprint.
 *
 * On a cache hit, returns the previously-resolved document reference
 * directly — no allocation, no resolver call. On a cache miss, invokes the
 * `did:key` or `did:jwk` resolver (chosen from the signer's `id` prefix)
 * to synthesise the document locally, stores it, and returns it.
 *
 * The returned document is conceptually immutable from the caller's
 * perspective; do not mutate it. If you need a deep copy (e.g. to append
 * `service` entries), use `structuredClone(doc)` at the call site.
 *
 * For DIDs whose document cannot be synthesised offline (e.g. `did:web`),
 * this helper falls through to the resolver but the document is NOT
 * cached: external resolution may have a TTL of its own, and this cache
 * has no eviction policy.
 *
 * @param signer - The active signer whose DID document is needed.
 * @returns The cached or freshly-resolved DID document.
 * @throws {CryptoError} if the DID method is unsupported by this cache.
 */
export async function getCachedSignerDidDocument(signer: Signer): Promise<DIDDocument> {
  const cacheKey = signer.metadata.fingerprint;
  const hit = cache.get(cacheKey);
  if (hit) {
    return hit;
  }

  // The signer's `id` is `<did>#<verificationMethod-fragment>`. Strip the
  // fragment to recover the base DID for the resolver call.
  const did = signer.id.split("#")[0];
  const doc = await resolveDidDocument(did);
  cache.set(cacheKey, doc);
  return doc;
}

/**
 * Resolve a DID document offline for `did:key` / `did:jwk` identifiers.
 *
 * Network-resolved DID methods (e.g. `did:web`) are intentionally not
 * supported here — they need SSRF-safe HTTP resolution which lives in
 * the verification path, not the signer cache.
 */
async function resolveDidDocument(did: string): Promise<DIDDocument> {
  if (did.startsWith("did:key:")) {
    const result = await new DIDKeyResolver().resolve(did);
    if (!result.didDocument) {
      throw new CryptoError(`DIDKeyResolver returned no document for ${did}`);
    }
    return result.didDocument;
  }
  if (did.startsWith("did:jwk:")) {
    const result = await new DIDJwkResolver().resolve(did);
    if (!result.didDocument) {
      throw new CryptoError(`DIDJwkResolver returned no document for ${did}`);
    }
    return result.didDocument;
  }
  throw new CryptoError(
    `Cannot synthesise DID document offline for ${did}: only did:key and did:jwk are supported by getCachedSignerDidDocument`,
  );
}

/**
 * Returns the number of entries currently held in the cache. Exposed for
 * tests that want to assert cache-hit/miss behaviour without poking at
 * the module's private `Map`.
 */
export function signerDidDocumentCacheSize(): number {
  return cache.size;
}

/**
 * Clear the cache. Used by tests that need isolation between cases; not
 * intended for production code paths. Cache entries hold only public
 * material, so clearing is always safe.
 */
export function resetSignerDidDocumentCache(): void {
  cache.clear();
}
