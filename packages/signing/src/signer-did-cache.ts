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
 * - LRU-capped Map (default 256 entries, configurable via
 *   `OPENCRED_SIGNER_DID_CACHE_SIZE`). At the cap, the least-recently-used
 *   entry is evicted on the next miss. Entries hold only public material
 *   (~1 KiB each) so the worst-case memory footprint is bounded at
 *   `cap * 1 KiB ≈ 256 KiB`.
 * - In-process. No TTL — DID-key / DID-jwk documents are pure functions of
 *   the DID identifier and never go stale. No Redis — entries are cheap to
 *   re-derive on a fresh worker, no need to share across processes.
 *
 * Eviction order
 * --------------
 * `Map` preserves insertion order in JavaScript. We exploit this for the
 * LRU: on a cache hit we `delete` the entry and re-`set` it, which moves
 * it to the end (most-recently-used position). On a miss with the cache
 * at capacity, we delete the FIRST entry returned by `keys()` (the
 * least-recently-used). This gives O(1) hit/miss and O(1) eviction
 * without pulling in a third-party LRU package.
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
 * Default LRU cap when no `OPENCRED_SIGNER_DID_CACHE_SIZE` is set.
 *
 * 256 is enough headroom for a multi-tenant Docker deployment that
 * rotates between dozens of signer keys without thrashing, while staying
 * cheap on a single-signer server where the cap is never reached (one
 * entry, 1 KiB). At ~1 KiB per DID document, 256 entries cap memory at
 * ~256 KiB even when fully populated.
 */
const DEFAULT_MAX_SIZE = 256;

/**
 * Read the LRU cap from `OPENCRED_SIGNER_DID_CACHE_SIZE` (positive int)
 * with a fall-back to {@link DEFAULT_MAX_SIZE}. Exported for tests.
 *
 * A value of `0` or a non-parseable / negative value falls back to the
 * default — a cap of 0 would defeat the cache entirely, and silently
 * accepting that as "no caching" would mask config bugs.
 */
export function resolveSignerDidCacheMaxSize(): number {
  const raw = process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
  if (raw === undefined || raw === "") {
    return DEFAULT_MAX_SIZE;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isFinite(parsed) && parsed >= 1) {
    return parsed;
  }
  return DEFAULT_MAX_SIZE;
}

/**
 * The cap is captured at module load. Tests that need to override it
 * call {@link resetSignerDidDocumentCache} after mutating the env var.
 */
let maxSize = resolveSignerDidCacheMaxSize();

/**
 * Singleton cache mapping `Signer.metadata.fingerprint` → DIDDocument.
 *
 * Module-scope so all callers within the same process share entries.
 * A fresh `Map` is created at module load; tests that need isolation
 * can call {@link resetSignerDidDocumentCache}.
 *
 * Iteration order is insertion order per the ECMAScript spec — we
 * use that to implement the LRU policy without an auxiliary list.
 */
const cache: Map<string, DIDDocument> = new Map();

/**
 * Resolve the DID document for a given {@link Signer}, using an in-process
 * memoization cache keyed on the signer's public-key fingerprint.
 *
 * On a cache hit, returns the previously-resolved document reference
 * directly — no allocation, no resolver call — and moves the entry to the
 * most-recently-used position. On a cache miss, invokes the `did:key` or
 * `did:jwk` resolver (chosen from the signer's `id` prefix) to synthesise
 * the document locally, evicts the least-recently-used entry if the cap
 * is reached, stores the new doc, and returns it.
 *
 * The returned document is conceptually immutable from the caller's
 * perspective; do not mutate it. If you need a deep copy (e.g. to append
 * `service` entries), use `structuredClone(doc)` at the call site.
 *
 * For DIDs whose document cannot be synthesised offline (e.g. `did:web`),
 * this helper falls through to the resolver but the document is NOT
 * cached: external resolution may have a TTL of its own, and this cache
 * has no TTL.
 *
 * @param signer - The active signer whose DID document is needed.
 * @returns The cached or freshly-resolved DID document.
 * @throws {CryptoError} if the DID method is unsupported by this cache.
 */
export async function getCachedSignerDidDocument(signer: Signer): Promise<DIDDocument> {
  const cacheKey = signer.metadata.fingerprint;
  const hit = cache.get(cacheKey);
  if (hit) {
    // Move to MRU position by re-inserting. `Map.set` on an existing
    // key would leave the insertion position unchanged in V8 — so we
    // delete first to force the entry to the tail of the iteration
    // order. This is the cheapest way to maintain LRU semantics with
    // a plain `Map`.
    cache.delete(cacheKey);
    cache.set(cacheKey, hit);
    return hit;
  }

  // The signer's `id` is `<did>#<verificationMethod-fragment>`. Strip the
  // fragment to recover the base DID for the resolver call.
  const did = signer.id.split("#")[0];
  const doc = await resolveDidDocument(did);

  // Enforce LRU cap. We evict BEFORE insertion so the post-condition is
  // `cache.size <= maxSize`. If the cap shrinks at runtime (e.g. a test
  // resets the env var and reloads), the `while` loop will catch up by
  // evicting multiple entries.
  while (cache.size >= maxSize) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) {
      // Defensive: `cache.size >= maxSize` implies at least one key. If
      // the iterator returns undefined, the cache is empty and we have
      // nothing to evict — break out to avoid an infinite loop.
      break;
    }
    cache.delete(oldest);
  }

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
 * Returns the LRU cap currently in effect. Exposed for tests and for
 * `/metrics`-style operator dashboards that want to surface the limit.
 */
export function signerDidDocumentCacheMaxSize(): number {
  return maxSize;
}

/**
 * Clear the cache. Used by tests that need isolation between cases; not
 * intended for production code paths. Cache entries hold only public
 * material, so clearing is always safe.
 *
 * Also re-reads `OPENCRED_SIGNER_DID_CACHE_SIZE` so tests that mutate the
 * env var pick up the new cap without re-importing the module.
 */
export function resetSignerDidDocumentCache(): void {
  cache.clear();
  maxSize = resolveSignerDidCacheMaxSize();
}
