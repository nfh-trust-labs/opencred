/**
 * DeDi-backed fallback resolver for did:web.
 *
 * Plugs into `DIDWebResolver`'s optional `fallback` constructor argument
 * (see `@opencred/did`). When canonical HTTPS resolution of a
 * `did:web:...` document fails — network error, 404, DNS hiccup — the
 * resolver consults DeDi's `public_key_registry` for a record matching
 * the input DID. If found, the record's stored DID document is returned
 * in the standard `DIDResolutionResult` shape; if not, the fallback
 * returns `null` and the resolver throws the original HTTP error.
 *
 * **SSRF safety.** `DIDWebResolver` never invokes the fallback when
 * canonical resolution failed due to an SSRF guard rejection — that
 * decision is enforced in the resolver itself, not here. The fallback
 * is only consulted on genuine "the canonical endpoint is unreachable"
 * errors, so a DeDi-anchored response can't be used to bypass private-IP
 * checks on the caller's behalf.
 *
 * **What this enables.** An issuer who has published their DID document
 * to DeDi via `POST /v1/keys/publish` can stop serving the canonical
 * `.well-known/did.json` from a webserver entirely, and DeDi acts as
 * the discovery layer. Verifiers wired with this fallback will resolve
 * the DID through DeDi whenever the HTTPS endpoint is unreachable —
 * the same `assertionMethod` keys, the same signatures, just a
 * different host serving the document.
 *
 * @example
 * ```ts
 * import { DIDWebResolver } from "@opencred/did";
 * import { DeDiClient, createDeDiDIDWebFallback } from "@opencred/dedi-client";
 *
 * const dediClient = new DeDiClient(...);
 * const fallback = createDeDiDIDWebFallback(dediClient);
 * const resolver = new DIDWebResolver(fallback);
 * ```
 */

import type { DIDDocument, DIDResolutionResult, DIDWebFallbackResolver } from "@opencred/did";

import type { DeDiClient } from "./client.js";

/**
 * Wrap a `DeDiClient` into a `DIDWebFallbackResolver` suitable for
 * `DIDWebResolver`.
 *
 * The returned function:
 * - Calls `client.resolveDID(did)` to look up the record in
 *   `public_key_registry` under the client's configured namespace.
 * - Maps the resulting `{did, document, resolvedAt}` record into a
 *   standard `DIDResolutionResult`, populating
 *   `didDocumentMetadata.resolvedAt` from the record so callers can
 *   see when DeDi last touched the entry.
 * - Returns `null` (not throws) for any DeDi-side failure — that lets
 *   the resolver re-raise the original HTTPS error, which is almost
 *   always more actionable for the user than a generic "DeDi didn't
 *   know about this DID" message. The thrown error is logged by the
 *   DeDi client's own observability — debug-level only, no PII.
 *
 * The returned function holds a reference to `client`. The client's
 * configured namespace at call time is what gets queried; if the
 * caller wants per-DID namespace selection, write a custom fallback.
 */
export function createDeDiDIDWebFallback(client: DeDiClient): DIDWebFallbackResolver {
  return async (did: string): Promise<DIDResolutionResult | null> => {
    try {
      const record = await client.resolveDID(did);
      // `record.document` is typed `unknown` in the DeDi adapter — it
      // came over the wire from another service, so we treat it as
      // opaque until we've sanity-checked the shape. The DID-document
      // contract is enforced by the downstream verifier; here we only
      // need to confirm we have an object before wrapping it.
      if (!record.document || typeof record.document !== "object") {
        return null;
      }
      return {
        didDocument: record.document as DIDDocument,
        didResolutionMetadata: { contentType: "application/did+json" },
        didDocumentMetadata: { resolvedAt: record.resolvedAt },
      };
    } catch {
      // Any failure — 404, network error, malformed response — falls
      // through to `null` so the resolver re-raises the original HTTPS
      // error. The DeDi client logs the underlying cause separately.
      return null;
    }
  };
}
