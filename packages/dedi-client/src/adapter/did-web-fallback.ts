/**
 * DeDi-backed fallback resolver for did:web.
 *
 * Plugs into `DIDWebResolver`'s optional `fallback` constructor argument
 * (see `@opencred/did`). When canonical HTTPS resolution of a
 * `did:web:...` document fails — network error, 404, DNS hiccup — the
 * resolver projects the DID document from the issuer's per-key records in
 * the `opencred-key-registry` (each record carries an immutable did.json
 * snapshot in its `document` field; #670). If a snapshot is found, it is
 * returned in the standard `DIDResolutionResult` shape; if not, the
 * fallback returns `null` and the resolver throws the original HTTP error.
 *
 * **SSRF safety.** `DIDWebResolver` never invokes the fallback when
 * canonical resolution failed due to an SSRF guard rejection — that
 * decision is enforced in the resolver itself, not here. The fallback
 * is only consulted on genuine "the canonical endpoint is unreachable"
 * errors, so a DeDi-anchored response can't be used to bypass private-IP
 * checks on the caller's behalf.
 *
 * **What this enables.** An issuer who opted into DeDi-hosted did.json
 * (`OPENCRED_DEDI_HOST_DID_DOC`, which embeds the snapshot on each key
 * record at publish/rotate time) can stop serving the canonical
 * `.well-known/did.json` from a webserver entirely, and DeDi acts as the
 * discovery layer. Verifiers wired with this fallback will resolve the DID
 * through DeDi whenever the HTTPS endpoint is unreachable — the same
 * `assertionMethod` keys, the same signatures, just a different host
 * serving the document.
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
 * - Calls `client.resolveDidWebDocument(did)`, which projects the did.json
 *   from the DID's key records in `opencred-key-registry` under the
 *   client's configured namespace (active key's snapshot, else the
 *   highest-index key's), returning the document directly or `null`.
 * - Maps the resolved document into a standard `DIDResolutionResult`,
 *   populating `didDocumentMetadata.resolvedAt` with the current
 *   wall-clock time so the fallback consumer can still see "when did we
 *   resolve this". The embedded snapshot itself carries no per-record
 *   `resolvedAt` (the envelope's `updated_at` is canonical if a precise
 *   on-server timestamp is needed in a future iteration).
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
      // The did.json snapshot lives on the DID's key records in
      // `opencred-key-registry` (the separate `did-documents` registry was
      // removed). `resolveDidWebDocument` picks the active — or latest —
      // key's snapshot, or returns `null` when no key carries a document.
      const document = await client.resolveDidWebDocument(did);
      // The document came over the wire from another service — treat it as
      // opaque until we've confirmed it's an object. The W3C DID-Document
      // contract is enforced by the downstream verifier.
      if (!document || typeof document !== "object") {
        return null;
      }
      return {
        didDocument: document as unknown as DIDDocument,
        didResolutionMetadata: { contentType: "application/did+json" },
        didDocumentMetadata: { resolvedAt: new Date().toISOString() },
      };
    } catch {
      // Any failure — empty registry, network error, malformed response —
      // falls through to `null` so the resolver re-raises the original HTTPS
      // error. The DeDi client logs the underlying cause separately.
      return null;
    }
  };
}
