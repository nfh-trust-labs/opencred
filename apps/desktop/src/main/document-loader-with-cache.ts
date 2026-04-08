/**
 * Custom-schema-aware JSON-LD document loader for the desktop client.
 *
 * Wraps the bundled `createDocumentLoader` from `@opencred/vc-core` so that
 * when a user creates a custom schema with a JSON-LD context URL, that
 * context (which is fetched and cached at schema-save time in the main
 * process) becomes resolvable to the document loader at issuance and
 * verification time.
 *
 * SECURITY INVARIANTS:
 *  - Never makes a network request. The wrapped resolver only serves
 *    contexts that have already been fetched and cached locally — the
 *    caching itself happens in `ipc-handlers.ts handleCustomSchemaSave`
 *    after shape validation. This file MUST NOT introduce any HTTP I/O.
 *  - Never logs the content of cached contexts. They may contain
 *    user-defined vocabulary that could be sensitive.
 *
 * JSON-LD 1.1 §3.1 treats a context URL as a global identifier: the same URL
 * must always dereference to the same document. `handleCustomSchemaSave`
 * enforces that invariant at the moment of conflict by rejecting a save
 * whose context URL is already cached with a different content hash.
 * Because of that enforcement, a plain URL → document lookup here is safe:
 * by construction, no two schemas can have registered different bodies
 * under the same URL.
 */

import {
  createDocumentLoader as createBundledLoader,
  setDefaultExtraContextResolver,
  ContextNotFoundError,
} from "@opencred/vc-core";
import type { ExtraContextResolver, JsonLdDocument } from "@opencred/vc-core";
import { getStore } from "./store.js";
import type { CustomSchemaEntry } from "./store.js";

/**
 * Find any custom schema entry that has cached this URL. Returns the owning
 * schema id alongside the document so callers that care about provenance
 * (diagnostics, the schema-management UI, and tests) can inspect it.
 */
export function findCachedCustomContext(
  url: string,
): { schemaId: string; document: Record<string, unknown> } | undefined {
  const store = getStore();
  const customSchemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];

  for (const entry of customSchemas) {
    if (!entry.cachedContextDocument) continue;
    if (entry.dediContextUrl === url) {
      return { schemaId: entry.id, document: entry.cachedContextDocument };
    }
  }
  return undefined;
}

/**
 * Look up a custom-schema context document in the local store.
 *
 * Returns `undefined` when no custom schema has cached this URL. Performs
 * no I/O — safe to call from synchronous JSON-LD loader callbacks.
 *
 * The save path guarantees that at most one schema owns the cache entry
 * for a given URL (see `handleCustomSchemaSave` content-hash check), so
 * this is a simple URL → document mapping as the JSON-LD spec assumes.
 */
export function lookupCachedCustomContext(url: string): Record<string, unknown> | undefined {
  return findCachedCustomContext(url)?.document;
}

/**
 * Build the resolver function for use with `setDefaultExtraContextResolver`
 * or as the `extraResolver` argument to {@link createBundledLoader}.
 */
export function createCustomContextResolver(): ExtraContextResolver {
  return (url: string) => lookupCachedCustomContext(url);
}

/**
 * Create a document loader that serves bundled contexts first, then any
 * custom-schema contexts cached in the local store.
 *
 * Throws {@link ContextNotFoundError} if neither source matches.
 */
export function createDocumentLoaderWithCache(): (url: string) => JsonLdDocument {
  return createBundledLoader(createCustomContextResolver());
}

/**
 * Register the custom-context resolver as the process-wide default. After
 * this is called once at app startup, every call to `createDocumentLoader()`
 * — including the one inside `@opencred/crypto`'s data-integrity
 * canonicalization — will transparently fall through to the custom cache.
 */
export function installCustomContextResolver(): void {
  setDefaultExtraContextResolver(createCustomContextResolver());
}

/**
 * Clear the process-wide custom-context resolver. Used by tests for
 * isolation.
 */
export function uninstallCustomContextResolver(): void {
  setDefaultExtraContextResolver(null);
}

// Re-export the error so callers can `instanceof`-check it without taking
// a separate dependency on @opencred/vc-core.
export { ContextNotFoundError };
