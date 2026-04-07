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
 *    after SSRF validation. This file MUST NOT introduce any HTTP I/O.
 *  - Never logs the content of cached contexts. They may contain
 *    user-defined vocabulary that could be sensitive.
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
 * Look up a custom-schema context document in the local store.
 *
 * Returns `undefined` if no custom schema has been saved with this
 * `contextUrl`/`dediContextUrl`, or if the matching schema has no
 * `cachedContextDocument`.
 *
 * Performs no I/O. Safe to call from synchronous JSON-LD loader callbacks.
 */
export function lookupCachedCustomContext(
  url: string,
): Record<string, unknown> | undefined {
  const store = getStore();
  const customSchemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];

  for (const entry of customSchemas) {
    if (!entry.cachedContextDocument) continue;
    if (entry.dediContextUrl === url) {
      return entry.cachedContextDocument;
    }
    // Check the user-provided contextUrl too (stored as sourceUrl when present);
    // some flows persist the context URL separately from the schema source URL,
    // so we also accept the cached doc if the URL matches the dedi URL.
    // (Currently dediContextUrl is the only mapping; this branch is reserved
    // for future custom URL fields.)
  }

  return undefined;
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
