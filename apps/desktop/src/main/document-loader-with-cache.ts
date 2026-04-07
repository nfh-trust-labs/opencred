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
 *  - Cached contexts are scoped per-schema via {@link runWithActiveSchemaContext}.
 *    Outside an active scope, the resolver returns `undefined` for every URL,
 *    so no custom-schema context can leak into a flow that did not opt in.
 *    This is a defence-in-depth measure: even if two custom schemas reference
 *    the same URL, issuance/verification of schema A cannot accidentally
 *    consume the context that was cached against schema B.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import {
  createDocumentLoader as createBundledLoader,
  setDefaultExtraContextResolver,
  ContextNotFoundError,
} from "@opencred/vc-core";
import type { ExtraContextResolver, JsonLdDocument } from "@opencred/vc-core";
import { getStore } from "./store.js";
import type { CustomSchemaEntry } from "./store.js";

interface CustomContextScope {
  /** Schema IDs whose cached contexts are visible inside this scope. */
  schemaIds: ReadonlySet<string>;
}

const customContextScope = new AsyncLocalStorage<CustomContextScope>();

/**
 * Run `fn` within a per-schema scope on cached custom JSON-LD contexts.
 *
 * Inside `fn`, the wrapped document loader will only resolve cached contexts
 * whose owning custom schema is in `schemaIds`. This applies transitively:
 * any async work spawned by `fn` (including the JSON-LD canonicalization
 * that runs deep inside `@opencred/crypto`) inherits the same scope.
 *
 * Outside any scope, no custom contexts are served — the loader behaves
 * exactly like the bundled-only loader. This is the safe default.
 */
export function runWithActiveSchemaContext<T>(
  schemaIds: readonly string[],
  fn: () => T,
): T {
  return customContextScope.run({ schemaIds: new Set(schemaIds) }, fn);
}

/**
 * Find any custom schema entry that has cached this URL, regardless of the
 * active scope. Intended for diagnostics, tests, and the schema-management
 * UI — NOT for the document loader code path.
 *
 * Returns the owning schema id alongside the document so callers can decide
 * whether to honour it.
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
 * Look up a custom-schema context document in the local store, honouring
 * the active per-schema scope.
 *
 * Returns `undefined` when:
 *  - no custom schema has cached this URL
 *  - no scope is active (the safe default — see file docstring)
 *  - the cached context belongs to a schema outside the active scope
 *
 * Performs no I/O. Safe to call from synchronous JSON-LD loader callbacks.
 */
export function lookupCachedCustomContext(
  url: string,
): Record<string, unknown> | undefined {
  const found = findCachedCustomContext(url);
  if (!found) return undefined;

  const scope = customContextScope.getStore();
  if (!scope) return undefined;
  if (!scope.schemaIds.has(found.schemaId)) return undefined;

  return found.document;
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
 * custom-schema contexts cached in the local store (subject to the active
 * per-schema scope).
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
 * canonicalization — will transparently fall through to the custom cache,
 * but ONLY when called inside a {@link runWithActiveSchemaContext} block.
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

/**
 * Derive the set of custom-schema IDs whose cached contexts should be in
 * scope when verifying a credential.
 *
 * The rule: a custom schema is in scope if its `dediContextUrl` appears
 * anywhere in the credential's `@context` array. This way, the verifier
 * only honours contexts it has explicitly imported AND that the credential
 * actually claims to use.
 *
 * Strings, objects, and nested arrays in `@context` are all handled. URLs
 * inside nested context objects (e.g. `{ "@context": "https://..." }`) are
 * not currently extracted — only top-level string entries — but the cache
 * is keyed off the URL the user pasted at save time, which is always the
 * top-level URL the credential references.
 */
export function deriveScopeForCredential(
  credential: Record<string, unknown>,
): string[] {
  const ctx = credential["@context"];
  const urls = new Set<string>();
  const collect = (v: unknown): void => {
    if (typeof v === "string") {
      urls.add(v);
    } else if (Array.isArray(v)) {
      for (const item of v) collect(item);
    }
    // Inline context objects intentionally ignored — they have no URL to match.
  };
  collect(ctx);

  if (urls.size === 0) return [];

  const store = getStore();
  const customSchemas =
    (store.get("customSchemas" as keyof typeof store.store) as CustomSchemaEntry[]) ?? [];

  const scope: string[] = [];
  for (const entry of customSchemas) {
    if (entry.dediContextUrl && urls.has(entry.dediContextUrl)) {
      scope.push(entry.id);
    }
  }
  return scope;
}

// Re-export the error so callers can `instanceof`-check it without taking
// a separate dependency on @opencred/vc-core.
export { ContextNotFoundError };
