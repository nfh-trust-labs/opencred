/**
 * Bundled JSON-LD document loader.
 *
 * Security invariant: never fetches remote contexts in production.
 * All W3C contexts are bundled as static JSON and served locally.
 *
 * The loader supports an optional "extra resolver" so that host applications
 * (e.g. the desktop client) can serve user-provided context URLs from a
 * pre-fetched local cache. The resolver is consulted *after* the bundled set,
 * never before, and resolvers themselves must NOT make network requests —
 * they must only return contexts that have already been fetched and stored.
 */

import { ContextNotFoundError } from "./context-errors.js";
import {
  W3C_CREDENTIALS_V2_CONTEXT,
  DATA_INTEGRITY_V1_CONTEXT,
  OPENCRED_DELEGATION_V1_CONTEXT,
  NFH_EDUCATION_V1_CONTEXT,
  NFH_EMPLOYMENT_V1_CONTEXT,
  NFH_IDENTITY_V1_CONTEXT,
  NFH_HEALTH_V1_CONTEXT,
  NFH_BUSINESS_V1_CONTEXT,
} from "./types.js";
import {
  credentialsV2,
  dataIntegrityV1,
  delegationV1,
  educationV1,
  employmentV1,
  identityV1,
  healthV1,
  businessV1,
} from "./context-data.js";

export interface JsonLdDocument {
  contextUrl: string | null;
  documentUrl: string;
  document: Record<string, unknown>;
}

/**
 * Synchronous resolver for extra (non-bundled) JSON-LD contexts.
 * Implementations must NOT perform network I/O — they may only return
 * contexts that have already been fetched/cached locally.
 */
export type ExtraContextResolver = (url: string) => Record<string, unknown> | undefined;

const BUNDLED_CONTEXTS: ReadonlyMap<string, Record<string, unknown>> = new Map([
  [W3C_CREDENTIALS_V2_CONTEXT, credentialsV2],
  [DATA_INTEGRITY_V1_CONTEXT, dataIntegrityV1],
  [OPENCRED_DELEGATION_V1_CONTEXT, delegationV1],
  [NFH_EDUCATION_V1_CONTEXT, educationV1],
  [NFH_EMPLOYMENT_V1_CONTEXT, employmentV1],
  [NFH_IDENTITY_V1_CONTEXT, identityV1],
  [NFH_HEALTH_V1_CONTEXT, healthV1],
  [NFH_BUSINESS_V1_CONTEXT, businessV1],
]);

/**
 * Module-level extra resolver. The host application (desktop client) registers
 * this once at startup so that downstream callers of `createDocumentLoader()`
 * (such as the canonicalization in @opencred/crypto) automatically pick it up.
 *
 * Default is `null`, preserving the original "bundled-only" behaviour.
 */
let defaultExtraResolver: ExtraContextResolver | null = null;

/**
 * Register a process-wide fallback resolver for extra JSON-LD contexts.
 * Pass `null` to clear it. Has no effect on loaders created with an explicit
 * `extraResolver` argument.
 */
export function setDefaultExtraContextResolver(resolver: ExtraContextResolver | null): void {
  defaultExtraResolver = resolver;
}

/** @internal — for tests; returns the currently registered fallback resolver. */
export function getDefaultExtraContextResolver(): ExtraContextResolver | null {
  return defaultExtraResolver;
}

/**
 * Creates a document loader that serves bundled JSON-LD contexts.
 *
 * Lookup order:
 *   1. Bundled contexts (W3C, NFH, etc.)
 *   2. The `extraResolver` argument, if provided
 *   3. The process-wide default resolver registered via
 *      {@link setDefaultExtraContextResolver}, if any
 *
 * Throws {@link ContextNotFoundError} if no source matches.
 *
 * Never makes network requests — both bundled lookups and extra resolvers
 * must be local-only.
 */
export function createDocumentLoader(extraResolver?: ExtraContextResolver) {
  return function documentLoader(url: string): JsonLdDocument {
    const bundled = BUNDLED_CONTEXTS.get(url);
    if (bundled) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: bundled,
      };
    }

    const resolver = extraResolver ?? defaultExtraResolver;
    if (resolver) {
      const extra = resolver(url);
      if (extra) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: extra,
        };
      }
    }

    throw new ContextNotFoundError(url);
  };
}

/** Returns the set of bundled context URLs. */
export function getBundledContextUrls(): ReadonlySet<string> {
  return new Set(BUNDLED_CONTEXTS.keys());
}
