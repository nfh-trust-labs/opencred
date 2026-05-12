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
  TRACEABILITY_V1_CONTEXT,
  OPEN_BADGES_V3_CONTEXT,
  OPENCRED_ELECTRICITY_V1_CONTEXT,
  OPENCRED_IMMUNIZATION_V1_CONTEXT,
  OPENCRED_PRESCRIPTION_V1_CONTEXT,
  OPENCRED_TEST_RESULT_V1_CONTEXT,
  OPENCRED_INSURANCE_POLICY_V1_CONTEXT,
  OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT,
  OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT,
  OPENCRED_BUSINESS_ENTITY_V1_CONTEXT,
} from "./types.js";
import {
  credentialsV2,
  dataIntegrityV1,
  traceabilityV1,
  openBadgesV3,
  electricityV1,
  immunizationV1,
  prescriptionV1,
  testResultV1,
  insurancePolicyV1,
  functionalIdentityV1,
  employmentOfferLetterV1,
  businessEntityV1,
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
  // W3C + OpenCred base contexts
  [W3C_CREDENTIALS_V2_CONTEXT, credentialsV2],
  [DATA_INTEGRITY_V1_CONTEXT, dataIntegrityV1],
  // Referenced upstream contexts bundled at build time
  [TRACEABILITY_V1_CONTEXT, traceabilityV1],
  [OPEN_BADGES_V3_CONTEXT, openBadgesV3],
  // OpenCred-defined credential contexts (SHA-pinned to schema-sources.json)
  [OPENCRED_ELECTRICITY_V1_CONTEXT, electricityV1],
  [OPENCRED_IMMUNIZATION_V1_CONTEXT, immunizationV1],
  [OPENCRED_PRESCRIPTION_V1_CONTEXT, prescriptionV1],
  [OPENCRED_TEST_RESULT_V1_CONTEXT, testResultV1],
  [OPENCRED_INSURANCE_POLICY_V1_CONTEXT, insurancePolicyV1],
  [OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT, functionalIdentityV1],
  [OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT, employmentOfferLetterV1],
  [OPENCRED_BUSINESS_ENTITY_V1_CONTEXT, businessEntityV1],
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
