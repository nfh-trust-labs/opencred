/**
 * Bundled JSON-LD document loader.
 *
 * Security invariant: never fetches remote contexts in production.
 * All W3C contexts are bundled as static JSON and served locally.
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
 * Creates a document loader that serves bundled JSON-LD contexts.
 * Rejects any URL not in the bundled set — never fetches remote contexts.
 */
export function createDocumentLoader() {
  return function documentLoader(url: string): JsonLdDocument {
    const document = BUNDLED_CONTEXTS.get(url);
    if (!document) {
      throw new ContextNotFoundError(url);
    }
    return {
      contextUrl: null,
      documentUrl: url,
      document,
    };
  };
}

/** Returns the set of bundled context URLs. */
export function getBundledContextUrls(): ReadonlySet<string> {
  return new Set(BUNDLED_CONTEXTS.keys());
}
