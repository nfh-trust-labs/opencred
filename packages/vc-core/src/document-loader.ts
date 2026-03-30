/**
 * Bundled JSON-LD document loader.
 *
 * Security invariant: never fetches remote contexts in production.
 * All W3C contexts are bundled as static JSON and served locally.
 */

import { createRequire } from "node:module";
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

const require = createRequire(import.meta.url);

const credentialsV2 = require("./contexts/credentials-v2.json") as Record<string, unknown>;
const dataIntegrityV1 = require("./contexts/data-integrity-v1.json") as Record<string, unknown>;
const delegationV1 = require("./contexts/delegation-v1.json") as Record<string, unknown>;
const educationV1 = require("./contexts/education-v1.json") as Record<string, unknown>;
const employmentV1 = require("./contexts/employment-v1.json") as Record<string, unknown>;
const identityV1 = require("./contexts/identity-v1.json") as Record<string, unknown>;
const healthV1 = require("./contexts/health-v1.json") as Record<string, unknown>;
const businessV1 = require("./contexts/business-v1.json") as Record<string, unknown>;

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
