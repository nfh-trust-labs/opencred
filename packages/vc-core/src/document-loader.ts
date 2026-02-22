/**
 * Bundled JSON-LD document loader.
 *
 * Security invariant: never fetches remote contexts in production.
 * All W3C contexts are bundled as static JSON and served locally.
 */

import { createRequire } from "node:module";
import { W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT } from "./types.js";

const require = createRequire(import.meta.url);

const credentialsV2 = require("./contexts/credentials-v2.json") as Record<string, unknown>;
const dataIntegrityV1 = require("./contexts/data-integrity-v1.json") as Record<string, unknown>;

export interface JsonLdDocument {
  contextUrl: string | null;
  documentUrl: string;
  document: Record<string, unknown>;
}

const BUNDLED_CONTEXTS: ReadonlyMap<string, Record<string, unknown>> = new Map([
  [W3C_CREDENTIALS_V2_CONTEXT, credentialsV2],
  [DATA_INTEGRITY_V1_CONTEXT, dataIntegrityV1],
]);

/**
 * Creates a document loader that serves bundled JSON-LD contexts.
 * Rejects any URL not in the bundled set — never fetches remote contexts.
 */
export function createDocumentLoader() {
  return function documentLoader(url: string): JsonLdDocument {
    const document = BUNDLED_CONTEXTS.get(url);
    if (!document) {
      throw new Error(
        `Refusing to fetch remote JSON-LD context: ${url}. ` +
          "Only bundled contexts are allowed in production."
      );
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
