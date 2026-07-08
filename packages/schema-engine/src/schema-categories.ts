import type { SchemaCategory } from "./types.js";

/**
 * Static map from schema ID (or prefix) to category.
 * Exact matches are checked first, then prefix matches.
 */
const EXACT_CATEGORIES: Record<string, SchemaCategory> = {
  education: "education",
  "employment-offer-letter": "employment",
  "functional-identity": "identity",
  immunization: "health",
  prescription: "health",
  "test-result": "health",
  "business-entity": "business",
  "insurance-policy": "business",
  electricity: "utility",
  "salary-slip": "employment",
  "open-badges": "education",
  "dif/verified-person": "identity",
  "dif/proof-of-age": "identity",
  "ies/electricity-credential": "utility",
  "ies/meter-data-credential": "utility",
};

const PREFIX_CATEGORIES: Array<[string, SchemaCategory]> = [["traceability/", "supply-chain"]];

/**
 * Determine the category for a schema ID.
 *
 * Checks exact match on the base name (before the version segment) first,
 * then prefix matches, then falls back to "other".
 */
export function getCategoryForSchema(schemaId: string): SchemaCategory {
  // Strip version suffix, including dotted versions (e.g. "education/v1" →
  // "education", "ies/electricity-credential/v1.2" → "ies/electricity-credential")
  const base = schemaId.replace(/\/v\d+(?:\.\d+)*$/, "");

  const exact = EXACT_CATEGORIES[base];
  if (exact) return exact;

  for (const [prefix, category] of PREFIX_CATEGORIES) {
    if (base.startsWith(prefix)) return category;
  }

  return "other";
}
