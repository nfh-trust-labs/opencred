/**
 * Template registry — maps schema IDs to SVG templates.
 *
 * v1 schema library ships with a single default template used for all ~33
 * credentials. Schema-specific branded templates are a v1.1 follow-up; the
 * default renders generic VC fields (title, issuer, subject name, dates)
 * which works for every credential, and credential-specific field polish
 * lands later.
 *
 * Lookup order:
 *   1. Exact schema ID match (templates.get(schemaId))
 *   2. Category match (first path segment before "/", e.g. "traceability/*"
 *      → category:traceability). Reserved for v1.1 when categories get
 *      dedicated templates.
 *   3. Default template fallback.
 */

import type { CredentialTemplate } from "./types.js";
import { defaultSvg } from "./svg-data.js";

const DEFAULT_TEMPLATE: CredentialTemplate = {
  id: "default",
  name: "Default Credential",
  svg: defaultSvg,
};

/**
 * Schema-specific templates. Empty in v1 — every credential uses the default
 * template. Populate this array in v1.1 to add branded templates for
 * high-frequency credentials (electricity, salary-slip, immunization, etc.).
 */
const SCHEMA_TEMPLATES: ReadonlyArray<CredentialTemplate> = [];

/**
 * Category-level templates. Used when no exact schema ID matches but the
 * schema ID falls under a known category (e.g. "traceability/*"). Empty in v1.
 */
const CATEGORY_TEMPLATES: ReadonlyMap<string, CredentialTemplate> = new Map();

const templates = new Map<string, CredentialTemplate>([["default", DEFAULT_TEMPLATE]]);

// Auto-register all schema-specific templates.
for (const tmpl of SCHEMA_TEMPLATES) {
  templates.set(tmpl.id, tmpl);
}

/**
 * Register a custom template for a schema ID.
 */
export function registerTemplate(schemaId: string, template: CredentialTemplate): void {
  templates.set(schemaId, template);
}

/**
 * Get the template for a schema ID, applying:
 *   1. Exact schema ID match
 *   2. Category match (first path segment — e.g. "traceability/commercial-invoice/v1"
 *      → category "traceability")
 *   3. Default template
 */
export function getTemplate(schemaId?: string): CredentialTemplate {
  if (!schemaId) {
    return DEFAULT_TEMPLATE;
  }
  const exact = templates.get(schemaId);
  if (exact) {
    return exact;
  }
  const category = schemaId.split("/")[0];
  const categoryTemplate = CATEGORY_TEMPLATES.get(category);
  if (categoryTemplate) {
    return categoryTemplate;
  }
  return DEFAULT_TEMPLATE;
}

/**
 * List all registered template IDs.
 */
export function listTemplateIds(): string[] {
  return Array.from(templates.keys());
}
