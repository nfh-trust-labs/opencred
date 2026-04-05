/**
 * Template registry — maps schema IDs to SVG templates.
 */

import type { CredentialTemplate } from "./types.js";
import {
  defaultSvg,
  educationSvg,
  employmentSvg,
  identitySvg,
  healthSvg,
  businessSvg,
} from "./svg-data.js";

const DEFAULT_TEMPLATE: CredentialTemplate = {
  id: "default",
  name: "Default Credential",
  svg: defaultSvg,
};

/** Schema-specific templates loaded at module init. */
const SCHEMA_TEMPLATES: ReadonlyArray<CredentialTemplate> = [
  {
    id: "education",
    name: "Education Credential",
    svg: educationSvg,
  },
  {
    id: "employment",
    name: "Employment Credential",
    svg: employmentSvg,
  },
  {
    id: "identity",
    name: "Identity Credential",
    svg: identitySvg,
  },
  {
    id: "health",
    name: "Health Credential",
    svg: healthSvg,
  },
  {
    id: "business",
    name: "Business Credential",
    svg: businessSvg,
  },
];

const templates = new Map<string, CredentialTemplate>([
  ["default", DEFAULT_TEMPLATE],
]);

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
 * Get the template for a schema ID, falling back to the default.
 */
export function getTemplate(schemaId?: string): CredentialTemplate {
  if (schemaId && templates.has(schemaId)) {
    return templates.get(schemaId)!;
  }
  return DEFAULT_TEMPLATE;
}

/**
 * List all registered template IDs.
 */
export function listTemplateIds(): string[] {
  return Array.from(templates.keys());
}
