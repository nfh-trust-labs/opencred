/**
 * Template registry — maps schema IDs to SVG templates.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { CredentialTemplate } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Load an SVG template file from the templates directory. */
function loadTemplate(filename: string): string {
  return readFileSync(resolve(__dirname, "templates", filename), "utf-8");
}

/** Load the default SVG template at module init. */
const DEFAULT_TEMPLATE_SVG = loadTemplate("default.svg");

const DEFAULT_TEMPLATE: CredentialTemplate = {
  id: "default",
  name: "Default Credential",
  svg: DEFAULT_TEMPLATE_SVG,
};

/** Schema-specific templates loaded at module init. */
const SCHEMA_TEMPLATES: ReadonlyArray<CredentialTemplate> = [
  {
    id: "education",
    name: "Education Credential",
    svg: loadTemplate("education.svg"),
  },
  {
    id: "employment",
    name: "Employment Credential",
    svg: loadTemplate("employment.svg"),
  },
  {
    id: "identity",
    name: "Identity Credential",
    svg: loadTemplate("identity.svg"),
  },
  {
    id: "health",
    name: "Health Credential",
    svg: loadTemplate("health.svg"),
  },
  {
    id: "business",
    name: "Business Credential",
    svg: loadTemplate("business.svg"),
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
