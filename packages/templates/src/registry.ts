/**
 * Template registry — maps schema IDs to SVG templates.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { CredentialTemplate } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Load the default SVG template at module init. */
const DEFAULT_TEMPLATE_SVG = readFileSync(
  resolve(__dirname, "templates", "default.svg"),
  "utf-8",
);

const DEFAULT_TEMPLATE: CredentialTemplate = {
  id: "default",
  name: "Default Credential",
  svg: DEFAULT_TEMPLATE_SVG,
};

const templates = new Map<string, CredentialTemplate>([
  ["default", DEFAULT_TEMPLATE],
]);

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
