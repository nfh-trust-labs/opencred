export type {
  SchemaCategory,
  SchemaDefinition,
  SchemaSource,
  ValidationResult,
  ValidationFieldError,
  SchemaManifest,
  SchemaManifestEntry,
} from "./types.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";
export { getCategoryForSchema } from "./schema-categories.js";

import { SchemaRegistry } from "./schema-registry.js";
import { createBuiltInRegistry } from "./generated-registry.js";
import { educationV1Definition } from "./schemas/education-v1.js";
import { getCategoryForSchema } from "./schema-categories.js";
import type { SchemaManifest } from "./types.js";

/**
 * Create a registry pre-populated with every bundled credential schema
 * plus locally-defined schemas (e.g. education/v1).
 *
 * After loading, categories are applied to all schemas via the
 * schema-categories mapping.
 */
export function createRegistry(): SchemaRegistry {
  const registry = createBuiltInRegistry();

  // Register locally-defined schemas
  registry.register(educationV1Definition);

  // Apply categories to all schemas (bundled schemas don't have categories
  // set by the code-generator, so we assign them here)
  for (const id of registry.listSchemas()) {
    const def = registry.getSchema(id);
    if (!def.category) {
      def.category = getCategoryForSchema(id);
    }
  }

  return registry;
}

/**
 * Get the manifest for all bundled schemas.
 * Convenience wrapper that creates a registry and returns its manifest.
 */
export function getSchemaManifest(): SchemaManifest {
  return createRegistry().getManifest();
}
