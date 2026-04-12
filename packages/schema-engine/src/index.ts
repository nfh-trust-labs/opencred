export type {
  SchemaCategory,
  SchemaDefinition,
  SchemaSource,
  ValidationResult,
  ValidationFieldError,
  SchemaManifest,
  SchemaManifestEntry,
  InferredField,
  GeneratedSchemaResult,
} from "./types.js";
export type {
  SchemaUpdateManifest,
  SchemaUpdateManifestEntry,
  SchemaUpdateConfig,
} from "./schema-updater.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";
export { getCategoryForSchema } from "./schema-categories.js";
export { checkForUpdates } from "./schema-updater.js";
export { generateSchemaFromFields } from "./schema-generator.js";

import { SchemaRegistry } from "./schema-registry.js";
import { createBuiltInRegistry } from "./generated-registry.js";
import { educationV1Definition } from "./schemas/education-v1.js";
import { getCategoryForSchema } from "./schema-categories.js";
import { checkForUpdates, type SchemaUpdateConfig } from "./schema-updater.js";
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
 * Create a registry with bundled schemas, then optionally check for
 * updates from a remote manifest. Intended for use at application
 * startup — NEVER during signing/verification operations.
 *
 * If `config.manifestUrl` is not set, returns the bundled registry
 * unchanged (updates disabled).
 */
export async function createRegistryWithUpdates(
  config: SchemaUpdateConfig,
): Promise<SchemaRegistry> {
  const registry = createRegistry();
  return checkForUpdates(config, registry);
}

/**
 * Get the manifest for all bundled schemas.
 * Convenience wrapper that creates a registry and returns its manifest.
 */
export function getSchemaManifest(): SchemaManifest {
  return createRegistry().getManifest();
}
