export type {
  SchemaDefinition,
  SchemaSource,
  ValidationResult,
  ValidationFieldError,
  SchemaManifest,
  SchemaManifestEntry,
} from "./types.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";

import { SchemaRegistry } from "./schema-registry.js";
import { createBuiltInRegistry } from "./generated-registry.js";
import type { SchemaManifest } from "./types.js";

/**
 * Create a registry pre-populated with every bundled credential schema.
 * Schemas are loaded from the build-time generated module (schema-data.ts +
 * generated-registry.ts), which is produced by scripts/fetch-and-embed-schemas.mjs
 * during `pnpm build`. The runtime never fetches schemas remotely.
 */
export function createRegistry(): SchemaRegistry {
  return createBuiltInRegistry();
}

/**
 * Get the manifest for all bundled schemas.
 * Convenience wrapper that creates a registry and returns its manifest.
 */
export function getSchemaManifest(): SchemaManifest {
  return createRegistry().getManifest();
}
