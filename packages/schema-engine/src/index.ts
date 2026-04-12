export type {
  SchemaDefinition,
  SchemaSource,
  ValidationResult,
  ValidationFieldError,
  SchemaManifest,
  SchemaManifestEntry,
} from "./types.js";
export type {
  SchemaUpdateManifest,
  SchemaUpdateManifestEntry,
  SchemaUpdateConfig,
} from "./schema-updater.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";
export { checkForUpdates } from "./schema-updater.js";

import { SchemaRegistry } from "./schema-registry.js";
import { createBuiltInRegistry } from "./generated-registry.js";
import { checkForUpdates, type SchemaUpdateConfig } from "./schema-updater.js";
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
