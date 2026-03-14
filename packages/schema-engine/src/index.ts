export type {
  SchemaDefinition,
  ValidationResult,
  ValidationFieldError,
  SchemaManifest,
  SchemaManifestEntry,
  SchemaUpdateResult,
} from "./types.js";
export { SchemaRegistry } from "./schema-registry.js";
export { Validator } from "./validator.js";
export {
  checkForSchemaUpdates,
  downloadSchema,
  loadCachedSchemas,
  saveSchemasToCache,
} from "./updater.js";
export {
  educationSchema,
  employmentSchema,
  identitySchema,
  healthSchema,
  businessSchema,
} from "./schemas/index.js";

import { SchemaRegistry } from "./schema-registry.js";
import {
  educationSchema,
  employmentSchema,
  identitySchema,
  healthSchema,
  businessSchema,
} from "./schemas/index.js";

import type { SchemaManifest } from "./types.js";

export function createRegistry(): SchemaRegistry {
  const registry = new SchemaRegistry();

  registry.registerSchema(
    "education",
    educationSchema,
    "https://opencred.dev/contexts/education/v1",
    "1.0.0",
    "2025-05-01T00:00:00Z",
  );
  registry.registerSchema(
    "employment",
    employmentSchema,
    "https://opencred.dev/contexts/employment/v1",
    "1.0.0",
    "2025-05-01T00:00:00Z",
  );
  registry.registerSchema(
    "identity",
    identitySchema,
    "https://opencred.dev/contexts/identity/v1",
    "1.0.0",
    "2025-05-01T00:00:00Z",
  );
  registry.registerSchema(
    "health",
    healthSchema,
    "https://opencred.dev/contexts/health/v1",
    "1.0.0",
    "2025-05-01T00:00:00Z",
  );
  registry.registerSchema(
    "business",
    businessSchema,
    "https://opencred.dev/contexts/business/v1",
    "1.0.0",
    "2025-05-01T00:00:00Z",
  );

  return registry;
}

/**
 * Get the manifest for all bundled schemas.
 * Convenience wrapper that creates a registry and returns its manifest.
 */
export function getSchemaManifest(): SchemaManifest {
  const registry = createRegistry();
  return registry.getManifest();
}
