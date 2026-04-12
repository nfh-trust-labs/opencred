/**
 * Shared SchemaRegistry singleton for the server.
 *
 * Initialised once at startup (optionally with remote updates) and
 * imported by route modules. The registry is immutable after init —
 * schemas are NEVER fetched during request handling.
 */

import type { SchemaRegistry } from "@opencred/schema-engine";
import { createRegistry } from "@opencred/schema-engine";

let instance: SchemaRegistry | null = null;

/**
 * Set the server-wide schema registry. Called once during startup in
 * index.ts after `createRegistryWithUpdates()` resolves.
 */
export function setSchemaRegistry(registry: SchemaRegistry): void {
  instance = registry;
}

/**
 * Get the server-wide schema registry. Falls back to a bundled-only
 * registry if `setSchemaRegistry` was never called (defensive).
 */
export function getSchemaRegistry(): SchemaRegistry {
  if (!instance) {
    instance = createRegistry();
  }
  return instance;
}
