/**
 * Shared SchemaRegistry singleton for the desktop main process.
 *
 * Initialised once at app startup (optionally with remote updates) and
 * imported by IPC handlers and signing flows. The registry is immutable
 * after init — schemas are NEVER fetched during signing/verification.
 */

import type { SchemaRegistry } from "@opencred/schema-engine";
import { createRegistry } from "@opencred/schema-engine";

let instance: SchemaRegistry | null = null;

/**
 * Set the app-wide schema registry. Called once during startup in
 * index.ts after `createRegistryWithUpdates()` resolves.
 */
export function setSchemaRegistry(registry: SchemaRegistry): void {
  instance = registry;
}

/**
 * Get the app-wide schema registry. Falls back to a bundled-only
 * registry if `setSchemaRegistry` was never called (defensive).
 */
export function getSchemaRegistry(): SchemaRegistry {
  if (!instance) {
    instance = createRegistry();
  }
  return instance;
}
