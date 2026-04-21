/**
 * Shared SchemaRegistry singleton for the server.
 *
 * Initialised once at startup from `src/index.ts` (or from `createTestApp`
 * for tests) and imported by route modules. The registry is immutable after
 * init — schemas are NEVER fetched during request handling.
 *
 * This module fails loud if `getSchemaRegistry()` is called before
 * `setSchemaRegistry()`. An earlier version silently lazy-created a fresh
 * bundled-only registry on first read, which meant any consumer that
 * happened to import this module before bootstrap (typically a test that
 * skipped the bootstrap path) would permanently bind itself to a standalone
 * registry — invisible to schemas later loaded via `setSchemaRegistry()`
 * (see Anand's P1-01).
 */

import type { SchemaRegistry } from "@opencred/schema-engine";

let instance: SchemaRegistry | null = null;

/**
 * Set the server-wide schema registry. Called once during startup in
 * index.ts after `createRegistryWithUpdates()` resolves.
 */
export function setSchemaRegistry(registry: SchemaRegistry): void {
  instance = registry;
}

/**
 * Get the server-wide schema registry.
 *
 * @throws Error if `setSchemaRegistry()` was never called. This fails loud
 *   by design — see the module docstring.
 */
export function getSchemaRegistry(): SchemaRegistry {
  if (!instance) {
    throw new Error(
      "Schema registry not initialized. setSchemaRegistry() must be called " +
        "during bootstrap (apps/server/src/index.ts) or via createTestApp() " +
        "before any route handler or CSV parser runs.",
    );
  }
  return instance;
}

/**
 * Clear the singleton. Intended for tests that need to reset state between
 * `createTestApp()` invocations. Do not call from production code.
 */
export function resetSchemaRegistry(): void {
  instance = null;
}
