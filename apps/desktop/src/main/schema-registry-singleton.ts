/**
 * Shared SchemaRegistry singleton for the desktop main process.
 *
 * Initialised once at app startup from `src/main/index.ts` and imported by
 * IPC handlers and signing flows. The registry is immutable after init —
 * schemas are NEVER fetched during signing/verification.
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
 * Set the app-wide schema registry. Called once during startup in
 * index.ts after `createRegistryWithUpdates()` resolves.
 */
export function setSchemaRegistry(registry: SchemaRegistry): void {
  instance = registry;
}

/**
 * Get the app-wide schema registry.
 *
 * @throws Error if `setSchemaRegistry()` was never called. Fails loud by
 *   design — see the module docstring.
 */
export function getSchemaRegistry(): SchemaRegistry {
  if (!instance) {
    throw new Error(
      "Schema registry not initialized. setSchemaRegistry() must be called " +
        "during bootstrap (apps/desktop/src/main/index.ts) before any IPC " +
        "handler or signing flow runs.",
    );
  }
  return instance;
}

/**
 * Clear the singleton. Intended for tests that need to reset state between
 * scenarios. Do not call from production code.
 */
export function resetSchemaRegistry(): void {
  instance = null;
}
