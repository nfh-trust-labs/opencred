/**
 * Shared Validator singleton for the server.
 *
 * The server previously created five independent `Validator` instances in
 * csv-parser.ts, batch-engine.ts, and credentials.ts (two in the server, two
 * in the desktop app), each lazily wrapping the schema registry on first
 * use. Under any race or mid-flight re-initialization that produced five
 * validators bound to five different registry snapshots — see Anand's
 * P1-01.
 *
 * There is exactly one Validator for the process, constructed in
 * `src/index.ts` (or `createTestApp` for tests) immediately after
 * `setSchemaRegistry()` resolves, and every consumer imports it via
 * `getValidator()`. Access before init throws.
 */

import type { Validator } from "@opencred/schema-engine";

let instance: Validator | null = null;

/**
 * Set the server-wide Validator. Called once during bootstrap.
 */
export function setValidator(validator: Validator): void {
  instance = validator;
}

/**
 * Get the server-wide Validator.
 *
 * @throws Error if `setValidator()` was never called. Fails loud by design —
 *   see the module docstring.
 */
export function getValidator(): Validator {
  if (!instance) {
    throw new Error(
      "Validator not initialized. setValidator() must be called during " +
        "bootstrap (apps/server/src/index.ts) or via createTestApp() before " +
        "any route handler or CSV parser runs.",
    );
  }
  return instance;
}

/**
 * Clear the singleton. Intended for tests that need to reset state between
 * `createTestApp()` invocations. Do not call from production code.
 */
export function resetValidator(): void {
  instance = null;
}
