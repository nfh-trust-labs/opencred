/**
 * Shared Validator singleton for the desktop main process.
 *
 * The desktop previously created two independent `Validator` instances in
 * `batch/csv-parser.ts` and `signing/local-signing-flow.ts`, each lazily
 * wrapping the schema registry on first use. Under any race or mid-flight
 * re-initialization that produced validators bound to different registry
 * snapshots — see Anand's P1-01.
 *
 * There is exactly one Validator for the main process, constructed in
 * `src/main/index.ts` immediately after `setSchemaRegistry()` resolves, and
 * every consumer imports it via `getValidator()`. Access before init
 * throws.
 */

import type { Validator } from "@opencred/schema-engine";

let instance: Validator | null = null;

/**
 * Set the app-wide Validator. Called once during bootstrap.
 */
export function setValidator(validator: Validator): void {
  instance = validator;
}

/**
 * Get the app-wide Validator.
 *
 * @throws Error if `setValidator()` was never called. Fails loud by design —
 *   see the module docstring.
 */
export function getValidator(): Validator {
  if (!instance) {
    throw new Error(
      "Validator not initialized. setValidator() must be called during " +
        "bootstrap (apps/desktop/src/main/index.ts) before any IPC handler " +
        "or signing flow runs.",
    );
  }
  return instance;
}

/**
 * Clear the singleton. Intended for tests. Do not call from production code.
 */
export function resetValidator(): void {
  instance = null;
}
