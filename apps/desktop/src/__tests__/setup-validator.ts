/**
 * Per-test helper — bootstrap the schema-registry and validator singletons
 * for a test file that calls `buildAndSign`, `parseCsv`, or any other code
 * path that reaches through `getValidator()`.
 *
 * Usage:
 *   import { bootstrapTestValidator } from "./setup-validator.js";
 *   beforeAll(() => { bootstrapTestValidator(); });
 *
 * Why this is a per-test import rather than a global `setupFiles` hook:
 * importing `@opencred/schema-engine` from a Vitest `setupFiles` entry
 * transitively loads `@opencred/shared` (via `schema-updater.ts`), which in
 * turn captures references to `node:dns` at module load time. Tests that
 * later call `vi.mock("node:dns")` then lose those mocks because the real
 * DNS functions are already bound — breaking SSRF regression tests.
 *
 * Calling this helper from `beforeAll` in the tests that actually need it
 * sidesteps that ordering problem while still keeping every consumer
 * explicit about its dependency on the validator singleton.
 */

import { createRegistry, Validator } from "@opencred/schema-engine";
import { setSchemaRegistry } from "../main/schema-registry-singleton.js";
import { setValidator } from "../main/validator-singleton.js";

export function bootstrapTestValidator(): void {
  const registry = createRegistry();
  setSchemaRegistry(registry);
  setValidator(new Validator(registry));
}
