/**
 * Singleton holder for the DeDi client initialised at server startup.
 *
 * The client is created once from `OPENCRED_DEDI_*` env vars during bootstrap
 * (see `index.ts`) and shared across all verification and revocation requests.
 *
 * Follows the same pattern as `trust-store.ts` and `schema-registry-singleton.ts`.
 *
 * SECURITY: The DeDi client only sends revocation hashes and public-key
 * records to DeDi. It NEVER sends private key material.
 */

import type { DeDiClient } from "@opencred/dedi-client";

let client: DeDiClient | null = null;

/**
 * Set the DeDi client. Called once at server startup.
 */
export function setDeDiClient(c: DeDiClient): void {
  client = c;
}

/**
 * Get the DeDi client, or null if DeDi is not configured.
 */
export function getDeDiClient(): DeDiClient | null {
  return client;
}

/**
 * Reset the DeDi client (for testing only).
 */
export function resetDeDiClient(): void {
  client = null;
}
