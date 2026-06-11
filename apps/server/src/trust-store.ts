/**
 * Singleton holder for the CSCA trust store loaded at server startup.
 *
 * The trust store is loaded once from `OPENCRED_CSCA_TRUST_STORE_PATH` during
 * bootstrap (see `index.ts`) and shared across all verification requests.
 * Loading per-request would re-read the filesystem on every verify call —
 * wasteful and a potential source of inconsistency if certs are being rotated.
 *
 * SECURITY: The trust store only holds public CA certificates — never private
 * keys. It is immutable after startup.
 */

import type { CscaTrustStore } from "@opencred/verification";

let store: CscaTrustStore | null = null;

/**
 * Set the CSCA trust store. Called once at server startup.
 */
export function setTrustStore(trustStore: CscaTrustStore): void {
  store = trustStore;
}

/**
 * Get the CSCA trust store, or null if none was configured.
 */
export function getTrustStore(): CscaTrustStore | null {
  return store;
}

/**
 * Reset the trust store (for testing only).
 */
export function resetTrustStore(): void {
  store = null;
}
