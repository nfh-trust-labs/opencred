/**
 * Singleton holder for startup-time outcomes that other parts of the server
 * (notably `/v1/health`) need to surface to operators.
 *
 * Right now this only tracks `didAutoPublishedAtStartup`, but the pattern is
 * intentionally generic — additional startup outcomes (e.g. trust-store load
 * success, schema-registry update sync) can live here without spawning a new
 * singleton module each time.
 *
 * Follows the same pattern as `dedi-singleton.ts`, `trust-store.ts`, etc.
 */

let didAutoPublishedAtStartup = false;

/**
 * Record whether the startup auto-publish step (driven by
 * `OPENCRED_AUTO_PUBLISH_KEY` or `OPENCRED_DEDI_HOST_DID_DOC=true` +
 * `OPENCRED_ISSUER_DID_METHOD=web`) succeeded.
 *
 * Called once during boot from `index.ts` after the DeDi client is
 * initialised. Treats both "freshly published" and "already published
 * (DeDiRecordExistsError idempotent skip)" as success — what an operator
 * cares about is "is my DID resolvable via DeDi right now," not "did the
 * publish call literally run this boot."
 */
export function setDidAutoPublishedAtStartup(value: boolean): void {
  didAutoPublishedAtStartup = value;
}

/**
 * Read the startup auto-publish outcome. Surfaced by `/v1/health` so
 * operators can verify their config landed without parsing logs.
 */
export function getDidAutoPublishedAtStartup(): boolean {
  return didAutoPublishedAtStartup;
}

/**
 * Reset for testing. Mirrors `resetDeDiClient` and friends.
 */
export function resetStartupState(): void {
  didAutoPublishedAtStartup = false;
}
