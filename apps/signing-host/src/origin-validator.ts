/**
 * Origin validator for the native messaging host.
 *
 * Validates that the browser extension origin is in the allowlist before
 * processing any request. This prevents unauthorised extensions or web
 * pages from invoking signing operations.
 *
 * SECURITY INVARIANTS:
 *  - Origins must match exactly — no wildcards, no prefix matching.
 *  - Empty/null/undefined origins are always rejected.
 *  - The allowlist is loaded from configuration at startup.
 */

/** Default allowed origins (Chrome and Firefox extension IDs). */
export const DEFAULT_ALLOWED_ORIGINS: readonly string[] = [
  // Placeholder — real extension IDs are added during build/deployment.
  // Example Chrome: "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
  // Example Firefox: "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
];

/**
 * Validate that a request origin is in the allowlist.
 *
 * @param origin - The origin string from the native messaging request.
 * @param allowlist - The list of allowed origin strings.
 * @returns true if the origin is allowed, false otherwise.
 */
export function validateOrigin(origin: string, allowlist: readonly string[]): boolean {
  if (!origin || origin.trim().length === 0) {
    return false;
  }

  return allowlist.includes(origin);
}
