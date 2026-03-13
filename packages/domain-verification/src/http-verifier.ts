/**
 * HTTP challenge verifier.
 *
 * Verifies domain ownership by fetching a well-known URL and comparing
 * the response body against the expected challenge token.
 *
 * Security considerations:
 * - HTTPS only (no HTTP fallback)
 * - DNS resolution with SSRF prevention (rejects private/loopback IPs)
 * - 10-second fetch timeout
 * - Redirects are rejected (potential SSRF vector)
 */

import dns from "node:dns";
import { AttestationError } from "@opencred/shared";
import { isPrivateIP } from "./ssrf.js";

/** Timeout for HTTP challenge fetch requests. */
const HTTP_TIMEOUT_MS = 10_000;

/** The well-known path prefix for HTTP challenges. */
export const WELL_KNOWN_PATH = ".well-known/opencred-challenge";

/**
 * Verify an HTTP challenge by fetching the well-known URL.
 *
 * The domain owner must place the expected token at:
 *   https://<domain>/.well-known/opencred-challenge/<challengeId>
 *
 * Security checks performed:
 * 1. Domain is resolved and all IPs are validated against SSRF ranges
 * 2. Only HTTPS is used (never HTTP)
 * 3. Redirects are rejected
 * 4. A 10-second timeout is enforced
 *
 * @param domain - The domain to verify
 * @param challengeId - The challenge identifier (used in the URL path)
 * @param expectedToken - The expected response body content
 * @returns true if the response body matches the expected token
 */
export async function verifyHttpChallenge(
  domain: string,
  challengeId: string,
  expectedToken: string,
): Promise<boolean> {
  if (!domain) {
    throw new AttestationError("Domain is required for HTTP verification");
  }
  if (!challengeId) {
    throw new AttestationError("Challenge ID is required for HTTP verification");
  }
  if (!expectedToken) {
    throw new AttestationError("Expected token is required for HTTP verification");
  }

  // SSRF prevention: resolve domain and reject private IPs
  await validateDomainResolution(domain);

  // Fetch the challenge URL (HTTPS only)
  const url = `https://${domain}/${WELL_KNOWN_PATH}/${challengeId}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: "GET",
        signal: controller.signal,
        redirect: "error", // Don't follow redirects (potential SSRF vector)
      });

      if (!response.ok) return false;

      const body = (await response.text()).trim();
      return body === expectedToken;
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err) {
    // Re-throw AttestationError (from SSRF checks), swallow others (network errors)
    if (err instanceof AttestationError) throw err;
    return false;
  }
}

/**
 * Validate that a domain resolves to public IP addresses only.
 *
 * Attempts IPv4 first, then IPv6 if IPv4 fails. All resolved addresses
 * must be public (non-private, non-loopback, non-link-local).
 *
 * @throws AttestationError if domain resolves to private IP or cannot be resolved
 */
async function validateDomainResolution(domain: string): Promise<void> {
  let resolved = false;

  // Try IPv4 first
  try {
    const addresses = await dns.promises.resolve4(domain);
    for (const addr of addresses) {
      if (isPrivateIP(addr)) {
        throw new AttestationError(
          "Domain resolves to a private or loopback IP address",
        );
      }
    }
    resolved = true;
  } catch (err) {
    if (err instanceof AttestationError) throw err;
    // IPv4 resolution failed, try IPv6
  }

  if (!resolved) {
    try {
      const addresses = await dns.promises.resolve6(domain);
      for (const addr of addresses) {
        if (isPrivateIP(addr)) {
          throw new AttestationError(
            "Domain resolves to a private or loopback IP address",
          );
        }
      }
    } catch (err) {
      if (err instanceof AttestationError) throw err;
      throw new AttestationError("Failed to resolve domain for SSRF check");
    }
  }
}
