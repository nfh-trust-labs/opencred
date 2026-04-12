/**
 * JWT size validation to prevent memory exhaustion from oversized tokens.
 *
 * A maliciously large JWT could cause memory exhaustion during base64 decoding.
 * This module provides a constant and guard function to enforce size limits
 * before any decoding takes place.
 */

import { PayloadTooLargeError } from "./errors.js";

/**
 * Maximum allowed size for a raw JWT/JWS/SD-JWT string, in bytes.
 *
 * 1 MiB is generous for any legitimate credential token:
 * - A typical VC-JWT is 2-10 KB
 * - SD-JWT with many disclosures may reach 50-100 KB
 * - 1 MiB accommodates edge cases while blocking DoS payloads
 */
export const MAX_JWT_BYTES = 1_048_576;

/**
 * Throws {@link PayloadTooLargeError} if `token` exceeds {@link MAX_JWT_BYTES}.
 *
 * Call this at every entry point that accepts a raw JWT/JWS/SD-JWT string
 * from an untrusted source *before* splitting or base64-decoding.
 */
export function assertJwtSize(token: string): void {
  if (Buffer.byteLength(token, "utf8") > MAX_JWT_BYTES) {
    throw new PayloadTooLargeError(
      `JWT exceeds maximum allowed size of ${MAX_JWT_BYTES} bytes`,
    );
  }
}
