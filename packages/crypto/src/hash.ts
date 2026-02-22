import { createHash } from "node:crypto";

/**
 * Compute SHA-256 hash of the given data.
 * @param data — string or Buffer to hash.
 * @returns The 32-byte SHA-256 digest as a Uint8Array.
 */
export function sha256(data: string | Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/**
 * Compute SHA-256 hash and return as a lowercase hex string.
 * @param data — string or Buffer to hash.
 * @returns The hex-encoded SHA-256 digest.
 */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
