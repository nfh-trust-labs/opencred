import { canonicalize } from "json-canonicalize";
import { sha256Hex } from "./hash.js";

/**
 * Canonicalize a JSON object using JCS (JSON Canonicalization Scheme, RFC 8785).
 * @param obj — The object to canonicalize.
 * @returns The canonical JSON string per RFC 8785.
 */
export function jcsCanonicalize(obj: unknown): string {
  return canonicalize(obj);
}

/**
 * Compute a hex-encoded SHA-256 hash of the JCS-canonicalized form of an object.
 * Used for revocation registry hashing and deterministic credential identifiers.
 * @param credential — The credential or object to hash.
 * @returns Lowercase hex SHA-256 of the JCS-canonicalized form.
 */
export function computeRevocationHash(credential: unknown): string {
  const canonical = canonicalize(credential);
  return sha256Hex(canonical);
}
