/**
 * Credential input format detection.
 *
 * Classifies a raw string into one of the supported credential input formats
 * so the server verify endpoint can dispatch to the correct parser/decoder.
 */

/** Supported credential input formats. */
export type CredentialInputFormat = "pixelpass" | "json" | "jwt-compact" | "unknown";

/** Base64url character class (RFC 4648 §5). */
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Detect the format of a credential input string.
 *
 * Detection rules (evaluated in order):
 *   1. Starts with "OPENCRED1:" → pixelpass (PixelPass-compressed QR data)
 *   2. Trimmed input starts with "{" → json (JSON-stringified credential)
 *   3. Three dot-separated non-empty base64url segments → jwt-compact (VC-JWT)
 *      OR contains "~" (SD-JWT compact serialization) → jwt-compact
 *   4. Otherwise → unknown
 */
export function detectCredentialInputFormat(input: string): CredentialInputFormat {
  if (input.startsWith("OPENCRED1:")) {
    return "pixelpass";
  }

  const trimmed = input.trimStart();
  if (trimmed.startsWith("{")) {
    return "json";
  }

  // SD-JWT: header.payload.signature~disclosure1~disclosure2~...
  if (input.includes("~")) {
    return "jwt-compact";
  }

  // VC-JWT: header.payload.signature (exactly 3 non-empty base64url parts)
  const parts = input.split(".");
  if (
    parts.length === 3 &&
    parts[0].length > 0 &&
    parts[1].length > 0 &&
    parts[2].length > 0 &&
    BASE64URL_RE.test(parts[0]) &&
    BASE64URL_RE.test(parts[1]) &&
    BASE64URL_RE.test(parts[2])
  ) {
    return "jwt-compact";
  }

  return "unknown";
}
