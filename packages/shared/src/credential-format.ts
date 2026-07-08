/**
 * Credential input format detection.
 *
 * Classifies a raw string into one of the supported credential input formats
 * so the server verify endpoint can dispatch to the correct parser/decoder.
 *
 * **PixelPass detection is content-based, not prefix-based.** OpenCred
 * emits bare PixelPass payloads (no `OPENCRED1:` header) so that any
 * downstream consumer using `@mosip/pixelpass.decode()` directly — most
 * notably the MOSIP/Inji verifier toolchain — can accept OpenCred QR data
 * unchanged. To detect a PixelPass payload here, we attempt a decode after
 * the cheap pattern checks fail. A successful decode is treated as positive
 * identification. The cost is one Base45 + zlib + CBOR attempt on the
 * negative path (a few ms at most); the win is wire-format interop with
 * the wider VC ecosystem.
 */

import { tryDecodePixelPass } from "./pixelpass.js";

/** Supported credential input formats. */
export type CredentialInputFormat = "pixelpass" | "json" | "jwt-compact" | "unknown";

/** Base64url character class (RFC 4648 §5). */
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Detect the format of a credential input string.
 *
 * Detection rules (evaluated in order):
 *   1. Trimmed input starts with "{" → json (JSON-stringified credential)
 *   2. Contains "~" → jwt-compact (SD-JWT compact serialization with
 *      disclosures)
 *   3. Three dot-separated non-empty base64url segments → jwt-compact
 *      (VC-JWT compact serialization)
 *   4. Successfully decodes as PixelPass → pixelpass (bare PixelPass QR
 *      payload, no header)
 *   5. Otherwise → unknown
 *
 * The PixelPass try-decode is intentionally the last check: pattern checks
 * are O(string-length); decode is O(payload) plus an exception cost on the
 * negative path. Putting it last keeps the common case (JSON / JWT) fast.
 */
export function detectCredentialInputFormat(input: string): CredentialInputFormat {
  // Empty input is `unknown`, not `pixelpass`. PixelPass's `decode("")`
  // returns an empty string rather than throwing, so the try-decode
  // fallback below would otherwise misclassify an empty payload.
  if (input.length === 0) {
    return "unknown";
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

  // Bare PixelPass payload — discriminated by successful decode. Base45's
  // alphabet (uppercase + digits + `$%*+-./:`) overlaps with neither JSON
  // (curly-brace-led) nor base64url JWTs (lowercase letters, no
  // `$%*+./:`), so the false-positive rate of this fallback in practice
  // is negligible.
  if (tryDecodePixelPass(input) !== null) {
    return "pixelpass";
  }

  return "unknown";
}

/** Magic-byte signature for the PDF format (`%PDF-` per ISO 32000-1 §7.5.2). */
const PDF_MAGIC = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]); // "%PDF-"

/**
 * Detect whether the given bytes are a PDF document.
 *
 * Checks the file's leading magic bytes (`%PDF-`). Only used to distinguish
 * PDF uploads from other binary inputs at the verification surface — does
 * not validate the rest of the PDF structure; that is the parser's job.
 *
 * @param bytes - The candidate file bytes (typically the start of a request body).
 * @returns true if the bytes begin with the PDF magic signature.
 */
export function isPdfBytes(bytes: Uint8Array): boolean {
  if (bytes.length < PDF_MAGIC.length) return false;
  for (let i = 0; i < PDF_MAGIC.length; i++) {
    if (bytes[i] !== PDF_MAGIC[i]) return false;
  }
  return true;
}
