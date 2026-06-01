/**
 * PixelPass codec for OpenCred QR / PDF-embedded credentials.
 *
 * OpenCred compresses credentials before embedding them in QR codes and PDF
 * metadata so they fit in QR capacity and stay small in metadata streams.
 * The compression pipeline is:
 *
 *   JSON → CBOR encode → zlib compress (level 9) → Base45 encode
 *
 * Payloads are emitted as **bare PixelPass** — no header, no prefix. This
 * matches `@mosip/pixelpass`'s default (`header = ""`) and lets any
 * downstream consumer that calls `pixelpass.decode()` directly (notably the
 * MOSIP/Inji verifier toolchain) accept OpenCred QR data with no special
 * handling.
 *
 * This module lives in `@opencred/shared` so both the format-detection
 * surface (`detectCredentialInputFormat`) and the verification surface
 * (`@opencred/verification`) can use the same codec without a circular
 * dependency.
 */

import { createRequire } from "node:module";

// PixelPass is a CommonJS module — go through createRequire for ESM compat.
const require = createRequire(import.meta.url);
const pixelpass = require("@mosip/pixelpass") as {
  decode: (data: string) => string;
  generateQRData: (data: string, header?: string) => string;
};

/**
 * Decode a PixelPass-compressed OpenCred payload back to credential JSON.
 *
 * Runs the inverse of the compression pipeline (Base45 → zlib decompress →
 * CBOR decode) to recover the original JSON string. The caller is
 * responsible for parsing the JSON into a credential object.
 *
 * @param data - The Base45-encoded PixelPass payload (no header).
 * @returns The decoded credential JSON string.
 * @throws If the payload cannot be decoded as PixelPass.
 */
export function decodePixelPass(data: string): string {
  return pixelpass.decode(data);
}

/**
 * Best-effort PixelPass decode. Returns the decoded JSON string on success
 * and `null` on any error. Useful for content sniffing where decode itself
 * is the discriminator (see `detectCredentialInputFormat`).
 */
export function tryDecodePixelPass(data: string): string | null {
  try {
    return pixelpass.decode(data);
  } catch {
    return null;
  }
}

/**
 * Compress a credential JSON string using the PixelPass pipeline.
 *
 * Emits a bare PixelPass payload — no header. See the module-level comment
 * for the rationale.
 *
 * @param json - The JSON-serialized credential.
 * @returns The Base45-encoded compressed payload.
 */
export function encodePixelPass(json: string): string {
  return pixelpass.generateQRData(json);
}
